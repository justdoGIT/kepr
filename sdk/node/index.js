'use strict';
// Thin client for the kepr credential daemon. Same wire format as the
// CLI: one JSON request per connection, framed by a 4-byte big-endian
// length, over the per-user Unix socket. The daemon identifies callers
// by socket credentials and applies the same rules as for the CLI
// (uid namespacing, audit, consent, sealed keys never returned).
//
// JavaScript strings can't be wiped from memory: keep values in scope
// briefly, and prefer `kepr exec` / `kepr agent run` for child processes.

const net = require('node:net');
const path = require('node:path');

const MAX_MSG_BYTES = 65536;

class KeprError extends Error {}

function socketPath() {
  if (process.env.KEPR_SYSTEM_MODE) return '/run/kepr/kepr.sock';
  const runtime =
    process.env.XDG_RUNTIME_DIR ||
    path.join(process.env.HOME || '/tmp', '.local/state/kepr/runtime');
  return path.join(runtime, 'kepr', 'kepr.sock');
}

function upper(name) {
  if (typeof name !== 'string' || name === '') {
    throw new KeprError('credential name must be a non-empty string');
  }
  return name.toUpperCase();
}

class Client {
  constructor({ path: p, timeoutMs = 65000 } = {}) {
    this.path = p || socketPath();
    this.timeoutMs = timeoutMs;
  }

  /** Send one raw request object ({cmd: ...}); resolve with the reply. */
  request(req) {
    const payload = Buffer.from(JSON.stringify(req));
    if (payload.length > MAX_MSG_BYTES) {
      return Promise.reject(new KeprError('request too large'));
    }
    return new Promise((resolve, reject) => {
      const sock = net.createConnection(this.path);
      let buf = Buffer.alloc(0);
      const fail = (e) => {
        sock.destroy();
        reject(e);
      };
      sock.setTimeout(this.timeoutMs, () => fail(new KeprError('timed out')));
      sock.on('error', (e) =>
        fail(new KeprError(`cannot reach the credential service at ${this.path} (${e.code || e.message}); start it with \`kepr-daemon --user\``)),
      );
      sock.on('connect', () => {
        const len = Buffer.alloc(4);
        len.writeUInt32BE(payload.length);
        sock.write(Buffer.concat([len, payload]));
      });
      sock.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length < 4) return;
        const n = buf.readUInt32BE(0);
        if (n > MAX_MSG_BYTES) return fail(new KeprError('reply too large'));
        if (buf.length < 4 + n) return;
        sock.end();
        let resp;
        try {
          resp = JSON.parse(buf.subarray(4, 4 + n).toString('utf8'));
        } catch {
          return reject(new KeprError('malformed reply'));
        }
        if (resp.kind === 'err') return reject(new KeprError(resp.error || 'request failed'));
        resolve(resp);
      });
      sock.on('end', () => {
        if (buf.length < 4) reject(new KeprError('connection closed by the credential service'));
      });
    });
  }

  async expect(req, kind) {
    const r = await this.request(req);
    if (r.kind !== kind) {
      if (r.kind === 'fido2_needed') throw new KeprError('this credential needs a FIDO2 touch; use `kepr get`');
      throw new KeprError(`unexpected reply: ${r.kind}`);
    }
    return r;
  }

  async get(name) {
    return (await this.expect({ cmd: 'get', name: upper(name) }, 'get_ok')).value;
  }

  async set(name, value, { generate, ttlSecs, requiresConsent } = {}) {
    const req = { cmd: 'set', name: upper(name) };
    if (value !== undefined && value !== null) req.value = value;
    else req.generate = generate || 'hex';
    if (ttlSecs !== undefined) req.ttl_secs = ttlSecs;
    if (requiresConsent) req.requires_consent = true;
    return this.expect(req, 'set_ok');
  }

  async delete(name) {
    await this.expect({ cmd: 'delete', name: upper(name) }, 'delete_ok');
  }

  async list() {
    return (await this.expect({ cmd: 'list' }, 'list_ok')).credentials;
  }

  async history(name) {
    return (await this.expect({ cmd: 'history', name: upper(name) }, 'history_ok')).versions;
  }

  async restore(name, version) {
    await this.expect({ cmd: 'restore', name: upper(name), version }, 'restore_ok');
  }

  async usage(days) {
    const req = { cmd: 'usage' };
    if (days !== undefined) req.days = days;
    return this.expect(req, 'usage_ok');
  }

  async health(maxAgeDays) {
    const req = { cmd: 'health' };
    if (maxAgeDays !== undefined) req.max_age_days = maxAgeDays;
    return (await this.expect(req, 'health_ok')).items;
  }

  async sshSign(name, data) {
    const r = await this.expect(
      { cmd: 'sshsign', name: upper(name), data_b64: Buffer.from(data).toString('base64') },
      'ssh_sign_ok',
    );
    return Buffer.from(r.signature_b64, 'base64');
  }

  async status() {
    return this.expect({ cmd: 'status' }, 'status_ok');
  }

  async ping() {
    await this.expect({ cmd: 'ping' }, 'pong');
    return true;
  }
}

module.exports = { Client, KeprError, socketPath };
