'use strict';
const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Client, KeprError, socketPath } = require('..');

function fakeDaemon(reply) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kepr-node-'));
  const sockPath = path.join(dir, 's.sock');
  const seen = [];
  const srv = net.createServer((c) => {
    let buf = Buffer.alloc(0);
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length < 4 || buf.length < 4 + buf.readUInt32BE(0)) return;
      const req = JSON.parse(buf.subarray(4).toString());
      seen.push(req);
      const out = Buffer.from(JSON.stringify(reply(req)));
      const len = Buffer.alloc(4);
      len.writeUInt32BE(out.length);
      c.end(Buffer.concat([len, out]));
    });
  });
  return new Promise((r) => srv.listen(sockPath, () => r({ sockPath, seen, close: () => srv.close() })));
}

test('get uppercases the name and returns the value', async () => {
  const d = await fakeDaemon((r) => ({ kind: 'get_ok', name: r.name, value: 'v1' }));
  assert.strictEqual(await new Client({ path: d.sockPath }).get('api_key'), 'v1');
  assert.deepStrictEqual(d.seen, [{ cmd: 'get', name: 'API_KEY' }]);
  d.close();
});

test('err replies reject with KeprError', async () => {
  const d = await fakeDaemon(() => ({ kind: 'err', error: 'credential unavailable' }));
  await assert.rejects(new Client({ path: d.sockPath }).get('SEALED'), (e) => e instanceof KeprError && /unavailable/.test(e.message));
  d.close();
});

test('set builds generate and flag fields', async () => {
  const d = await fakeDaemon((r) => ({ kind: 'set_ok', name: r.name, cred_name: 'x', password_protected: false }));
  await new Client({ path: d.sockPath }).set('k', null, { ttlSecs: 60, requiresConsent: true });
  assert.deepStrictEqual(d.seen[0], { cmd: 'set', name: 'K', generate: 'hex', ttl_secs: 60, requires_consent: true });
  d.close();
});

test('unreachable socket and bad names', async () => {
  await assert.rejects(new Client({ path: '/nonexistent/kepr.sock', timeoutMs: 1000 }).ping(), /cannot reach/);
  await assert.rejects(new Client({ path: '/x' }).get(''), KeprError);
});

test('socket path follows the runtime dir', () => {
  const old = { ...process.env };
  delete process.env.KEPR_SYSTEM_MODE;
  process.env.XDG_RUNTIME_DIR = '/run/user/1000';
  assert.strictEqual(socketPath(), '/run/user/1000/kepr/kepr.sock');
  process.env.KEPR_SYSTEM_MODE = '1';
  assert.strictEqual(socketPath(), '/run/kepr/kepr.sock');
  process.env = old;
});

test('live round trip', { skip: !process.env.KEPR_SDK_LIVE }, async () => {
  const c = new Client();
  const name = `NODE_SDK_${process.pid}`;
  await c.set(name, 'one');
  await c.set(name, 'two');
  try {
    assert.strictEqual(await c.get(name), 'two');
    assert.strictEqual((await c.history(name)).length, 1);
    await c.restore(name, 1);
    assert.strictEqual(await c.get(name), 'one');
  } finally {
    await c.delete(name);
  }
});
