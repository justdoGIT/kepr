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
  // unref: a failed assertion that skips close() must not hang the run.
  srv.unref();
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

test('set sends a value or a generate kind, and validates first', async () => {
  const d = await fakeDaemon((r) => ({ kind: 'set_ok', name: r.name, cred_name: 'x', password_protected: false }));
  const c = new Client({ path: d.sockPath });
  await c.set('a', 'v', { requiresFido2: true });
  await c.generate('b', 'words');
  assert.deepStrictEqual(d.seen, [
    { cmd: 'set', name: 'A', value: 'v', requires_fido2: true },
    { cmd: 'set', name: 'B', generate: 'words' },
  ]);
  await assert.rejects(c.generate('c', 'rot13'), /generate must be one of/);
  await assert.rejects(c.set('c', 'v', { generate: 'hex' }), /not both/);
  await assert.rejects(c.set('c', ''), /non-empty/);
  assert.strictEqual(d.seen.length, 2, 'invalid calls never reach the daemon');
  d.close();
});

test('delete, list with metadata and info', async () => {
  const creds = [
    { name: 'GH', cred_name: 'kepr-1-gh', size: 40, modified: '2026-10-01 12:00', expires_at: '2026-12-01 00:00', requires_consent: true },
    { name: 'OA', cred_name: 'kepr-1-oa', size: 9, modified: '2026-10-02 08:00', sealed: true, tags: ['work'] },
  ];
  const d = await fakeDaemon((r) =>
    r.cmd === 'delete' ? { kind: 'delete_ok', name: r.name } : { kind: 'list_ok', credentials: creds, count: 2 },
  );
  const c = new Client({ path: d.sockPath });
  await c.delete('gh');
  assert.deepStrictEqual(d.seen[0], { cmd: 'delete', name: 'GH' });
  const infos = await c.credentials();
  assert.strictEqual(infos[0].expiresAt, '2026-12-01 00:00');
  assert.strictEqual(infos[0].requiresConsent, true);
  assert.strictEqual(infos[0].sealed, false);
  assert.strictEqual(infos[1].sealed, true);
  assert.deepStrictEqual(infos[1].tags, ['work']);
  assert.strictEqual(infos[1].recordType, null);
  assert.ok(!('cred_name' in infos[0]) && !('value' in infos[0]));
  assert.strictEqual((await c.info('oa')).name, 'OA');
  assert.strictEqual(await c.info('missing'), null);
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
