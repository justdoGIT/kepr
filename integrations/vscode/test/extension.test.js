'use strict';
// Hover text, status bar, credential list and activation, against a fake
// client and a stub of the VS Code API (no editor needed).
const test = require('node:test');
const assert = require('node:assert');
const { hoverMarkdown, statusText, pickItems } = require('../src/view');
const { CredCache } = require('../src/creds');
const { activate } = require('../extension');

const CREDS = [
  { name: 'PROD_DB', size: 90, modified: '2026-10-01 12:00', expiresAt: '2026-12-01 00:00', recordType: 'database',
    boundHosts: null, sealed: false, requiresConsent: true, requiresFido2: false, tags: ['prod', 'db'] },
  { name: 'OPENAI_API_KEY', size: 50, modified: '2026-09-01 08:00', expiresAt: null, recordType: null,
    boundHosts: ['api.openai.com'], sealed: true, requiresConsent: false, requiresFido2: false },
];

// A client that can list but whose `get` must never be called.
function fakeClient({ locked = false, down = false } = {}) {
  const calls = [];
  return {
    calls,
    async credentials() {
      calls.push('credentials');
      if (down) throw new Error('cannot reach the credential service');
      return CREDS;
    },
    async status() {
      calls.push('status');
      if (down) throw new Error('cannot reach the credential service');
      return { kind: 'status_ok', locked, password_protected: true };
    },
    async get() {
      throw new Error('the extension must never read a value');
    },
  };
}

test('hover shows type, field, tags, expiry and flags, never a value', () => {
  const md = hoverMarkdown({ name: 'PROD_DB', field: 'password' }, CREDS[0]);
  for (const want of ['kepr://PROD_DB/password', 'database', '`password`', 'prod, db', '2026-12-01 00:00', 'consent']) {
    assert.ok(md.includes(want), `${want} missing from:\n${md}`);
  }
  const sealed = hoverMarkdown({ name: 'OPENAI_API_KEY', field: null }, CREDS[1]);
  assert.ok(sealed.includes('sealed') && sealed.includes('api.openai.com') && sealed.includes('never'), sealed);
  assert.ok(hoverMarkdown({ name: 'OPENAI_API_KEY', field: 'user' }, CREDS[1]).includes('not a record'));
  assert.ok(hoverMarkdown({ name: 'NOPE', field: null }, null).includes('No credential named `NOPE`'));
});

test('status text for unlocked, locked, unprotected and offline', () => {
  assert.match(statusText({ locked: false, password_protected: true }).text, /unlocked/);
  assert.match(statusText({ locked: true, password_protected: true }).text, /locked/);
  assert.match(statusText({ locked: false, password_protected: false }).tooltip, /no passphrase/);
  assert.match(statusText(null, new Error('cannot reach')).text, /offline/);
});

test('quick pick items describe credentials without values', () => {
  const items = pickItems(CREDS);
  assert.strictEqual(items[0].label, 'OPENAI_API_KEY');
  assert.match(items[0].description, /sealed/);
  assert.match(items[1].description, /database/);
  assert.match(items[1].detail, /expires 2026-12-01 00:00/);
});

test('cache lists once per ttl and drops entries on refresh', async () => {
  let now = 0;
  const c = fakeClient();
  const cache = new CredCache(c, { ttlMs: 1000, now: () => now });
  assert.strictEqual((await cache.info('prod_db')).recordType, 'database');
  assert.strictEqual(await cache.info('missing'), null);
  assert.strictEqual(c.calls.length, 1);
  now = 1500;
  await cache.info('PROD_DB');
  assert.strictEqual(c.calls.length, 2);
  cache.clear();
  await cache.info('PROD_DB');
  assert.strictEqual(c.calls.length, 3);
});

// Minimal stand-in for the `vscode` module.
function fakeVscode() {
  const api = {
    registered: {},
    clipboard: [],
    Hover: class { constructor(contents, range) { this.contents = contents; this.range = range; } },
    MarkdownString: class { constructor(value) { this.value = value; } },
    Range: class { constructor(l1, c1, l2, c2) { Object.assign(this, { l1, c1, l2, c2 }); } },
    StatusBarAlignment: { Left: 1 },
    languages: {
      registerHoverProvider: (sel, provider) => { api.registered.hover = provider; return { dispose() {} }; },
    },
    commands: {
      registerCommand: (id, fn) => { api.registered[id] = fn; return { dispose() {} }; },
    },
    window: {
      activeTextEditor: null,
      createStatusBarItem: () => (api.bar = { show() {}, dispose() {} }),
      showQuickPick: async (items) => items[0],
      showErrorMessage: (m) => api.registered.error = m,
      showInformationMessage: () => {},
    },
    env: { clipboard: { writeText: async (t) => api.clipboard.push(t) } },
    workspace: { getConfiguration: () => ({ get: () => undefined }) },
  };
  return api;
}

test('activation wires hover, list command and status bar', async () => {
  const vs = fakeVscode();
  const client = fakeClient({ locked: true });
  const context = { subscriptions: [] };
  const ext = activate(context, { vscode: vs, client, pollMs: 0 });
  await ext.ready;
  assert.match(vs.bar.text, /locked/);
  assert.strictEqual(vs.bar.command, 'kepr.refreshStatus');

  const doc = { lineAt: () => ({ text: 'password: kepr://PROD_DB/password' }) };
  const hover = await vs.registered.hover.provideHover(doc, { line: 3, character: 14 });
  assert.ok(hover.contents.value.includes('database'));
  assert.deepStrictEqual([hover.range.l1, hover.range.c1, hover.range.c2], [3, 10, 33]);
  assert.strictEqual(await vs.registered.hover.provideHover(doc, { line: 3, character: 2 }), null);

  await vs.registered['kepr.listCredentials']();
  assert.deepStrictEqual(vs.clipboard, ['kepr://OPENAI_API_KEY'], 'copies the reference, not the value');
  assert.ok(!client.calls.includes('get'));
  assert.ok(context.subscriptions.length >= 4);
  ext.dispose();
});

test('daemon down: status shows offline and the command reports the error', async () => {
  const vs = fakeVscode();
  const ext = activate({ subscriptions: [] }, { vscode: vs, client: fakeClient({ down: true }), pollMs: 0 });
  await ext.ready;
  assert.match(vs.bar.text, /offline/);
  await vs.registered['kepr.listCredentials']();
  assert.match(vs.registered.error, /cannot reach/);
  ext.dispose();
});
