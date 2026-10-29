'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { parseList, parseStatus, subtitle, copyable, validName } = require('../src/parse');

test('parseList reads metadata, sorts, and has no value field', () => {
  const text = JSON.stringify({
    kind: 'list_ok',
    count: 3,
    credentials: [
      { name: 'ZED', cred_name: 'kepr-1-zed', size: 3, modified: '2026-10-28 15:29' },
      { name: 'ALPHA', size: 9, modified: 'x', tags: ['prod', 'db'], expires_at: '2027-01-01', record_type: 'database' },
      { name: 'KEY', sealed: true, requires_consent: true, modified: 'y' },
    ],
  });
  const l = parseList(text);
  assert.deepEqual(l.map((c) => c.name), ['ALPHA', 'KEY', 'ZED']);
  assert.deepEqual(l[0].tags, ['prod', 'db']);
  assert.equal(l[1].sealed, true);
  assert.equal(l[1].requiresConsent, true);
  assert.equal(l[2].sealed, false);
  for (const c of l) assert.equal(Object.keys(c).some((k) => /value|secret/i.test(k)), false);
});

test('daemon errors and odd replies throw', () => {
  assert.throws(() => parseList('{"kind":"err","error":"locked"}'), /locked/);
  assert.throws(() => parseList('{"kind":"pong"}'), /unexpected/);
  assert.throws(() => parseList('not json'));
  assert.deepEqual(parseList('{"kind":"list_ok","credentials":[null,{"x":1}]}'), []);
});

test('parseStatus', () => {
  assert.equal(parseStatus('{"kind":"status_ok","locked":true}').state, 'locked');
  assert.equal(parseStatus('{"kind":"status_ok","locked":false,"password_protected":true}').state, 'unlocked');
  assert.match(parseStatus('{"kind":"status_ok","locked":false}').detail, /no passphrase/);
  assert.equal(parseStatus('{"kind":"err","error":"cannot connect"}').state, 'offline');
  assert.equal(parseStatus('garbage').state, 'offline');
});

test('subtitle, copyable and names', () => {
  const [c] = parseList('{"kind":"list_ok","credentials":[{"name":"A","sealed":true,"tags":["t"],"modified":"m"}]}');
  assert.equal(subtitle(c), 'value · sealed · t · no expiry');
  assert.equal(copyable(c), false);
  assert.equal(validName('DB_PASS'), true);
  for (const bad of ['', 'a b', 'a;b', '../x', '-rf', 'A'.repeat(129)]) assert.equal(validName(bad), false, bad);
});
