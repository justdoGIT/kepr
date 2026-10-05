'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { findReferences, referenceAt } = require('../src/notation');

test('finds names and lower-case fields like kepr inject', () => {
  const line = 'u=kepr://db/user p=kepr://DB/password x=kepr://DB/Up kepr://DB/ kepr:// end';
  const refs = findReferences(line);
  assert.deepStrictEqual(
    refs.map((r) => [r.name, r.field, line.slice(r.start, r.end)]),
    [
      ['DB', 'user', 'kepr://db/user'],
      ['DB', 'password', 'kepr://DB/password'],
      ['DB', null, 'kepr://DB'],
      ['DB', null, 'kepr://DB'],
    ],
  );
});

test('referenceAt picks the reference under the cursor', () => {
  const line = 'url: postgres://kepr://APP_DB/user@host and kepr://TOKEN';
  const at = (i) => referenceAt(line, i);
  const first = line.indexOf('kepr://APP_DB');
  assert.strictEqual(at(first).name, 'APP_DB');
  assert.strictEqual(at(first + 'kepr://APP_DB/user'.length - 1).field, 'user');
  assert.strictEqual(at(first + 'kepr://APP_DB/user'.length), null, 'end is exclusive');
  assert.strictEqual(at(line.indexOf('TOKEN')).name, 'TOKEN');
  assert.strictEqual(at(0), null);
});

test('names longer than the daemon allows are not references', () => {
  assert.deepStrictEqual(findReferences(`kepr://${'A'.repeat(129)}`), []);
  assert.strictEqual(findReferences(`kepr://${'A'.repeat(128)}`).length, 1);
});
