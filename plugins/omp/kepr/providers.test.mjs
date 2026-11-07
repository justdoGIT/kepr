import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import vm from 'node:vm';

const source = stripTypeScriptTypes(await readFile(new URL('./providers.ts', import.meta.url), 'utf8')).replaceAll('export function ', 'function ');
const register = vm.runInNewContext(source + '\nregisterProviders;', { URL });
const gate = 'http://127.0.0.1:9876';
const route = (credential, slot = 0, host = 'api.example.com') => ({ credential, host, route: `https+${host}+${credential}`, variable: `KEPR_OMP_KEY_${slot}` });
const plan = (config, routes = [route('WORK')], env = { KEPR_OMP_KEY_0: 'kepr-ph-test' }) => {
  const registrations = new Map();
  const result = register({ registerProvider: (id, spec) => registrations.set(id, spec) }, gate, routes, config, env);
  return { ...result, registrations };
};

test('configured credential commands become host-bound placeholders without replacing models', () => {
  const models = [{ id: 'custom-model', contextWindow: 12345 }];
  const cfg = { providers: { custom: { baseUrl: 'https://api.example.com/api/v2', apiKey: '!kepr get WORK --quiet', models } } };
  const out = plan(cfg);
  assert.equal(out.registrations.get('custom')?.baseUrl, gate + '/https+api.example.com+WORK/api/v2');
  assert.equal(out.registrations.get('custom')?.apiKey, 'KEPR_OMP_KEY_0');
  assert.equal(out.registrations.get('custom')?.models, undefined);
  assert.equal(cfg.providers.custom.models, models);
});

test('account aliases on one host keep distinct credentials', () => {
  const providers = Object.fromEntries(['WORK', 'PERSONAL'].map(name => [name.toLowerCase(), { baseUrl: 'https://api.example.com/v1', apiKey: `!kepr get ${name}` }]));
  const out = plan({ providers }, [route('WORK'), route('PERSONAL', 1)], { KEPR_OMP_KEY_0: 'kepr-ph-work', KEPR_OMP_KEY_1: 'kepr-ph-personal' });
  assert.equal(out.registrations.get('work').apiKey, 'KEPR_OMP_KEY_0');
  assert.equal(out.registrations.get('personal').apiKey, 'KEPR_OMP_KEY_1');
});

test('unavailable or unbound references cannot fall back to secret-reading commands', () => {
  for (const baseUrl of ['https://unbound.example.com/v1', 'http://api.example.com/v1', 'https://api.example.com:8443/v1']) {
    const out = plan({ providers: { custom: { baseUrl, apiKey: '!kepr get WORK --quiet' } } });
    assert.equal(out.unavailable.length, 1);
    assert.equal(out.registrations.get('custom').baseUrl, gate + '/__kepr/unavailable');
  }
});

test('OAuth, subscription helpers and local keyless services are preserved', () => {
  const providers = { subscription: { auth: 'oauth', apiKey: '!login-helper' }, local: { auth: 'none', baseUrl: 'http://localhost:1234' } };
  assert.equal(plan({ providers }).registrations.size, 0);
});

test('built-in defaults use sealed credentials and preserve models', () => {
  const out = plan({}, [route('OPENAI_API_KEY', 0, 'api.openai.com')]);
  assert.equal(out.registrations.get('openai')?.baseUrl, gate + '/https+api.openai.com+OPENAI_API_KEY/v1');
  assert.equal(out.registrations.get('openai')?.models, undefined);
});

test('malformed route metadata and non-placeholder values fail closed', () => {
  assert.throws(() => plan({}, [{ ...route('WORK'), route: '../escape' }]));
  assert.throws(() => plan({}, [route('WORK')], { KEPR_OMP_KEY_0: 'not-a-placeholder' }));
});
