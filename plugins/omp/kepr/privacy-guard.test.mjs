import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import privacyGuard, {
  evaluatePrivacyGuard,
  filterEligibleProviders,
  isProviderAllowed,
  isRestrictedRepo,
  parsePolicyYaml,
} from './privacy-guard.ts';

test('parsePolicyYaml parses strict mode, allowed_providers, and restricted_repos', () => {
  const policy = parsePolicyYaml(`
# comment
strict: true
allowed_providers:
  - anthropic
  - openai # inline comment
  - ollama
restricted_repos:
  - dev-setup
  - fleet-management
`);
  assert.equal(policy.strict, true);
  assert.deepEqual(policy.allowed_providers, ['anthropic', 'openai', 'ollama']);
  assert.deepEqual(policy.restricted_repos, ['dev-setup', 'fleet-management']);
});

test('isProviderAllowed permits first-party/local providers and blocks third-party relays', () => {
  const policy = parsePolicyYaml('');
  for (const ok of [
    'anthropic',
    'openai',
    'openai-codex',
    'claude-waddhwaa',
    'codex-waddhwaa',
    'google',
    'google-antigravity',
    'google-vertex',
    'deepseek',
    'groq',
    'mistral',
    'xai',
    'nvidia',
    'ollama',
    'local-decider',
    'anthropic/claude-sonnet-4-5',
    'https+api.anthropic.com+ANTHROPIC_API_KEY',
    'https://api.openai.com/v1',
    'http://127.0.0.1:4229/v1',
  ]) {
    assert.equal(isProviderAllowed(ok, policy), true, `expected allowed: ${ok}`);
  }
  for (const blocked of [
    'openrouter',
    'agentrouter',
    'selora',
    'venice',
    'fireworks',
    'moonshot',
    'https+openrouter.ai+OPENROUTER_API_KEY',
    'https://openrouter.ai/api/v1',
  ]) {
    assert.equal(isProviderAllowed(blocked, policy), false, `expected blocked: ${blocked}`);
  }
});

test('isRestrictedRepo detects restricted folder names, markers, and git origin URLs', () => {
  const root = mkdtempSync(join(tmpdir(), 'kepr-pguard-'));
  try {
    const devSetup = join(root, 'dev-setup', 'scripts');
    mkdirSync(devSetup, { recursive: true });
    assert.equal(isRestrictedRepo(devSetup), true);

    const publicRepo = join(root, 'demo-app');
    mkdirSync(publicRepo, { recursive: true });
    assert.equal(isRestrictedRepo(publicRepo), false);

    writeFileSync(join(publicRepo, '.kepr-strict'), '');
    assert.equal(isRestrictedRepo(publicRepo), true);

    const mounted = join(root, 'workspace');
    mkdirSync(join(mounted, '.git'), { recursive: true });
    writeFileSync(
      join(mounted, '.git', 'config'),
      '[remote "origin"]\n\turl = git@github.com:org/fleet-management.git\n',
    );
    assert.equal(isRestrictedRepo(mounted), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('generic plugin hooks block third-party providers in restricted repos and allow first-party', async () => {
  const root = mkdtempSync(join(tmpdir(), 'kepr-pguard-hook-'));
  try {
    const restricted = join(root, 'dev-setup');
    mkdirSync(restricted, { recursive: true });
    const handlers = new Map();
    privacyGuard({ on: (name, fn) => handlers.set(name, fn) });

    const blockedTool = await handlers.get('tool_call')(
      { toolName: 'bash', input: {} },
      { cwd: restricted, model: { provider: 'openrouter' } },
    );
    assert.equal(blockedTool?.block, true);
    assert.match(blockedTool?.reason ?? '', /PRIVACY GUARD BLOCKED/);

    const allowedTool = await handlers.get('tool_call')(
      { toolName: 'bash', input: {} },
      { cwd: restricted, model: { provider: 'anthropic' } },
    );
    assert.equal(allowedTool, undefined);

    const blockedInput = await handlers.get('input')(
      { text: 'explain this config' },
      { cwd: restricted, model: { provider: 'openrouter' } },
    );
    assert.equal(blockedInput?.action, 'handled');

    const slashCmd = await handlers.get('input')(
      { text: '/model anthropic/claude-sonnet-4-5' },
      { cwd: restricted, model: { provider: 'openrouter' } },
    );
    assert.equal(slashCmd?.action, 'continue');

    const filtered = filterEligibleProviders(
      [{ provider: 'openrouter' }, { provider: 'anthropic' }, { provider: 'openai' }],
      restricted,
    );
    assert.deepEqual(filtered, [{ provider: 'anthropic' }, { provider: 'openai' }]);
    assert.equal(
      evaluatePrivacyGuard({ cwd: restricted, provider: 'openrouter' }).allowed,
      false,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
