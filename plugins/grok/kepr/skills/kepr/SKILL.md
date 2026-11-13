---
name: kepr
description: How to work with API keys and other secrets when kepr manages them. Use when a task needs a credential, an API key, a token, a database password, or a .env file.
---

# Working with secrets under kepr

Kepr protection starts only when the operator launches the harness through
`kepr agent run <harness>`. A plugin or skill installed in an ordinary shell
does not protect that process, the device, or other applications.

In a protected launch:

- the harness receives an isolated private home, an allowlisted environment,
  and a local gate URL; the daemon socket, credential store, host auth files,
  and desktop keyring are not exposed;
- provider credentials are `kepr-ph-…` placeholders; the gate resolves a
  sealed credential only for its exact bound HTTPS host and injects it there;
- `KEPR_GATE_URL` is a loopback session URL. If it is absent, treat the
  session as unprotected and ask the operator to relaunch it;
- an unavailable gate, failed safety hook, invalid route, or missing binding
  is a refusal, never a direct-network or plaintext fallback.

## Operator setup

Run these commands in the operator's terminal, outside the agent:

```bash
kepr agent add NAME --for PROVIDER
kepr agent ls
kepr agent run HARNESS
```

Use the exact provider binding. A custom HTTPS destination is explicit, for
example `--for api.example.com:443:bearer`; an OpenAI-compatible reseller is
not OpenAI. `--requires-consent` makes the daemon ask before releasing the
sealed value. `kepr agent add` stores a sealed, write-only credential; `kepr
get` cannot read it back. Never put a key in chat, a command argument, a
file, an environment export, a prompt, a log, or a commit.

Cloudflare AI Gateway credentials use the structured `kepr agent add-cloudflare`
conversion. Do not bind the gateway token to OpenAI or use `!kepr get` as its
OMP credential source. `kepr agent doctor --json` checks the operator-side
installation; it does not prove that a live provider or model is available.

Credential rotation and upstream revocation are operator actions, not agent
operations. `kepr agent revoke NAME` removes the local sealed record; it does
not prove that the provider revoked the old key. Use an official provider
management flow or an approved `kepr rotate` flow from the operator terminal,
and keep any separate admin or management credential sealed. Never pass a
bootstrap key to the agent or put it in a hook argument, file, environment
export, or prompt.

## OMP provider routing

After `kepr agent install omp`, start a new protected session with
`kepr agent run omp`. The extension:

- reads the session's `models.yml` and converts configured `apiKey` names (or
  the metadata-only `!kepr get NAME` form) into gate placeholders;
- accepts only route metadata created by Kepr, with an exact lower-case host,
  credential name, `KEPR_OMP_KEY_<n>` placeholder, and
  `https+HOST+CREDENTIAL` route;
- accepts only HTTPS endpoints without an explicit port, credentials, query,
  or fragment, and requires the endpoint host to match a sealed binding;
- leaves OAuth/keyless providers alone, but marks an unbound or malformed
  credential provider unavailable instead of falling back to a secret-reading
  command or direct network access.

The reviewed OpenAI-compatible defaults include Fireworks
(`api.fireworks.ai/inference/v1`), Moonshot CN (`api.moonshot.cn/v1`), and
Venice (`api.venice.ai/api/v1`). A route only proves local binding and
inspection eligibility; provider authentication, account permissions, and
model availability still need independent qualification.

The extension runs `kepr hook` before session startup, tool calls, and prompts.
It recursively checks message text and structured tool arguments, bounds the
redaction cache and child checks, and fails closed when the check is invalid or
times out. Signed reasoning is never edited: key-shaped signed reasoning is
refused. Privacy masking is bounded pattern masking, not anonymity or
device-wide egress enforcement.

## MCP tools

Use the operator-owned grants explicitly:

```bash
kepr mcp --credential API_KEY_NAME --read-only
kepr mcp --credential DB_LOGIN --ssh deploy@host --ssh-key DEPLOY_KEY
```

`list_secrets` returns names and bound hosts only. `call_api` accepts an
allowlisted provider, HTTP method, and provider path; the gate injects the
credential and bounds the response. Database queries default to read-only and
must be one conservative SQL statement. SSH hosts and sign-only key names
must be granted with `--ssh` and `--ssh-key`. `--allow-writes` and
`--allow-admin` are explicit opt-ins; tenant, workspace, connector-account,
resource, action, and finite request-budget checks still apply. No MCP tool
returns a credential, and result text is scrubbed and bounded.

## Protected workspace and sandbox

Protected launches require the supported Linux sandbox, isolated networking,
and a private workspace snapshot. Use `--workspace PATH` or prepare one from
the operator terminal:

```bash
kepr workspace prepare SOURCE
kepr workspace review SESSION
kepr workspace export SESSION --approve DIGEST --output NEW_DIRECTORY
```

Review the generated patch before using the one-use digest. Export writes a
new bundle; it does not modify the original tree or silently apply deletions.
The snapshot reports files omitted for unsafe paths, links, binary or
oversized content, control characters, or failed screening. Explicit file
inputs are UTF-8 text and fail closed when they cannot be screened.

`--compatibility` is an explicit security downgrade. It may use the sandbox
when available; `--compatibility --no-sandbox` is the only non-sandbox path.
Do not use it to repair an authentication, binding, privacy, or isolation
failure. Codex protection always requires the sandbox. `local-only` currently
refuses cloud launch because local inference routing is not implemented.

## Secret-safe inspection

Never print environment variables or `.env` files. For bounded source or log
inspection that may contain key-shaped examples, pass captured text through
`kepr hook redact` and emit only its validated `text` field. If the safety
check fails, withhold the captured output. If a real credential appears,
stop and tell the operator to run `kepr leaked NAME`; do not copy or rotate it
from the agent.

An OpenAI Responses "different ... OpenAI resource" error is an upstream
conversation-state failure. Preserve item contents, tool-call links, and
encrypted reasoning; do not delete live history or disable Kepr to repair it.
Updated gates apply to new agent sessions, so leave the current gate running
while it is in use.
