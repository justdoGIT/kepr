# Kepr Quick Reference

## Essential Commands

### Ordinary Credential Management (outside agents)

```bash
kepr set APP_TOKEN            # Interactive hidden input; no value in argv
kepr get APP_TOKEN            # Reveals an ordinary readable entry in your terminal
kepr list                    # Names/metadata, not values
kepr status                  # Vault status
kepr lock                    # Lock the vault
kepr unlock                  # Unlock privately; does not unseal agent keys
```

Use `set`/`get` only for intentionally readable, non-agent credentials. Never
capture/export provider keys into an agent environment or put them in config
files. Sealed agent credentials cannot be retrieved through plaintext APIs.

### Agent Operations

```bash
kepr agent add ANTHROPIC_API_KEY --for anthropic
kepr agent add XAI_API_KEY --for xai
kepr agent ls                       # Sealed names and destination bindings
kepr agent install omp              # One-time OMP integration
kepr agent run omp                  # Protected snapshot of current folder
kepr agent install grok             # Grok Build, NOT community grok-cli
kepr agent run grok
kepr agent run grok-cli             # Community CLI needs no install step
kepr agent run codex -- codex --profile selora
kepr agent doctor                   # Integration diagnostics
```

Run `agent add` yourself outside the agent. The terminal disables echo: type
or paste the value, see no characters/asterisks, and press Enter. Bind to the
actual provider, not whichever API dialect it resembles. The Codex example
requires a configured Selora profile and `kepr agent add SELORA_API_KEY --for
selora`; OpenAI and AgentRouter instead require their selected `env_key`
credential. Arguments after `--` start with the executable.

If your current session was not launched through Kepr, relaunch with
`kepr agent run <harness>`; installing a plugin does not retrofit protection.

### Deliver Ordinary Secrets to Your Own Process

```bash
kepr exec --env APP_TOKEN -- my-app
kepr exec --memfd APP_TOKEN -- my-app
```

Both deliver plaintext to that process; memfd does not prevent it reading the
secret. These are not substitutes for sealed-agent launches and are blocked
inside agent sessions.

## Selected Provider Bindings

| Provider | Exact HTTPS host (`:443`) | Standard sealed entry / Codex `env_key` |
|----------|---------------------------|----------------------------------------|
| OpenAI | `api.openai.com` | `OPENAI_API_KEY` |
| Anthropic | `api.anthropic.com` | `ANTHROPIC_API_KEY` (not a Codex provider) |
| xAI | `api.x.ai` | `XAI_API_KEY` (not a Codex provider) |
| AgentRouter | `agentrouter.org` | `AGENTROUTER_API_KEY` |
| Selora | `api.selora.lol` | `SELORA_API_KEY` |
| Fireworks | `api.fireworks.ai` | `FIREWORKS_API_KEY` (OMP) |
| Moonshot CN | `api.moonshot.cn` | `MOONSHOT_API_KEY` (OMP) |
| Venice | `api.venice.ai` | `VENICE_API_KEY` (OMP) |

Use `kepr agent add NAME --for PROVIDER`; prefix/name inference is optional,
not a reason to bind a reseller's credential to OpenAI. Codex loads the
selected provider from `$CODEX_HOME/config.toml` (default `~/.codex`) and the
selected `NAME.config.toml` profile overlay. It requires the matching sealed
entry and HTTPS host, pins the dynamic gate route, and uses ephemeral auth.
Inline credentials and alternate auth helpers are refused. No provider/model
availability is implied by these routes.

## Integration Paths and Session Ports

- OMP host configuration: `$PI_CODING_AGENT_DIR/models.yml`, otherwise
  `${XDG_CONFIG_HOME:-~/.config}/omp/agent/models.yml`; its extension goes in
  the same agent directory's `extensions/kepr/`.
- Grok Build: `~/.grok/config.toml`; plugin source:
  `~/.local/share/kepr/plugins/grok/kepr/`, registered by the installer.
- Community grok-cli: distinct from Grok Build, although both execute `grok`;
  select the correct binary on `PATH`. Session env supplies its placeholders
  and `GROK_BASE_URL`.
- Session ports are dynamic by default. Use supplied `KEPR_GATE_URL` and
  placeholders, not a hard-coded port 7878 or plaintext config values.
- Protected launches generate a private home: host configs/auth/history are
  not copied wholesale. OMP receives an embedded extension and generated empty
  `models.yml`; Grok Build host plugin installation does not prove its hooks
  are loaded inside that private home.

For native command names, use `kepr agent shim HARNESS` and follow its PATH
instructions rather than a wrapper that accidentally passes flags to Kepr.

## Protected Workspace Workflow

```bash
kepr agent run claude --workspace /absolute/project
kepr workspace review <SESSION>
# Inspect the patch, then approve exactly that review:
kepr workspace export <SESSION> --approve <DIGEST> --output /absolute/new-bundle
```

The default snapshots the current directory. `--workspace-session SESSION`
selects an existing prepared, not previously run session; it is not a resume
flag. Export consumes an approval valid for one hour and refuses changed
contents/modes or an existing destination. The bundle contains `files/` and
`manifest.json`, including deletion metadata; it does not alter your host tree.
Run review/export in the operator terminal, not inside the agent.

## Protection Boundaries

- Protected Linux launches require sandbox and gate-only networking; failure
  stops launch rather than falling back silently. This is session-scoped,
  not device-wide protection or qualified native macOS/Windows enforcement.
- `private-cloud` provides bounded local pattern masking, not anonymity or
  zero disclosure. `local-only` refuses launch: local inference is unfinished.
- `--compatibility` explicitly disables privacy filtering, automatic snapshots,
  and required isolation. It is a security downgrade, not a repair.
- Protected mode grants inspected model routes, not arbitrary database,
  tunnel, or tool credentials. Do not disable isolation to bypass refusals.

## Troubleshooting

```bash
kepr status
kepr doctor
kepr agent doctor
kepr agent ls
```

- **Sealed-key `get` refusal:** expected; launch through Kepr, never export it.
- **Vault locked:** unlock privately; sealing and destination binding remain.
- **Missing credential/binding:** match the selected provider's `env_key` and
  exact HTTPS host, then privately add/re-add with the correct `--for`.
- **Ciphertext authentication/decryption failure:** preserve the store and
  matching master-key/recovery material; verify the intended daemon/profile
  and recover from a matching backup or enrolled recovery mechanism. A
  restart cannot repair ciphertext; do not regenerate/delete the master key.
- **Daemon unreachable:** start the approved daemon/service. User clients may
  start a missing daemon outside agents, but this is not an upgrade restart;
  protected sessions do not auto-start the host daemon.

Full details: [AI Agent Protection](../content/docs/guides/ai-agents.mdx).
