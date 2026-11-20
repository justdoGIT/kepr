# Kepr — Sealed Credentials for Applications and Agents

Kepr is a Linux-first credential vault with a CLI, local daemon, agent gate, Git/Docker credential helpers, and an optional Kubernetes ESO provider. Applications receive readable credentials through sealed memory descriptors. Protected AI sessions receive placeholders: the gate uses sealed keys only for their bound destinations, without giving the agent the stored values.

```
Operator["Operator terminal"] --> Daemon["Kepr daemon"]
Daemon -- "readable app credential via memfd" --> App["Application"]
Agent["Protected agent with placeholder"] --> Gate["Local session gate"]
Gate -- "private authenticated channel" --> Daemon
Gate -- "bound-host authenticated request" --> Provider["Model provider"]
```

The default Linux user socket is `/run/user/<uid>/kepr/kepr.sock`; the optional root-managed system daemon uses `/run/kepr/kepr.sock`. A local gate does not make cloud inference offline or anonymous.

---

## Credential Delivery Boundaries

| Workflow | Command | Who receives the real value? |
| --- | --- | --- |
| Application integration | `kepr exec --memfd NAME -- COMMAND` | The application reads it from an inherited descriptor. |
| Protected agent session | `kepr agent run HARNESS` | The daemon/gate use it; the harness receives a session placeholder. |
| Legacy agent injection | `kepr protect-agent` | The agent reads the injected value; not the sealed-key boundary. |

---

## Quickstart

### Installation

```bash
# Clone and run hermetic installer
git clone https://github.com/aikepeer/kepr.git && cd kepr
./install.sh
```

The installer builds and installs `kepr`, `kepr-daemon`, `kepr-gate`, and both credential helpers to `/usr/local/bin`. It restarts the system daemon and gate service on systemd, or the selected per-user daemon otherwise, including `--login` installations. Linux user-mode restart requires Python 3.9 or newer. Restarting ends active agent gates but does not reset the vault; a protected store may need `kepr unlock` afterward.

### Basic Usage

**For an application that supports Kepr's `KEPR_FD_NAME` descriptors:**

```bash
kepr set APP_TOKEN                       # masked terminal input
kepr exec --memfd APP_TOKEN -- your-app  # app reads KEPR_FD_APP_TOKEN
```

**For a protected AI agent session — store provider credentials once, then run:**

```bash
kepr agent add ANTHROPIC_API_KEY --for anthropic
kepr agent add XAI_API_KEY --for xai
kepr agent add OPENAI_API_KEY --for openai

kepr agent install omp                  # one-time plugin/config integration
kepr agent install grok                 # Grok Build, not community grok-cli

kepr agent run omp                      # from the project directory
kepr agent run grok
kepr agent run codex
```

Each `agent add` reads hidden input, seals the value, and binds its permitted destination. `kepr agent ls` lists names/bindings, not values. `kepr get` refusing a sealed key is expected. Codex uses its selected API provider's sealed key; an existing Selora profile can be launched with `kepr agent run codex -- codex --profile selora`. Community grok-cli uses `kepr agent run grok-cli` instead of the Grok Build integration.

Protected runs edit a private copy. Keep the announced session identifier and review/export its changes afterward; see the [agent guide](docs/content/docs/guides/ai-agents.mdx). Explicit `--compatibility` weakens protection and is not a recommended workaround.

#### Workspaces and Windows (`--workspace` and `--window`)

- **Workspace Snapshot (default)**: `kepr agent run <harness>` creates an ephemeral private workspace snapshot under `~/.local/state/kepr/workspace/<SESSION>` in an isolated user/mount namespace. Files are screened against sensitive patterns, size limits (max 2 MB/file), and depth limits.
- **In-Place Compatibility Mode** (for existing repos with build directories):
  ```bash
  kepr agent run omp --compatibility
  kepr agent run codex --compatibility
  kepr agent run claude --compatibility
  ```
  The agent operates directly on your working tree (where `git` provides version control), while Kepr's TLS proxy gate remains active — LLM provider keys remain sealed behind session placeholders (`kepr-ph-...`).
- **Terminal Windows (`--window`)** spawns a dedicated Rio GPU-accelerated terminal window.
- **Inside Zellij**: run directly in your active pane, or open a new tab:
  ```bash
  zellij action new-tab --name "omp" -- kepr agent run omp --compatibility
  ```

`kepr lock` / `kepr unlock` manage vault passphrase protection; they do not make sealed entries readable. A vault that reports unlocked can still have a separate ciphertext authentication failure. Preserve its credentials and original key or recovery material; do not reset the vault or overwrite entries to troubleshoot it. After recovery, `kepr check` verifies decryption without printing values. Add or replace keys only once the vault is healthy, using hidden terminal prompts — not command arguments, `.env`, harness config files, or chat.

Use bare option names such as `generate`, `quiet`, and `env`. Existing forms with a `--` prefix remain accepted. See `kepr help COMMAND` for each command's usage. Help forms do not contact the daemon. The `--` separator before a child command is optional for `exec` and `protect-agent`. `kepr-daemon help` documents daemon startup; credential operations remain on the `kepr` client.

Install user-local Bash completion:

```bash
install -D -m 0644 completions/kepr.bash \
  "$HOME/.local/share/bash-completion/completions/kepr"
install -D -m 0644 completions/kepr.bash \
  "$HOME/.local/share/bash-completion/completions/kepr-daemon"
```

---

## Agent Commands — Complete Reference

The `kepr agent` commands manage sealed credentials for protected AI sessions. Each `agent add` binds a credential to a specific provider destination; the daemon-spawned gate swaps the session placeholder for the real value only when the agent calls that exact host.

**Important:** The usage line shows two separate subcommands:
- `kepr agent add NAME ...` — stores a new sealed credential
- `kepr agent add-cloudflare` — seals existing Cloudflare credentials (no NAME argument)

They are alternatives (separated by `|` in the usage), not a single command.

---

### `kepr agent add NAME [--for PROVIDER]... [--stdin|--from-clipboard]` — Store a sealed provider credential

**Arguments:**
- `NAME` — The credential name (uppercase, e.g., `ANTHROPIC_API_KEY`)
- `--for PROVIDER` — Bind this credential to a provider destination. Can be repeated for multiple destinations. The provider determines which host:port the gate will swap the placeholder for. Common providers: `anthropic`, `openai`, `xai`, `github`, `gitlab`, `cloudflare`.

**Input methods (choose one):**
- **Interactive (default):** Prompts for masked input — recommended for terminals
- `--stdin` — Read value from stdin (for scripts/pipelines)
- `--from-clipboard` — Read from clipboard (Wayland/X11)

```bash
# Interactive masked input (recommended for terminals)
kepr agent add ANTHROPIC_API_KEY --for anthropic
# Prompts: Enter value for ANTHROPIC_API_KEY: ****

# From stdin (for scripts/CI)
printf 'sk-ant-v0-...\n' | kepr agent add ANTHROPIC_API_KEY --for anthropic --stdin

# Multiple destinations for the same key (gate will swap for both)
kepr agent add OPENAI_API_KEY --for openai --for github

# From clipboard
kepr agent add GITHUB_TOKEN --for github --from-clipboard
```

**When to use `--for`:** Every sealed credential MUST be bound to at least one provider. The gate only swaps the placeholder when the agent makes an HTTPS request to that exact destination. Without `--for`, the credential cannot be used by any agent.

---

### `kepr agent run HARNESS [options]` — Start a protected agent session

**Arguments:**
- `HARNESS` — The agent to run: `omp`, `grok`, `opencode`, `claude`, `codex`, `cursor`, `copilot`, `grok-cli`

**Workspace options (mutually exclusive):**
- *(default)* — Creates an ephemeral **workspace snapshot** of the current directory under `~/.local/state/kepr/workspace/<SESSION>`. The agent operates on this isolated copy. Use `kepr workspace review` and `kepr workspace export` to apply changes back.
- `--workspace PATH` — Snapshot a specific directory instead of the current one
- `--workspace-session SESSION` — Reuse an existing workspace session by its ID (avoids re-snapshotting)

**Mode options:**
- `--compatibility` — **In-place mode**: Agent operates directly on your working tree (where `git` provides version control). Kepr's TLS proxy gate remains active — LLM keys stay sealed behind placeholders. Use this for existing repos with build directories (`target/`, `node_modules/`) that hit snapshot limits.
- `--window` — Spawn a dedicated Rio GPU-accelerated terminal window (Wayland/X11)

**Security presets:**
- `--security-preset private-cloud` — Default: masks supported text schemas before forwarding; not an anonymity guarantee
- `--security-preset local-only` — Refuses to launch (local inference routing not implemented)

**Resource limits (optional):**
- `--port N` — Gate listening port (default: random)
- `--max-requests N` — Max requests per session
- `--max-tokens N` — Max tokens per session
- `--rate N` — Max requests per minute
- `--max-requests-day N` / `--max-tokens-day N` — Daily limits

**Pass arguments to the agent:**
```bash
kepr agent run omp -- omp "your prompt here"
# Everything after `--` is passed to the agent command
```

```bash
# Basic run (current directory becomes workspace snapshot)
kepr agent run omp

# Reuse an existing workspace session
kepr agent run omp --workspace-session abc123

# Run in a dedicated terminal window (Rio on Wayland)
kepr agent run omp --window

# Compatibility mode (operates on your actual working tree, git for rollback)
kepr agent run omp --compatibility
kepr agent run codex --compatibility
kepr agent run claude --compatibility

# With resource limits
kepr agent run omp --max-requests 100 --max-tokens 200000 --rate 10

# Pass arguments to the agent
kepr agent run omp -- omp "your prompt here"
```

**What happens:** The daemon spawns `kepr-gate` for this session. The agent receives `kepr-ph-...` placeholders in its environment. When the agent makes an HTTPS request to a bound destination (e.g., `anthropic.com:443`), the gate swaps the placeholder for the real credential.

---

### `kepr agent install HARNESS` — One-time harness integration

Installs the harness-specific plugin/config integration so it can use Kepr's sealed credentials. Run once per harness per machine.

```bash
# Install OMP plugin/config integration
kepr agent install omp

# Install Grok Build integration (not community grok-cli)
kepr agent install grok

# Install Codex, Claude, Cursor, Copilot, OpenCode
kepr agent install codex
kepr agent install claude
kepr agent install cursor
kepr agent install copilot
kepr agent install opencode
```

This sets up the harness to use Kepr's sealed credentials (e.g., writes the `kepr-ssh-keygen` adapter for Git signing).

---

### `kepr agent ls` — List agent credentials and bindings

Shows all sealed credentials for the current user with their bound destinations.

```bash
kepr agent ls
# ANTHROPIC_API_KEY → anthropic.com:443
# OPENAI_API_KEY → api.openai.com:443
# GITHUB_TOKEN → github.com:443
```

---

### `kepr agent doctor` — Diagnose protected harness setup

Checks daemon reachability, gate spawn, credential bindings, and reports missing/incorrect setup.

```bash
kepr agent doctor
# ✓ kepr-daemon reachable
# ✓ kepr-gate spawns
# ✓ ANTHROPIC_API_KEY bound to anthropic.com:443
# ✗ OPENAI_API_KEY missing (run: kepr agent add OPENAI_API_KEY --for openai)
```

Options: `--port N` (gate port), `--json` (machine-readable output).

---

### `kepr agent shim HARNESS [--dir DIR] [--remove]` — Create a wrapper script

Creates a wrapper script that runs `kepr agent run HARNESS --compatibility` so you can type just the harness name.

```bash
kepr agent shim omp --dir ~/.local/bin
# Creates ~/.local/bin/omp that runs: kepr agent run omp --compatibility -- omp "$@"

# Remove the shim
kepr agent shim omp --remove
```

---

### `kepr agent revoke NAME` — Remove a sealed agent credential

```bash
kepr agent revoke ANTHROPIC_API_KEY
```

---

### `kepr agent add-cloudflare` — Seal existing Cloudflare login

Seals the existing `CLOUDFLARE_AI_GATEWAY_API_KEY`, `CLOUDFLARE_ACCOUNT_ID`, and `CLOUDFLARE_GATEWAY_ID` credentials inside the daemon. No credential values are returned. Protected applications receive session placeholders and a local gate URL.

```bash
kepr agent add-cloudflare
# Seals CLOUDFLARE_AI_GATEWAY_API_KEY, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_GATEWAY_ID
```

**Note:** This is a separate subcommand (not `kepr agent add NAME`). It reads the three Cloudflare keys from the regular store and seals them for agent use.

---

## Help with Examples for Every Command

```bash
kepr help                    # All commands with examples
kepr set help                # set-specific help
kepr help agent              # agent commands with examples (agent help shows usage only)
kepr exec help               # exec usage with manifest/env/memfd examples
kepr unlock help             # unlock usage
```

### Example Output: `kepr help agent`

```
USAGE:
  kepr agent add NAME [--for PROVIDER]... [--stdin|--from-clipboard]
  kepr agent add-cloudflare
  kepr agent run HARNESS [--workspace PATH | --workspace-session SESSION] [--window] [--security-preset private-cloud|local-only] [--compatibility [--no-sandbox]] [--port N] [--max-requests N] [--max-tokens N] [--rate N] [--max-requests-day N] [--max-tokens-day N] [-- ARGV...]
  kepr agent install omp|grok|opencode|claude|codex|cursor|copilot
  kepr agent doctor [--port N] [--json]
  kepr agent shim HARNESS [--dir DIR] [--remove]
  kepr agent ls
  kepr agent revoke NAME

EXAMPLES:
  kepr agent add ANTHROPIC_API_KEY --for anthropic     # interactive, masked input
  printf 'sk-ant-v0-...\n' | kepr agent add ANTHROPIC_API_KEY --for anthropic --stdin
  kepr agent add OPENAI_API_KEY --for openai --for github  # multiple destinations
  kepr agent ls                                      # list bindings
  kepr agent run omp                                 # snapshot mode (current dir)
  kepr agent run omp --compatibility                 # in-place mode (git for rollback)
  kepr agent run omp --window                        # dedicated Rio terminal window
  kepr agent install omp                             # one-time harness integration
  kepr agent install grok                            # Grok Build integration
  kepr agent install codex                           # Codex integration
  kepr agent doctor                                  # diagnose protected harness setup
  kepr agent shim omp --dir ~/.local/bin             # create wrapper script
  kepr agent revoke ANTHROPIC_API_KEY                # remove sealed agent credential
```

---

## Integrations

### Git Credential Helper

```bash
git config --global credential.helper kepr
```

### Docker Credential Helper

In `~/.docker/config.json`:

```json
{ "credsStore": "kepr" }
```

### Direnv Integration (`.envrc`)

```bash
source_env completions/kepr.envrc
use_kepr OPENAI_API_KEY ANTHROPIC_API_KEY
```

---

## Example Cases — When Things Go Wrong

### Case 1: Agent reports "cannot connect to credential service at /run/user/1000/kepr/kepr.sock"

**What happened:** The agent tried to use a sealed credential, but the Kepr daemon is not running or the socket is stale.

**Immediate check:**

```bash
kepr status
```

If it prints the connection error, the daemon is down.

**Fix:**

```bash
# User daemon (runit)
sudo sv start kepr-daemon

# Or system daemon (systemd)
sudo systemctl start kepr-daemon
```

Then retry the agent command.

**Why this happens:** The daemon may have been stopped by a logout, a runit restart, or the session runtime directory was recreated. The agent gate cannot auto-start the daemon when the user socket is owned by a different runtime.

---

### Case 2: Tool fails with `502 Bad Gateway: {"error":{"message":"kepr could not obtain the credential","type":"kepr"}}`

**What happened:** The gated host (e.g., `forgejo.kepr.dev`) rejected the request because the credential placeholder was not swapped. The gate could not reach the daemon.

**Immediate check:**

```bash
kepr agent ls          # Shows the bound key and its destination
kepr status            # Confirms daemon reachability
```

**Fix:**

1. Ensure daemon is running (see Case 1).
2. Verify the placeholder is in the tool config (e.g., `token: $FORGEJO_TOKEN` in `~/.config/tea/config.yml`).
3. Retry: `tea whoami`

**Why this happens:** The gate swaps the placeholder for the real credential only when the daemon is reachable. If the daemon is down or the credential is missing/bound to a different destination, the gate returns 502.

---

### Case 3: `kepr get KEY` or `kepr exec --env KEY` fails with "credential store is locked"

**What happened:** The vault is password-protected and currently locked.

**Fix:**

```bash
kepr unlock            # Enter passphrase at prompt
# Or if using the same passphrase as sudo:
kepr get KK_SUDO_PASSWORD --quiet | kepr unlock --stdin
```

Then retry.

**Why this happens:** The daemon starts with the store locked. It unlocks on successful `kepr unlock` (or PAM login with matching password). A locked store is the expected state after reboot or idle timeout.

---

### Case 4: `git commit` fails with "No private key found for public key"

**What happened:** Git's SSH signing cannot find the private key because it's only in the Kepr agent.

**Fix:**

```bash
# Ensure the adapter is installed
kepr agent install omp   # or: sudo ./install.sh --runit

# Verify the key is in the agent
ssh-add -l               # Should show the ED25519 fingerprint

# Git config (one-time)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global gpg.ssh.program kepr-ssh-keygen
```

**Why this happens:** The private key never touches disk. `kepr-ssh-keygen` selects the Kepr agent socket automatically. If the agent is not running or the key wasn't added, signing fails.

---

### Case 5: Agent session starts but `kepr agent ls` shows no credentials / empty placeholders

**What happened:** The credentials were added for a different destination, or the agent harness doesn't match the binding.

**Fix:**

```bash
kepr agent ls            # Check bound destinations
kepr agent add KEY --for PROVIDER   # Re-add with correct --for flag
```

**Why this happens:** Each `agent add` binds the credential to a specific provider host. The gate only swaps it for that exact destination.

---

## Security Architecture & Invariants

1. **Encrypted credentials**: Values use AES-256-GCM. Linux user mode defaults to an owner-only local master-key file; `kepr lock` adds Argon2id passphrase protection. A missing master key never triggers replacement generation over a nonempty credential store.
2. **Distinct exposure boundaries**: Memfd delivery avoids putting values in environment tables but the receiving application can read them. Sealed agent credentials are instead consumed by the destination-bound gate.
3. **Kernel-attested peers**: The daemon authenticates local client identity. Native Windows secret storage/IPC and macOS protection remain separate implementation and qualification work.
4. **Durable gate decisions**: Metadata-only intents are persisted before the inspected gate HTTP request is forwarded, results are paired by intent ID, and missing results reconcile to `Unknown` on daemon startup.
5. **Memory handling and limits**: Sensitive buffers use zeroizing storage; this does not establish anonymity, protect an already compromised host, or prevent all private information from being encoded into outbound requests.

---

## Documentation

Comprehensive documentation lives at **[https://kepr.dev](https://kepr.dev)** (source in `docs/` built with Fumadocs / Next.js 15):

- [Architecture & Threat Model](docs/content/docs/architecture/overview.mdx)
- [RAM Delivery Strategy (`memfd`)](docs/content/docs/architecture/ram-delivery.mdx)
- [AI Agent Protection Guide](docs/content/docs/guides/ai-agents.mdx)
- [Kubernetes ESO Integration](docs/content/docs/guides/kubernetes-eso.mdx)
- [Security implementation and remaining gaps](docs/content/docs/security-suite-plan.mdx)
- [Current and target agent security flow](docs/content/docs/agent-security-flow.mdx)

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).