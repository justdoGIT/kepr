
# Kepr — The Developer-Native Secret Vault That Kills `.env` Leaks

Kepr is a per-user secret vault for Linux and macOS, written in Rust (`kepr` CLI, `kepr-daemon` over Unix/IPC socket, `git-credential-kepr`, `docker-credential-kepr`, `kepr-core` library, and `kepr-eso-provider`).

It eliminates plaintext `.env` files, shell history exposures, and `/proc/<pid>/environ` leaks by delivering secrets directly into process memory via **RAM-sealed memory file descriptors (`memfd`)**.
<p align="center">
  <img src="./.github/assets/kepr.png" alt="Kepr — The Developer-Native Secret Vault" width="100%">
</p>


```
┌──────────────────────────┐         /run/kepr/kepr.sock          ┌──────────────────────────┐
│  kepr  (user process)    │ ◀──── framed JSON IPC / peer creds ─▶│ kepr-daemon  (user/root) │
│  unprivileged CLI / SDK  │                                      │ Argon2id + AES-256-GCM   │
└──────────────────────────┘                                      │ memory-sealed RAM FDs    │
                                                                  └──────────────────────────┘
                                                                                 │
                                                                                 ▼
                                                                ~/.local/share/kepr/credentials/
                                                                (or /etc/credstore.encrypted/)
```

---

## Key Differentiators

| Feature | Kepr | `.env` / `export` | `pass` / `gopass` | 1Password CLI / Vault |
|---|---|---|---|---|
| **No `/proc` Env Leaks** | **Yes (`memfd` RAM delivery)** | No (visible in `/proc`) | No (visible in `/proc`) | No (environment variables) |
| **AI Agent Protection** | **Yes: agents use keys they never see (`kepr agent run`)** | No | No | No |
| **Zero `sudo` Required** | **Yes (Standalone User Daemon)** | Yes | Yes | Yes |
| **OS Peer Isolation** | **Yes (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS)** | No | No | No |
| **Git / Docker Helpers** | **Yes (`git-credential-kepr`)** | No | Optional | Optional |
| **Zero-Knowledge Cloud Sync** | **Yes (Vault, AWS SM, GCP SM)** | No | No | Cloud lock-in |

---

## Features

- **RAM-Based Execution (`kepr exec --memfd`)**: Pass secrets to child processes using sealed, read-only memory descriptors (`KEPR_FD_<KEY>=3`). Secrets never touch `/proc/<pid>/environ` or shell history.
- **Sealed agent sessions (`kepr agent add` / `kepr agent run`)**: paste a key once; it is stored write-only and bound to its provider's host. Agent harnesses (Claude Code, Codex, grok-cli, Aider, oh-my-pi, Grok Build) get a worthless placeholder, and a local proxy (`kepr-gate`, started by the daemon, non-dumpable, key held in `memfd_secret` memory) swaps in the real key on the wire, only toward that host. The harness runs in a sandbox (user/mount/PID namespaces, seccomp; `--isolate-net` for gate-only networking) that can't see the vault, the daemon socket or other processes. Requests containing a stored key are blocked before they reach the provider. Also: `kepr agent adopt` (move keys out of `.env`/shell rc files), `kepr mcp` (MCP server that never returns values), `--requires-consent` (polkit approval per session), `kepr panic`. See the [AI agents guide](docs/content/docs/guides/ai-agents.mdx).
- **Everyday tools**: `kepr totp` (2FA codes), `kepr inject` (fill `kepr://NAME` templates), `kepr scan` (find leaked keys; works as a pre-commit hook), `kepr copy` (clipboard, auto-cleared), `kepr exec --mask` (hide values in command output).
- **SSH agent without key files (`kepr ssh` / `kepr ssh-agent`)**: Ed25519 keys generated or imported into the daemon are sign-only. `eval "$(kepr ssh-agent)"` lets ssh and git use them; nothing can export them.
- **History and usage**: `kepr history` / `kepr restore` keep the last five values of every credential, encrypted. `kepr usage` reports uses, refusals and last use per key from the hash-chained audit log, and flags keys that were never used.
- **Lock on sleep and TPM2 binding**: the user daemon stops agent gates and locks a passphrase-protected store when the machine suspends or the screen locks. `KEPR_MASTER_KEY_SEAL=tpm2` binds the master key to this machine's TPM.
- **Health, breach checks and import**: `kepr health [--breach]` flags weak, reused, old and breached values without any value leaving the daemon (k-anonymity range lookup). `kepr import` reads 1Password / Bitwarden / KeePassXC / LastPass / browser CSV, Bitwarden / Keeper / Doppler / Infisical JSON and `.env`; `--seal` stores provider API keys write-only. `kepr discover` finds plain-text credentials in aws/git/netrc/npm/pypi/docker/gh/kube configs and imports them, in the git and docker helpers' formats.
- **Client SDKs**: dependency-free Python (`sdk/python`), Node.js (`sdk/node`) and Go (`sdk/go`) clients over the daemon socket.
- **Cross-Platform (in progress)**: Linux is fully supported and CI-tested today (`SO_PEERCRED`, systemd). macOS has a user-mode daemon (`LOCAL_PEERCRED`, `launchd`) with master-key protection currently resting on filesystem permissions, not yet real Keychain integration — the macOS path compiles but has no macOS CI runner exercising it yet. Windows has trait scaffolding only — the daemon does not yet build or run on Windows; tracked as a follow-up.
- **Master Key Security**: Argon2id passphrase protection (`kepr lock` / `kepr unlock`) with in-process AES-256-GCM encryption and zeroized buffers.
- **Universal Integrations**: `git-credential-kepr` (Git HTTP auth), `docker-credential-kepr` (Docker login), `.envrc` (`direnv`), and `kepr-eso-provider` (Kubernetes External Secrets Operator).
- **FIDO2 Hardware Auth**: Require hardware key touch for high-value credentials.

---

## Quickstart

### Installation

```bash
# Clone and run hermetic installer
git clone https://github.com/aikepeer/kepr.git && cd kepr
./install.sh
```

### Basic Usage

```bash
# 1. Store a credential interactively (masked entry)
kepr set OPENAI_API_KEY

# 2. Run your app with zero secrets in /proc (RAM delivery via memfd)
kepr exec --memfd OPENAI_API_KEY -- python train.py

# 3. Give an AI agent a key it can use but never see
kepr agent add ANTHROPIC_API_KEY    # paste once; write-only from now on
kepr agent run claude               # sandboxed Claude Code gets a placeholder
kepr agent adopt --yes --remove     # move keys already in .env / ~/.bashrc into kepr

# 4. Lock your store with Argon2id passphrase
kepr lock

# 5. Unlock your store
kepr unlock
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
{
  "credsStore": "kepr"
}
```

### Direnv Integration (`.envrc`)
In your project `.envrc`:
```bash
source_env completions/kepr.envrc
use_kepr OPENAI_API_KEY ANTHROPIC_API_KEY
```

---

## Security Architecture & Invariants

1. **Zero Plaintext at Rest**: Master key wrapped with Argon2id; credential values encrypted with AES-256-GCM.
2. **Zero Plaintext in Environment**: `kepr exec --memfd` passes sealed `memfd` file descriptors (`MFD_CLOEXEC` cleared post-seal), preventing `/proc` environment snooping.
3. **Kernel-Attested Peer Isolation**: The daemon verifies peer identity using kernel-level peer credentials (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS), ignoring user-supplied request headers. Windows named-pipe SID verification is not yet implemented.
4. **Memory Wiping**: All secret strings wrap in `ZeroString` and `zeroize::Zeroizing` to ensure memory clearing on drop.

---

## Documentation

Comprehensive documentation lives at **[https://kepr.dev](https://kepr.dev)** (source in `docs/` built with Fumadocs / Next.js 15):

- [Architecture & Threat Model](docs/content/docs/architecture/overview.mdx)
- [RAM Delivery Strategy (`memfd`)](docs/content/docs/architecture/ram-delivery.mdx)
- [AI Agent Protection Guide](docs/content/docs/guides/ai-agents.mdx)
- [Kubernetes ESO Integration](docs/content/docs/guides/kubernetes-eso.mdx)

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
