
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
| **AI Agent Protection** | **Yes (`kepr protect-agent`)** | No | No | No |
| **Zero `sudo` Required** | **Yes (Standalone User Daemon)** | Yes | Yes | Yes |
| **OS Peer Isolation** | **Yes (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS)** | No | No | No |
| **Git / Docker Helpers** | **Yes (`git-credential-kepr`)** | No | Optional | Optional |
| **Zero-Knowledge Cloud Sync** | **Yes (Vault, AWS SM, GCP SM)** | No | No | Cloud lock-in |

---

## Features

- **RAM-Based Execution (`kepr exec --memfd`)**: Pass secrets to child processes using sealed, read-only memory descriptors (`KEPR_FD_<KEY>=3`). Secrets never touch `/proc/<pid>/environ` or shell history.
- **AI Agent Protection (`kepr protect-agent`)**: Native wrapper for Claude Code, Cursor, Windsurf, and Aider. Keys never touch the environment table, `/proc/<pid>/environ`, or shell history — the agent reads them from a sealed `memfd`. This stops *accidental* leaks (env dumps, crash reports, shared shells); it does not stop an agent that deliberately echoes a key it already read back into its own output.
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

# 3. Protect an AI Agent session
kepr protect-agent claude -- claude

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
