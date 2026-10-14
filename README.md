
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

- **RAM-Based Execution (`kepr exec --memfd`)**: Pass secrets to child processes using sealed, read-only memory descriptors (`KEPR_FD_<KEY>=3`). Secrets never touch `/proc/<pid>/environ` or shell history. With `kepr exec --pull`, the program fetches each secret itself, when it needs it, as a sealed fd its own children never inherit.
- **Sealed agent sessions (`kepr agent add` / `kepr agent run`)**: paste a key once; it is stored write-only and bound to its provider's host. Agent harnesses (Claude Code, Codex, grok-cli, Aider, oh-my-pi, Grok Build) get a worthless placeholder, and a local proxy (`kepr-gate`, started by the daemon, non-dumpable, key held in `memfd_secret` memory) swaps in the real key on the wire, only toward that host. The harness runs in a sandbox (user/mount/PID namespaces, seccomp, Landlock; `--isolate-net` for gate-only networking) that can't see the vault, the daemon socket or other processes. Requests containing a stored key are blocked before they reach the provider. Also: `kepr agent adopt` (move keys out of `.env`/shell rc files), `kepr mcp` (MCP server that never returns values), `--requires-consent` (polkit approval per session), `kepr panic`. See the [AI agents guide](docs/content/docs/guides/ai-agents.mdx).
- **More for agent sessions**: the gate re-signs AWS SigV4 requests made with a placeholder key pair, has presets for Stripe, npm, gcloud and Docker, logs in to PostgreSQL, MySQL and Redis for the agent, mints GitHub App installation tokens, and opens plain TCP tunnels. Sessions can be recorded (encrypted), capped per day across sessions, and given a PostgreSQL role only for their lifetime; `kepr agent logs` shows the request journal, and `kepr mcp` adds database and SSH tools that never return a credential.
- **Everyday tools**: `kepr totp` (2FA codes), `kepr inject` (fill `kepr://NAME` templates), `kepr scan` (find leaked keys; works as a pre-commit hook), `kepr copy` (clipboard, auto-cleared), `kepr exec --mask` (hide values in command output).
- **Records and organisation**: typed records (built-in types or your own, with custom fields, lists and links between records), tags, folders, `kepr search` (never matches values), a 30-day trash, aliases, a duplicate finder and encrypted file attachments. `kepr://NAME/field[i]` references work in templates, `kepr exec` / `kepr env`, `.kepr.toml` (with per-stage sets) and `kepr resolve`. Generator profiles and `kepr strength` help with new values.
- **SSH agent without key files (`kepr ssh` / `kepr ssh-agent`)**: Ed25519 keys generated or imported into the daemon are sign-only. `eval "$(kepr ssh-agent)"` lets ssh and git use them; nothing can export them. `kepr ssh rotate` replaces a key on a host and in the vault.
- **History and usage**: `kepr history` / `kepr restore` keep the last five values of every credential, encrypted; `--diff` names the record fields that changed, never their values. `kepr usage` reports uses, refusals and last use per key from the hash-chained audit log, flags keys that were never used, and with `--report` shows agent traffic and estimated cost per harness, key and host.
- **Master-key protection**: Argon2id passphrase protection (`kepr lock` / `kepr unlock`) with in-process AES-256-GCM encryption and zeroized buffers, optionally plus a FIDO2 security-key touch (`kepr lock --fido2`). A new master key can instead be bound to this machine's TPM (also with a PIN and an anti-rollback counter) or wrapped by AWS KMS, Google Cloud KMS, Azure Key Vault, a PKCS#11 token such as a YubiHSM, or the macOS keychain. The user daemon locks a passphrase-protected store on suspend, screen lock or idle (`KEPR_IDLE_LOCK`), wrong passphrases back off (optionally wiping the key after N), `kepr unlock --fingerprint` can reopen a soft-locked store, and a recovery kit (K-of-N shares or 24 words) rebuilds a lost key.
- **Vault image (opt-in)**: with `KEPR_STORE=image`, the whole store lives in one fixed-size file of encrypted, noise-filled slots, so the file doesn't show how many credentials it holds or how big they are. Slots are authenticated and covered by a Merkle root, commits are journaled, deletes crypto-shred, and an older copy of the image is refused. `kepr vault init|migrate|verify|status` manage it.
- **Sharing, devices and sync**: share a credential with another kepr user in an envelope only their daemon can open (X25519 + ML-KEM-768), with pinned contacts, QR codes and view windows; send one-time links through a self-hosted `kepr-relay`, optionally self-destructing; share whole folders as signed bundles. Enrol your other machines (optionally after an OIDC login) and sync them end-to-end encrypted over a directory, a git repository or S3. Also: passphrase-encrypted export, time-delayed emergency access, and audited break-glass and escrow paths.
- **Rotation and cloud secrets**: rotate through a hook, the AWS IAM API or the database, on a schedule the user daemon runs; `kepr aws credential-process` hands the AWS CLI temporary STS credentials, never the stored key; just-in-time grants and check-out / check-in limit when a key is usable. Cloud sync pushes and pulls single keys to and from HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault and JSON files, pushes many at once from a map file (with a dry run), and imports a store's secrets in bulk.
- **Policy and monitoring**: a deny-by-default `policy.toml` (with `kepr policy test`), access reports per key, M-of-N approvals, consent answered from a desktop or phone notification, read access limited to chosen programs by binary digest, re-authentication before a value is revealed, and canary keys that raise an alarm when used. Audit events stream to JSONL, syslog or OTLP; alert rules, anomaly rules over the gate journal and health findings post to Slack, Teams, Discord or ntfy webhooks.
- **Health, breach checks and import**: `kepr health [--breach]` flags weak, reused, old and breached values without any value leaving the daemon (k-anonymity range lookup), checks hygiene rules per tag, and warns of expiring certificates. `kepr import` reads 1Password / Bitwarden / KeePassXC / LastPass / browser CSV, Bitwarden / Keeper / Doppler / Infisical JSON, `.env`, KeePass KDBX 4 databases and kepr's own encrypted bundles; `--seal` stores provider API keys write-only. `kepr discover` finds plain-text credentials in aws/git/netrc/npm/pypi/docker/gh/kube configs and imports them, in the git and docker helpers' formats, following your own add / ignore / ask rules.
- **Platform tools**: read-only FUSE files fetched on open (`kepr mount`), kernel `logon` keys (`kepr keyring add`), encrypted credential lines for systemd units (`kepr systemd-cred`), a local CA whose key stays sealed in the store, with SPIFFE SVIDs that can require a TPM quote (`kepr pki`), a local read-only REST API (`kepr serve`), separate stores per profile (`--profile`), and `kepr shell`, `kepr batch` and a terminal UI (`kepr ui`).
- **Client SDKs**: dependency-free Python (`sdk/python`), Node.js (`sdk/node`) and Go (`sdk/go`) clients over the daemon socket. They read, write (a value or a generated one), delete and list with typed metadata; Python and Go can also take a value as a sealed fd.
- **Cross-Platform (in progress)**: Linux is fully supported and CI-tested today (`SO_PEERCRED`, systemd). macOS has a user-mode daemon (`LOCAL_PEERCRED`, `launchd`); its master key rests on filesystem permissions by default, and `KEPR_MASTER_KEY_SEAL=keychain` keeps it in the login keychain instead, read by the daemon through Security.framework. The macOS path compiles but has no macOS CI runner exercising it yet. Windows has trait scaffolding only — the daemon does not yet build or run on Windows; tracked as a follow-up.
- **Universal Integrations**: `git-credential-kepr` (Git HTTP auth), `docker-credential-kepr` (Docker login), `.envrc` (`direnv`), `kepr-eso-provider` (Kubernetes External Secrets Operator), and in `integrations/`: a Secrets Store CSI provider, a Podman secret driver, a Terraform provider, an Ansible lookup plugin, a GitHub Action and GitLab CI template, and a VS Code extension.
- **FIDO2 Hardware Auth**: Require hardware key touch for high-value credentials.
- **Build assurance**: an optional `fips` build routes the daemon's AES-256-GCM and SHA-256 and the gate's TLS through aws-lc-rs, and releases carry SLSA build provenance.

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

# 6. Organise, find and recover
kepr tag OPENAI_API_KEY +ai         # tags; `kepr mv KEY work/ml` files it in a folder
kepr search ai                      # names, tags, folders, types; never values
kepr rm OLD_TOKEN                   # to the trash for 30 days: kepr trash restore OLD_TOKEN

# 7. Give a credential to another kepr user
kepr share contact add bob kepr-pk2-…   # bob's `kepr share key` output, pinned once
kepr share send DB_PASS --to bob -o db.share   # bob: kepr share receive db.share
```

Every verb, with its flags and limits, is in the
[feature reference](docs/content/docs/reference/features.mdx) (`kepr --help`
prints the list).

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
- [Features and Command Reference](docs/content/docs/reference/features.mdx)
- [Kubernetes ESO Integration](docs/content/docs/guides/kubernetes-eso.mdx)

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
