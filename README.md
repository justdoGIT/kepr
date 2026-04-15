<p align="center">
  <img src="./.github/assets/credman.png" alt="credman" width="1280">
</p>

# credman

Per-user credential manager for Linux. An unprivileged CLI talks to a
root systemd service over a Unix socket; the daemon owns all
encryption, decryption, and audit logging. No `sudo` for day-to-day use,
no plaintext on disk, no secret values in the journal.

```
┌──────────────────────────┐         /run/credman/credman.sock         ┌──────────────────────────┐
│  credman  (your uid)     │ ◀──── framed JSON, 0660 root:credman ───▶ │ credman-daemon  (root)   │
│  unprivileged CLI        │                                           │ encrypts / decrypts      │
└──────────────────────────┘                                           │ audits to journald       │
                                                                       └──────────────────────────┘
                                                                                 │
                                                                                 ▼
                                                                /etc/credstore.encrypted/
                                                                  credman-<uid>-<name>
```

---

## Requirements

- Linux with **systemd** (the daemon is a systemd unit; the encryption
  backend ships with systemd).
- **Rust** stable toolchain (`rustc`, `cargo`) — only at build time.
- `bash`, `sudo` access for installation.
- Optional: `jq` to run `tests/e2e.sh`.

---

## Install

```bash
git clone <repo> credman && cd credman
chmod +x install.sh
./install.sh
```

The installer:

1. `cargo build --release`
2. Creates the `credman` system group and adds the invoking user.
3. Installs `/usr/local/bin/credman` (0755) and
   `/usr/local/sbin/credman-daemon` (0700, root-only).
4. Installs bash completion if `bash-completion` is present.
5. Installs and starts `credman.service`.

After install, **activate group membership** in your current shell:

```bash
newgrp credman          # or log out / in
groups | grep credman   # verify
```

Verify the daemon is reachable:

```bash
systemctl status credman
credman list            # empty list, no error
```

---

## Usage

```text
credman [--json] [--color] COMMAND [args]

COMMANDS
  set    KEY [--generate] [--value V] [--gen-kind hex|base62|pass|uuid]
  get    KEY [--quiet] [--export]
  list                                 (alias: ls)
  delete KEY [--force]                 (alias: rm)
  check
```

### Store a credential

```bash
credman set OPENAI_API_KEY                       # interactive, masked input
credman set OPENAI_API_KEY --generate            # auto-generate (default: hex)
credman set OPENAI_API_KEY --generate --gen-kind pass
credman set OPENAI_API_KEY --value sk-abc123     # non-interactive
```

Names are uppercase, `[A-Z0-9_]` only, ≤128 chars. The daemon rejects
anything else (path-traversal defence) — see
`store::validate_name`.

### Retrieve a credential

```bash
credman get OPENAI_API_KEY                       # pretty
credman get OPENAI_API_KEY --quiet               # raw value (for $(...) capture)
credman get OPENAI_API_KEY --export              # 'export OPENAI_API_KEY=...'

eval "$(credman get OPENAI_API_KEY --export)"    # load into the current shell
export OPENAI_API_KEY="$(credman get OPENAI_API_KEY --quiet)"
```

### List, verify, delete

```bash
credman list                                     # alias: ls
credman check                                    # decrypts every cred, exits 1 if any fail
credman delete OPENAI_API_KEY                    # interactive confirm
credman rm OPENAI_API_KEY --force                # no prompt
```

### Machine-readable output

`--json` emits a single JSON object on stdout. On clean errors (missing
arg, unknown verb), nothing goes to stderr — scripts can rely on a
single object or empty stdout + non-zero exit.

```bash
credman --json list | jq '.credentials[].name'
credman --json get DOES_NOT_EXIST                # {"kind":"err","error":"..."} ; exit 1
```

### Generators

| `--gen-kind` | Length | Format                                         |
| ------------ | ------ | ---------------------------------------------- |
| `hex`        | 64     | `[0-9a-f]` from 32 random bytes (default)      |
| `base62`     | 48     | `[A-Za-z0-9]`, rejection-sampled (no bias)     |
| `pass`       | 32     | upper + lower + digit + symbol                 |
| `uuid`       | 36     | RFC 4122 v4                                    |

All entropy from `/dev/urandom`.

---

## Per-user isolation

Credentials live in the shared `/etc/credstore.encrypted/` directory but
are namespaced by uid:

```
credman-1000-openai-api-key      # uid 1000
credman-1001-openai-api-key      # uid 1001 (same name, different file)
```

The daemon takes the uid from `SO_PEERCRED` on the socket, **not** from
the request payload, so users can only see and operate on their own
credentials. Group membership in `credman` is the only client-side
permission needed.

---

## Audit log

Every operation is logged to journald with structured fields. The
**value is never logged.**

```bash
journalctl -t credman-daemon                          # tail it
journalctl -t credman-daemon CREDMAN_UID=1000         # one user
journalctl -t credman-daemon CREDMAN_OP=get           # one op
journalctl -t credman-daemon CREDMAN_RESULT=fail      # only failures
```

Each entry carries `CREDMAN_OP`, `CREDMAN_NAME`, `CREDMAN_UID`,
`CREDMAN_USER`, `CREDMAN_RESULT`.

---

## Environment

| Variable           | Effect                                                |
| ------------------ | ----------------------------------------------------- |
| `NO_COLOR`         | Any value disables ANSI (overrides `--color`).        |
| `CLICOLOR_FORCE=1` | Enables ANSI without `--color`.                       |

Precedence: `NO_COLOR` > `--no-color` > `CLICOLOR_FORCE` > `--color` > off.

Exit codes: `0` on success, `1` on any error (including `check` with at
least one failed credential).

---

## Development

```bash
cargo build --release       # both binaries → target/release/
cargo test                  # hermetic unit tests; no daemon needed
./tests/e2e.sh              # end-to-end against the running daemon
sudo systemctl restart credman.service   # reload after a rebuild
```

`cargo test` covers `protocol`, `store`, `generate`, `framing`,
`cli_mode`, and `cli_activity`. The crypto / audit / handler layers are
covered by the e2e suite, which requires the installed daemon and
`credman` group membership.

See [DOCS.md](./DOCS.md) for architecture, design patterns, sequence
diagrams, and the full test matrix.

## File layout

```
src/
├── main.rs                 credman CLI entry
├── client.rs               CLI-side socket transport (framed JSON)
├── cli_activity.rs         CliActivity newtype, verb -> handler dispatch
├── cli_args.rs             argv parser, --help renderer
├── cli_cmds.rs             cmd_set/get/list/delete/check
├── cli_input.rs            masked terminal input
├── cli_mode.rs             process-wide JSON/color mode (OnceLock)
├── cli_ui.rs               ANSI helpers, print_json
├── daemon.rs               credman-daemon entry, accept loop, dispatch
├── daemon_cache.rs         per-uid credstore listing cache
├── daemon_handlers.rs      handle_{set,get,list,delete,check}
├── daemon_peer.rs          SO_PEERCRED -> peer uid
├── daemon_pool.rs          bounded worker thread pool (backpressure)
├── daemon_socket.rs        socket dir setup, 0660 root:credman
├── protocol.rs             shared Request/Response enums, wire limits
├── framing.rs              <u32 BE len><payload> codec
├── store.rs                naming, validate_name, path helpers
├── generate.rs             ZeroString, CSPRNG, UUIDv4, base62/hex/pass
├── crypto.rs               encryption-backend wrapper (daemon only)
└── audit.rs                structured journal logger (daemon only)

systemd/credman.service      hardened unit (mlockall, ProtectSystem=strict)
completions/credman.bash     bash completion with live cred-name lookup
tests/e2e.sh                 13 end-to-end cases against the installed daemon
```

Shared modules (`protocol`, `framing`, `generate`, `store`) compile into
both binaries. `crypto`, `audit`, and everything prefixed `daemon_` are
daemon-only and are not declared in `main.rs`'s module tree — the
module split is enforced by the compiler.

---

## Troubleshooting

| Symptom                                             | Fix                                                                   |
| --------------------------------------------------- | --------------------------------------------------------------------- |
| `cannot connect to credential service`              | `systemctl status credman`; ensure the unit is `active (running)`.    |
| `Permission denied` on the socket                   | Not in the `credman` group — `newgrp credman` or log out / in.        |
| `set` fails with `Read-only file system`            | First-run key seeding needs `/var/lib/systemd` writable; the unit's `ReadWritePaths` already allows this — check for a custom override. |
| `credman get` returns `credential not found`        | `credman list` to verify the name; remember names are uppercased.     |
| Audit entries missing                               | Your user lacks journal-read access — join `systemd-journal` or `adm`.|

---

## Uninstall

```bash
sudo systemctl disable --now credman.service
sudo rm /etc/systemd/system/credman.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/credman /usr/local/sbin/credman-daemon
sudo rm -f /usr/share/bash-completion/completions/credman
# Credentials are NOT removed automatically:
sudo rm -rf /etc/credstore.encrypted/credman-*
sudo groupdel credman
```

---

## License

See [LICENSE](./LICENSE).
