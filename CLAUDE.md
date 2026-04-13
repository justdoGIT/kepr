# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build / Install / Run

- `cargo build --release` — produces both binaries in `target/release/`.
- `cargo test` — fast, hermetic unit tests for `store`, `generate`, `protocol` (no root, no daemon, no encryption backend). Tests in `store.rs` only compile under the `credman-daemon` bin target because `main.rs` doesn't `mod`-include `store`.
- `./install.sh` — full install: builds, creates `credman` system group, installs binaries to `/usr/local/bin/credman` and `/usr/local/sbin/credman-daemon`, installs and starts the systemd service.
- `sudo systemctl restart credman.service` — reload the daemon after rebuilding.
- `./tests/e2e.sh` — end-to-end against the installed daemon. Requires `credman.service` running, the invoking user in the `credman` group, and `jq`. Cases 7 (error sanitization) and 8 (audit log) skip gracefully without sudo / journal read access. All creds it creates use the prefix `E2E_<pid>_<epoch>_` and are cleaned up on exit.
- `journalctl -t credman-daemon -f` — follow the audit log (structured fields: `CREDMAN_OP`, `CREDMAN_NAME`, `CREDMAN_UID`, `CREDMAN_USER`, `CREDMAN_RESULT`).

## Architecture

Two binaries share one crate (see `Cargo.toml` `[[bin]]` entries):

- `credman` (`src/main.rs`) — unprivileged CLI. Never invokes the encryption backend directly, never needs root/sudo. Connects to the daemon over a Unix socket and exchanges JSON.
- `credman-daemon` (`src/daemon.rs`) — root systemd service. Owns all encrypt/decrypt/delete operations and audit logging. Spawns a thread per connection.

**Socket contract:** `/run/credman/credman.sock`, owned `root:credman 0660`. Any user in the `credman` group can connect; the daemon reads the peer uid via `SO_PEERCRED` and uses *that* uid for namespacing — never trust a uid from the request body.

**Per-user namespacing:** credentials live in the shared `/etc/credstore.encrypted/` directory but are named `credman-<uid>-<lowercased-name>` (see `src/store.rs`). `list_for_uid` filters by this prefix so users only ever see their own credentials. This is the *only* access-control boundary for reads — there is no per-file unix permission separation between users.

**Module split (enforced by `mod` declarations in each binary):**
- Shared by both: `protocol.rs` (wire types, socket path, limits), `generate.rs` (CSPRNG + `ZeroString`), `store.rs` (naming, validation, path helpers).
- Daemon-only: `crypto.rs` (wraps the host-keyed encryption backend), `audit.rs` (journal logging).

When adding a new command, touch all three layers: add a variant to `Request`/`Response` in `protocol.rs`, a client function in `main.rs`, and a handler + audit call in `daemon.rs::dispatch`.

## Conventions that matter

- **Never log secret values.** Audit entries include op/name/uid/user/result only — see `ARCHITECTURE.md`.
- **Hide the encryption backend from users.** `crypto::sanitize_error` scrubs internal tool names and flags from error output; the systemd unit uses a neutral `SyslogIdentifier`. Preserve this stance in any new code, error strings, and docs — refer to it generically as "the credential backend."
- **Validate names in the daemon**, not just the client. `store::validate_name` (A-Z/0-9/underscore, ≤128 chars) is the boundary against path traversal; every handler that takes a `name` must call it.
- **Secrets use `ZeroString`** (from `generate.rs`) so memory is wiped on drop. Don't convert to plain `String` except at the socket boundary.
- **Names are uppercased** on the client (`main.rs`) and re-uppercased in the daemon. The lowercase form only exists inside the on-disk cred name.

## Reference files

- `ARCHITECTURE.md` — socket permissions, namespacing rules, audit log schema.
- `FILE_LAYOUT.md` — one-line map of `src/`.
- `systemd/credman.service` — hardening flags (`ProtectSystem=strict`, `ReadWritePaths` allowlist, `MemoryDenyWriteExecute`, etc.). `NoNewPrivileges=no` is intentional — the backend needs root to use the host key.
