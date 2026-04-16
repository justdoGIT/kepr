# CLAUDE.md

## Build / Install / Run

- `cargo build --release` — produces both binaries in `target/release/`.
- `cargo clippy -- -D warnings` — lint both binaries; zero warnings enforced.
- `cargo test` — fast, hermetic unit tests for `store`, `generate`, `protocol` (no root, no daemon, no encryption backend). Tests in `store.rs` only compile under the `credman-daemon` bin target because `main.rs` doesn't `mod`-include `store`.
- `./install.sh` — full install: builds, creates `credman` system group, installs binaries to `/usr/local/bin/credman` and `/usr/local/sbin/credman-daemon`, installs and starts the systemd service.
- `sudo systemctl restart credman.service` — reload the daemon after rebuilding.
- `./tests/e2e.sh` — end-to-end against the installed daemon. Requires `credman.service` running, the invoking user in the `credman` group, and `jq`. Cases 7 (error sanitization) and 8 (audit log) skip gracefully without sudo / journal read access. All creds it creates use the prefix `E2E_<pid>_<epoch>_` and are cleaned up on exit.
- `journalctl -t credman-daemon -f` — follow the audit log (structured fields: `CREDMAN_OP`, `CREDMAN_NAME`, `CREDMAN_UID`, `CREDMAN_USER`, `CREDMAN_RESULT`).

## Architecture

Two binaries share one crate (see `Cargo.toml` `[[bin]]` entries):

- `credman` (`src/main.rs`) — unprivileged CLI. Never invokes the encryption backend directly, never needs root/sudo. Connects to the daemon over a Unix socket and exchanges JSON.
- `credman-daemon` (`src/daemon.rs`) — root systemd service. Owns all encrypt/decrypt/delete operations and audit logging. Dispatches connections to a bounded worker pool (`daemon_pool.rs`) to cap concurrency and prevent thread exhaustion.

**Socket contract:** `/run/credman/credman.sock`, owned `root:credman 0660`. Any user in the `credman` group can connect; the daemon reads the peer uid via `SO_PEERCRED` and uses *that* uid for namespacing — never trust a uid from the request body.

**Per-user namespacing:** credentials live in the shared `/etc/credstore.encrypted/` directory but are named `credman-<uid>-<lowercased-name>` (see `src/store.rs`). `list_for_uid` filters by this prefix so users only ever see their own credentials. This is the *only* access-control boundary for reads — there is no per-file unix permission separation between users.

**Module split (enforced by `mod` declarations in each binary):**
- Shared by both: `protocol.rs` (wire types, socket path, limits), `generate.rs` (CSPRNG + `ZeroString`), `framing.rs` (length-prefixed u32 wire framing).
- CLI-only: `client.rs` (framed JSON transport), `cli_args.rs` (argv parsing), `cli_cmds.rs` (set/get/list/delete/check orchestration), `cli_ui.rs` (ANSI/JSON rendering), `cli_input.rs` (masked TTY entry), `cli_mode.rs` (colour/JSON flags), `cli_activity.rs` (subcommand newtype).
- Daemon-only: `store.rs` (naming, validation, path helpers), `crypto.rs` (wraps the host-keyed encryption backend), `audit.rs` (journal logging), `daemon_handlers.rs` (operation handlers), `daemon_peer.rs` (SO_PEERCRED extraction), `daemon_pool.rs` (bounded worker pool), `daemon_socket.rs` (socket setup), `daemon_cache.rs` (per-uid credstore scan cache).

When adding a new command, touch all three layers: add a variant to `Request`/`Response` in `protocol.rs`, a client function in `cli_cmds.rs` (with transport via `client.rs`), and a handler + audit call in `daemon_handlers.rs`.

## Conventions that matter

- **Never log secret values.** Audit entries include op/name/uid/user/result only — see `DOCS.md` §3.3.
- **Hide the encryption backend from users.** `crypto::sanitize_error` scrubs internal tool names and flags from error output; the systemd unit uses a neutral `SyslogIdentifier`. Preserve this stance in any new code, error strings, and docs — refer to it generically as "the credential backend."
- **Validate names in the daemon**, not just the client. `store::validate_name` (A-Z/0-9/underscore, ≤128 chars) is the boundary against path traversal; every handler that takes a `name` must call it.
- **Secrets use `ZeroString`** (from `generate.rs`) so memory is wiped on drop. Don't convert to plain `String` except at the socket boundary.
- **Names are uppercased** on the client (`cli_args.rs` / `cli_cmds.rs`) and re-uppercased in the daemon. The lowercase form only exists inside the on-disk cred name.

## Reference files

- `README.md` — install, usage, file layout, troubleshooting.
- `DOCS.md` — architecture, design patterns, sequence diagrams, test matrix.
- `systemd/credman.service` — hardening flags (`ProtectSystem=strict`, `ReadWritePaths` allowlist, `MemoryDenyWriteExecute`, etc.). `NoNewPrivileges=no` is intentional — the backend needs root to use the host key.

## Skill routing

When the user's request matches an available skill, ALWAYS invoke it using the Skill
tool as your FIRST action. Do NOT answer directly, do NOT use other tools first.
The skill has specialized workflows that produce better results than ad-hoc answers.

Key routing rules:
- Product ideas, "is this worth building", brainstorming → invoke office-hours
- Bugs, errors, "why is this broken", 500 errors → invoke investigate
- Ship, deploy, push, create PR → invoke ship
- QA, test the site, find bugs → invoke qa
- Code review, check my diff → invoke review
- Update docs after shipping → invoke document-release
- Weekly retro → invoke retro
- Design system, brand → invoke design-consultation
- Visual audit, design polish → invoke design-review
- Architecture review → invoke plan-eng-review
- Save progress, checkpoint, resume → invoke checkpoint
- Code quality, health check → invoke health

## Health Stack

- lint: cargo clippy -- -D warnings
- test: cargo test
- shell: shellcheck install.sh tests/e2e.sh
