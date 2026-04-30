# CLAUDE.md

## Build / Install / Run

- `cargo build --release` — produces three binaries (`kepr`, `kepr-daemon`, `docker-credential-kepr`) in `target/release/`. Workspace contains the bins plus the `kepr-core` library member at `crates/kepr-core/`.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — lint everything; zero warnings enforced.
- `cargo test --workspace` — fast, hermetic unit tests across the three buckets: `kepr` (CLI module tests), `kepr-daemon` (handler / store / crypto-error / rate-limit / umask / audit), and `kepr-core` (framing / generate / protocol). `store.rs` lives in the daemon bin only — it's not `mod`-included from `main.rs`, so its tests only compile under the daemon target.
- `cd crates/kepr-core && cargo +nightly fuzz run frame_fuzz -- -max_total_time=60` — fuzz `read_frame` for 60 s. Requires `rustup install nightly` and `cargo install cargo-fuzz` once. Targets live at `crates/kepr-core/fuzz/fuzz_targets/`; corpus and crash artifacts are gitignored.
- `cd crates/kepr-core && cargo +nightly fuzz run protocol_fuzz -- -max_total_time=60` — same idea against `serde_json::from_slice::<Request>`.
- `./tests/e2e.sh` — end-to-end against the installed daemon. Requires `kepr.service` running, the invoking user in the `kepr` group, and `jq`. Cases 7 (error sanitization), 8 (audit log), 14 (on-disk magic), 15 (master-key perms) and 16 (legacy-cred sweep on daemon restart) skip gracefully without sudo / journal-read access / `systemctl`. All creds it creates use the prefix `E2E_<pid>_<epoch>_` and are cleaned up on exit.
- `./install.sh` — full install: builds, creates `kepr` system group, installs binaries to `/usr/local/bin/kepr` and `/usr/local/sbin/kepr-daemon`, installs and starts the systemd service.
- `sudo systemctl restart kepr.service` — reload the daemon after rebuilding.
- `journalctl -t kepr-daemon -f` — follow the audit log (structured fields: `KEPR_OP`, `KEPR_NAME`, `KEPR_UID`, `KEPR_USER`, `KEPR_RESULT`).

## Architecture

Three binaries share one crate (see `Cargo.toml` `[[bin]]` entries):

- `kepr` (`src/main.rs`) — unprivileged CLI. Never invokes the encryption backend directly, never needs root/sudo. Connects to the daemon over a Unix socket and exchanges JSON.
- `kepr-daemon` (`src/daemon.rs`) — root systemd service. Owns all encrypt/decrypt/delete operations and audit logging. Dispatches connections to a bounded worker pool (`daemon_pool.rs`) to cap concurrency and prevent thread exhaustion.
- `docker-credential-kepr` (`src/docker_helper.rs`) — Phase 1 ε. Implements the docker credential-helper protocol (get/store/erase/list over stdin/stdout JSON). Wraps `client::send_request`. Same socket, same `kepr` group gate as the main CLI.

**Socket contract:** `/run/kepr/kepr.sock`, owned `root:kepr 0660`. Any user in the `kepr` group can connect; the daemon reads the peer uid via `SO_PEERCRED` and uses *that* uid for namespacing — never trust a uid from the request body.

**Per-user namespacing:** credentials live in the shared `/etc/credstore.encrypted/` directory but are named `kepr-<uid>-<lowercased-name>` (see `src/store.rs`). `list_for_uid` filters by this prefix so users only ever see their own credentials. This is the *only* access-control boundary for reads — there is no per-file unix permission separation between users.

**Module split:**
- `crates/kepr-core/` (library, depended on by both bins): `protocol` (wire types, socket path, limits), `generate` (CSPRNG + `ZeroString`), `framing` (length-prefixed u32 wire framing). The lib has no IO logic beyond the framing read/write helpers and no knowledge of `systemd-creds`, the daemon cache, or the credstore layout — so future out-of-tree consumers (`docker-credential-kepr`, the External Secrets Operator provider) can depend on it without pulling in root-only privileges.
- CLI-only (in `src/`): `client.rs` (framed JSON transport), `cli_args.rs` (argv parsing — recognises `--env CSV`, `--manifest PATH`, and the `--` separator for `kepr exec`), `cli_cmds.rs` (set/get/list/delete/check orchestration; `--export` path now uses `cli_envdump::shell_escape` so values containing shell metachars are POSIX-quoted), `cli_exec.rs` (Phase 1 — fetches creds from the daemon and `execvp`s a child with the env merged in; never forks, so the parent's process image is replaced atomically and the secret-bearing env is never observable post-fact), `cli_doctor.rs` (Phase 1 — `kepr doctor` setup-diagnostics: socket presence/mode, kepr-group membership, daemon Ping; trait-based so checks are unit-testable without a live daemon), `cli_envdump.rs` (Phase 1 — `kepr env --env VAR1,VAR2`: emits POSIX-safe `export VAR='value'` lines for `eval`/direnv; reuses the `CredFetcher` trait from `cli_exec`), `cli_manifest.rs` (Phase 1 — `.kepr.toml` parser + walk-up auto-discovery; resolver applies precedence `--env CSV > --manifest PATH > auto-discovery`; both `kepr exec` and `kepr env` route through `resolve_env_for` in `cli_activity` so the precedence is centralised), `cli_rotate.rs` (Phase 2 γ — `kepr rotate NAME --hook ./script.sh`: generate fresh value → pipe to hook on stdin → commit via `Request::Set` only on hook exit 0. Validate-then-commit ordering: cred-store carries the new value only after the hook proves the upstream accepts it. Stdin not argv to keep the secret out of `ps` output. `HookRunner` trait + `Setter` closure for unit-test injection), `sync.rs` (Phase 2 ζ — `Syncer` trait + `pick_syncer` URL-scheme dispatch + `cmd_sync_push` / `cmd_sync_pull`. Client-side: the daemon never sees the cloud token, the cloud never sees kepr's master key), `sync_vault.rs` (Phase 2 ζ — HashiCorp Vault KV v2 backend. Auth via `VAULT_ADDR` + `VAULT_TOKEN` env vars; path mapping `vault:secret/myapp/db` → `{addr}/v1/secret/data/myapp/db`. AWS / GCP backends land in follow-up PRs as additional `sync_*.rs` modules), `cli_ui.rs` (ANSI/JSON rendering), `cli_input.rs` (masked TTY entry), `cli_mode.rs` (colour/JSON flags), `cli_activity.rs` (subcommand newtype).
- Daemon-only (in `src/`): `store.rs` (naming, validation, path helpers), `crypto.rs` (Backend trait + legacy systemd-creds path; selects the active backend via `default_backend()`), `crypto_inproc.rs` (in-process AES-256-GCM backend, default since α3; writes `kepr_v2` files with a counter inside the AEAD plaintext, reads both `kepr_v1` and `kepr_v2`), `master_key.rs` (load-or-generate the 32-byte master key sealed via systemd-creds at `/var/lib/kepr/master.key`), `version_state.rs` (per-credential monotonic counter persisted at `/var/lib/kepr/cred-versions.json`; closes the rollback-by-restore finding), `expiry.rs` (Phase 2 α — sidecar `<cred>.meta` JSON file with absolute `expires_at_unix`; `handle_get` checks before decrypt, `handle_list` surfaces `expires_at`, `handle_delete` cleans up; `handle_set` rolls back the cred file on meta-write failure so a TTL-less persistent cred can never silently land), `daemon_expiry.rs` (Phase 2 β — periodic sweeper thread; ticks every 60s, walks `*.meta` siblings of cred files, removes any pair whose `expires_at_unix` is past `now`. Tombstones the version-state counter BEFORE the file unlink so a post-restore replay can't bypass rollback protection. Audit op = `expire` to distinguish from user-driven deletes), `audit_chain.rs` (Phase 2 δ — append-only hash-chained audit log at `/var/lib/kepr/audit.log`. `H_n = SHA-256(H_{n-1} || canonical_event_bytes)`. `AuditChain::open` recovers state on daemon start; `append` writes one JSON-per-line entry with self-describing `prev_hash` + `hash` fields; `verify` walks the file and rejects any tamper — edit, delete, reorder, fabrication. Wired into `audit::log` so every audit event extends the chain; chain-write failures are logged via stderr/journald with a distinctive `AUDIT_CHAIN_APPEND_FAILED` marker but never block the cred-store operation), `daemon_audit.rs` (Phase 2 δ.3 — `handle_audit_verify` for `Request::AuditVerify`. Walks the chain via `AuditChain::verify`, returns `Response::AuditOk { entries, last_hash }` on success or a tamper reason. Lives in its own file because `daemon_handlers.rs` is at the LOC ceiling and `audit_verify` is a different concept — read-only, no per-uid namespacing), `audit.rs` (journal logging), `daemon_handlers.rs` (operation handlers), `daemon_peer.rs` (SO_PEERCRED extraction), `daemon_pool.rs` (bounded worker pool), `daemon_socket.rs` (socket setup; umask + chown), `daemon_cache.rs` (per-uid credstore scan cache), `daemon_ratelimit.rs` (per-uid token bucket).

When adding a new command, touch all three layers: add a variant to `Request`/`Response` in `crates/kepr-core/src/protocol.rs`, a client function in `cli_cmds.rs` (with transport via `client.rs`), and a handler + audit call in `daemon_handlers.rs`.

## Workflow

- **TDD by default.** For new features and bug fixes: write a failing test first (RED), confirm the failure mode is what you expect, implement the minimal code to make it pass (GREEN), then refactor with the suite as a safety net. Use the `verify-first` skill to lock down the success command + failure mode + rollback *before* any code change. The exception is pure mechanical refactors that preserve all external behaviour (file moves, crate splits) — there the existing suite is the contract.
- **Self-review every PR.** After `gh pr create`, before asking for merge, walk the diff yourself: re-read changed files, check error-message hygiene, look for missed test coverage, confirm the PR description matches the code, and consider edge cases the tests do not yet exercise. Post a self-review summary as a PR comment that names the riskiest assumption you made. Do this even when Codex / Copilot say nothing or 👍 — automated reviewers catch a slice; the rest you have to find before merge. Skill: `pr-review-lean`.
- **350 LOC per file.** No `.rs` file under `src/` or `crates/*/src/` may exceed 350 lines of production code. "Production" excludes the `#[cfg(test)] mod tests { … }` block at the bottom of the file (test count is unbounded; `super::*` access keeps tests next to the code). Pinned by `tests/file_size_limit.rs` — adding a new file >350 LOC fails the test; growing an allowlisted file beyond its pinned ceiling fails the test. Refactor pressure: when a module trips the limit, split by *concept* not by line count (two 200-line files that just depend on each other don't fix anything). Existing violators are grandfathered in `ALLOWLIST` with a refactor backlog.

## Responsive UI
- Mobile-first. Breakpoints: 360/768/1024/1280px. Use Tailwind `sm:/md:/lg:/xl:`.
- Touch targets: min 44×44px. No fixed px widths >360px without `overflow-x-auto`.
- Images: `max-width:100%; height:auto`. Wide content: scrollable container + click-to-zoom.

## Pan-Zoom (diagrams/charts/images)
- Dynamic content (Mermaid, auto-layout): `minScale:0.75`, `maxScale:15`, `wheel.step:0.01`.
- Fixed content (SVG, full-size images): `minScale:0.25`, `maxScale:2`, `wheel.step:0.001`.
- Both: `doubleClick.step:1.3-1.5 mode:toggle`, `pinch.step:5`.
- Always add −/Reset/+ buttons (accessibility fallback).
- Library: `react-zoom-pan-pinch` v3+. Wrap in `<TransformWrapper>` + `<TransformComponent contentStyle={{width:'100%',height:'100%'}}>`.

## Conventions that matter

- **Never log secret values.** Audit entries include op/name/uid/user/result only — see `DOCS.md` §3.3.
- **Hide the encryption backend from users.** `crypto::sanitize_error` scrubs internal tool names and flags from error output; the systemd unit uses a neutral `SyslogIdentifier`. Preserve this stance in any new code, error strings, and docs — refer to it generically as "the credential backend."
- **Validate names in the daemon**, not just the client. `store::validate_name` (A-Z/0-9/underscore, ≤128 chars) is the boundary against path traversal; every handler that takes a `name` must call it.
- **Secrets use `ZeroString`** (from `generate.rs`) so memory is wiped on drop. Don't convert to plain `String` except at the socket boundary.
- **Names are uppercased** on the client (`cli_args.rs` / `cli_cmds.rs`) and re-uppercased in the daemon. The lowercase form only exists inside the on-disk cred name.

## Reference files

- `README.md` — install, usage, file layout, troubleshooting.
- `DOCS.md` — architecture, design patterns, sequence diagrams, test matrix.
- `systemd/kepr.service` — hardening flags: `ProtectSystem=strict`, `ReadWritePaths` allowlist (incl. `/var/lib/kepr` for the master-key file), `StateDirectory=kepr` (auto-creates `/var/lib/kepr/` at 0700), `MemoryDenyWriteExecute=yes`, `CapabilityBoundingSet=CAP_IPC_LOCK CAP_CHOWN CAP_DAC_READ_SEARCH`, `SystemCallFilter=@system-service` minus mount/reboot/swap/cpu-emulation/debug/raw-io/clock/module/obsolete, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `NoNewPrivileges=yes`. The InProc AEAD backend means per-credential ops are pure in-process; `systemd-creds` is only invoked at daemon startup to seal/unseal the master key.

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
