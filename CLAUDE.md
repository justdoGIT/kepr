# CLAUDE.md

## Build / Install / Run

- `cargo build --release` — produces both binaries (`kepr`, `kepr-daemon`) in `target/release/`. Workspace contains the bins plus the `kepr-core` library member at `crates/kepr-core/`.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — lint everything; zero warnings enforced.
- `cargo test --workspace` — fast, hermetic unit tests across the three buckets: `kepr` (CLI module tests), `kepr-daemon` (handler / store / crypto-error / rate-limit / umask / audit), and `kepr-core` (framing / generate / protocol). `store.rs` lives in the daemon bin only — it's not `mod`-included from `main.rs`, so its tests only compile under the daemon target.
- `cd crates/kepr-core && cargo +nightly fuzz run frame_fuzz -- -max_total_time=60` — fuzz `read_frame` for 60 s. Requires `rustup install nightly` and `cargo install cargo-fuzz` once. Targets live at `crates/kepr-core/fuzz/fuzz_targets/`; corpus and crash artifacts are gitignored.
- `cd crates/kepr-core && cargo +nightly fuzz run protocol_fuzz -- -max_total_time=60` — same idea against `serde_json::from_slice::<Request>`.
- `./tests/e2e.sh` — end-to-end against the installed daemon. Requires `kepr.service` running, the invoking user in the `kepr` group, and `jq`. Cases 7 (error sanitization), 8 (audit log), 14 (on-disk magic), 15 (master-key perms) and 16 (legacy-cred sweep on daemon restart) skip gracefully without sudo / journal-read access / `systemctl`. All creds it creates use the prefix `E2E_<pid>_<epoch>_` and are cleaned up on exit.
- `./install.sh` — full install: builds, creates `kepr` system group, installs binaries to `/usr/local/bin/kepr` and `/usr/local/sbin/kepr-daemon`, installs and starts the systemd service.
- `sudo systemctl restart kepr.service` — reload the daemon after rebuilding.
- `journalctl -t kepr-daemon -f` — follow the audit log (structured fields: `KEPR_OP`, `KEPR_NAME`, `KEPR_UID`, `KEPR_USER`, `KEPR_RESULT`).

## Architecture

Two binaries share one crate (see `Cargo.toml` `[[bin]]` entries):

- `kepr` (`src/main.rs`) — unprivileged CLI. Never invokes the encryption backend directly, never needs root/sudo. Connects to the daemon over a Unix socket and exchanges JSON.
- `kepr-daemon` (`src/daemon.rs`) — root systemd service. Owns all encrypt/decrypt/delete operations and audit logging. Dispatches connections to a bounded worker pool (`daemon_pool.rs`) to cap concurrency and prevent thread exhaustion.

**Socket contract:** `/run/kepr/kepr.sock`, owned `root:kepr 0660`. Any user in the `kepr` group can connect; the daemon reads the peer uid via `SO_PEERCRED` and uses *that* uid for namespacing — never trust a uid from the request body.

**Per-user namespacing:** credentials live in the shared `/etc/credstore.encrypted/` directory but are named `kepr-<uid>-<lowercased-name>` (see `src/store.rs`). `list_for_uid` filters by this prefix so users only ever see their own credentials. This is the *only* access-control boundary for reads — there is no per-file unix permission separation between users.

**Module split:**
- `crates/kepr-core/` (library, depended on by both bins): `protocol` (wire types, socket path, limits), `generate` (CSPRNG + `ZeroString`), `framing` (length-prefixed u32 wire framing). The lib has no IO logic beyond the framing read/write helpers and no knowledge of `systemd-creds`, the daemon cache, or the credstore layout — so future out-of-tree consumers (`docker-credential-kepr`, the External Secrets Operator provider) can depend on it without pulling in root-only privileges.
- CLI-only (in `src/`): `client.rs` (framed JSON transport), `cli_args.rs` (argv parsing), `cli_cmds.rs` (set/get/list/delete/check orchestration), `cli_ui.rs` (ANSI/JSON rendering), `cli_input.rs` (masked TTY entry), `cli_mode.rs` (colour/JSON flags), `cli_activity.rs` (subcommand newtype).
- Daemon-only (in `src/`): `store.rs` (naming, validation, path helpers), `crypto.rs` (Backend trait + legacy systemd-creds path; selects the active backend via `default_backend()`), `crypto_inproc.rs` (in-process AES-256-GCM backend, default since α3), `master_key.rs` (load-or-generate the 32-byte master key sealed via systemd-creds at `/var/lib/kepr/master.key`), `audit.rs` (journal logging), `daemon_handlers.rs` (operation handlers), `daemon_peer.rs` (SO_PEERCRED extraction), `daemon_pool.rs` (bounded worker pool), `daemon_socket.rs` (socket setup; umask + chown), `daemon_cache.rs` (per-uid credstore scan cache), `daemon_ratelimit.rs` (per-uid token bucket).

When adding a new command, touch all three layers: add a variant to `Request`/`Response` in `crates/kepr-core/src/protocol.rs`, a client function in `cli_cmds.rs` (with transport via `client.rs`), and a handler + audit call in `daemon_handlers.rs`.

## Workflow

- **TDD by default.** For new features and bug fixes: write a failing test first (RED), confirm the failure mode is what you expect, implement the minimal code to make it pass (GREEN), then refactor with the suite as a safety net. Use the `verify-first` skill to lock down the success command + failure mode + rollback *before* any code change. The exception is pure mechanical refactors that preserve all external behaviour (file moves, crate splits) — there the existing suite is the contract.
- **Self-review every PR.** After `gh pr create`, before asking for merge, walk the diff yourself: re-read changed files, check error-message hygiene, look for missed test coverage, confirm the PR description matches the code, and consider edge cases the tests do not yet exercise. Post a self-review summary as a PR comment that names the riskiest assumption you made. Do this even when Codex / Copilot say nothing or 👍 — automated reviewers catch a slice; the rest you have to find before merge. Skill: `pr-review-lean`.

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
