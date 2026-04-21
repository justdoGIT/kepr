---
title: Rename credman to kepr
status: Ready
date: 2026-04-21
spec: docs/superpowers/specs/2026-04-21-rename-credman-to-kepr-design.md
feature_branch: feat/rename-credman-to-kepr
target_version: 0.3.0
---

# Rename credman to kepr Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the project, both binaries, the systemd unit, the system group,
the Unix-socket path, the credential-file prefix, the audit-log identifiers,
and every reachable code or documentation occurrence of `credman` to `kepr`.

**Architecture:** Single atomic pull request stacked on top of the design-doc
commit (`bd2ad79`) on the `feat/rename-credman-to-kepr` branch. The plan produces
roughly 12 logical commits, each reviewable in isolation. No data migration
(clean break at v0.3.0); `/etc/credstore.encrypted/credman-<uid>-<name>` files
are abandoned, and users re-enter credentials after upgrade.

**Tech Stack:** Rust 2021 (cargo), Bash, systemd, GitHub Actions,
Fumadocs (Next.js / React).

**Spec:** [`docs/superpowers/specs/2026-04-21-rename-credman-to-kepr-design.md`](../specs/2026-04-21-rename-credman-to-kepr-design.md)
(commit `bd2ad79`).

**Rename convention used throughout this plan:** three `sed` passes per file,
in the order `credman → kepr`, `CREDMAN → KEPR`, `Credman → Kepr`. That
covers all 509 occurrences counted in the pre-rename snapshot (Appendix A
of the spec). Each task ends with a `git grep` assertion proving the file
or subtree is clean, followed by a signed commit.

**Commit convention:** every commit uses `git commit -s` (SSH-signed + DCO
sign-off). Subject ≤ 50 characters, body wrapped at 72. Never mention the
session-specific details. See `CLAUDE.md` for full convention.

---

## Pre-flight

### Task 1: Verify branch, clean working tree, and spec commit

**Files:** read-only.

- [ ] **Step 1: Confirm active branch and spec commit**

Run:

```bash
git rev-parse --abbrev-ref HEAD && \
git log --oneline -1 -- docs/superpowers/specs/
```

Expected:

```
feat/rename-credman-to-kepr
bd2ad79 docs: add rename design — credman to kepr
```

If HEAD is not `feat/rename-credman-to-kepr`, stop and check out the branch
before proceeding.

- [ ] **Step 2: Confirm working tree is clean**

Run:

```bash
git status --short
```

Expected: empty, or only untracked items like `.playwright-mcp/` or
`target/`. If there are modified tracked files, commit or stash them
before starting.

- [ ] **Step 3: Snapshot the starting occurrence count for later parity**

Run:

```bash
git grep -iE '\b(credman|CREDMAN|Credman)\b' | wc -l
```

Record the number. After Task 16 the completeness grep must return zero,
so this is the baseline you're driving to 0.

---

## Phase A — Rust sources and cargo metadata

This phase is genuine TDD: `src/store.rs` already has unit tests
(`to_cred_name`, `from_cred_name`) that assert the old `credman-<uid>-<name>`
filename prefix, and `src/audit.rs` has a test asserting journal-field
formatting with `CREDMAN_*`. We update the assertions first, watch them
fail, then update the implementation.

### Task 2: Rename prefix in src/store.rs (TDD)

**Files:**
- Modify: `src/store.rs`

- [ ] **Step 1: Update the assertions first so they describe the new prefix**

Open `src/store.rs` and apply the rename pass to the test-block assertions
(lines 138–176 in the pre-rename snapshot). Do **not** change `CRED_PREFIX`
yet.

```bash
# Leave CRED_PREFIX alone; only flip literals inside #[cfg(test)] blocks.
sed -i '/^#\[cfg(test)\]/,$ s/credman-/kepr-/g' src/store.rs
sed -i '/^#\[cfg(test)\]/,$ s/notcredman-/notkepr-/g' src/store.rs
```

Sanity check that no production `CRED_PREFIX` constant was touched:

```bash
grep -n 'CRED_PREFIX\|pub const CRED_PREFIX' src/store.rs
```

Expected: one match showing `pub const CRED_PREFIX: &str = "credman";`
(still the old value).

- [ ] **Step 2: Run the store tests and watch them fail**

Run:

```bash
cargo test --quiet store::tests 2>&1 | tail -30
```

Expected: at least two failures, one per renamed assertion (for example
`test_to_cred_name_basic` and `test_from_cred_name_round_trip`), with
`left: "credman-1000-foo-bar"` vs `right: "kepr-1000-foo-bar"` style diffs.

- [ ] **Step 3: Flip the CRED_PREFIX constant**

Edit `src/store.rs` so that:

```rust
pub const CRED_PREFIX: &str = "kepr";
```

Then apply the full three-pass rename to the rest of the file (doc
comments, code-comment examples, and any remaining literals):

```bash
sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' src/store.rs
```

- [ ] **Step 4: Re-run the store tests and confirm green**

Run:

```bash
cargo test --quiet store::tests
```

Expected: all tests pass.

- [ ] **Step 5: Confirm no `credman` remains in the file**

Run:

```bash
! grep -iE '\b(credman|CREDMAN|Credman)\b' src/store.rs
```

Expected: no output, exit code 0. If this fails, re-read the file and
fix the remaining occurrences.

---

### Task 3: Rename socket and prefix references in src/protocol.rs

**Files:**
- Modify: `src/protocol.rs`

Key symbols (pre-rename):
- `SOCKET_PATH = "/run/credman/credman.sock"` (line 16)
- `SOCKET_DIR = "/run/credman"` (line 18)
- Inline doc-comments on line 3 and line 114
- Test constants around line 244 (`cred_name: "credman-1000-x"`)

- [ ] **Step 1: Apply the three-pass rename**

```bash
sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' src/protocol.rs
```

- [ ] **Step 2: Confirm the updated constants**

Run:

```bash
grep -n 'SOCKET_PATH\|SOCKET_DIR' src/protocol.rs
```

Expected:

```
pub const SOCKET_PATH: &str = "/run/kepr/kepr.sock";
pub const SOCKET_DIR: &str = "/run/kepr";
```

- [ ] **Step 3: Confirm the file is clean**

```bash
! grep -iE '\b(credman|CREDMAN|Credman)\b' src/protocol.rs
```

- [ ] **Step 4: Run the protocol unit tests**

```bash
cargo test --quiet protocol::tests
```

Expected: all pass.

---

### Task 4: Rename journal fields in src/audit.rs (TDD)

**Files:**
- Modify: `src/audit.rs`

Key references (pre-rename):
- Log prefix `[credman]` (line 72)
- `SYSLOG_IDENTIFIER=credman-daemon` (line 112)
- `MESSAGE=credman: op=...` (line 123)
- `CREDMAN_OP`, `CREDMAN_NAME`, `CREDMAN_UID`, `CREDMAN_USER`, `CREDMAN_RESULT` (lines 128–132)
- Test assertion with forged input (line 168)

- [ ] **Step 1: Update the assertion block first**

The test at roughly line 168 references forged `CREDMAN_OP=admin` /
`CREDMAN_UID=0` strings to prove line-sanitisation. Flip those literals
to `KEPR_OP` / `KEPR_UID` first (only inside the `#[cfg(test)]` block):

```bash
sed -i '/^#\[cfg(test)\]/,$ s/CREDMAN_/KEPR_/g' src/audit.rs
```

- [ ] **Step 2: Confirm the audit tests now fail**

```bash
cargo test --quiet audit::tests 2>&1 | tail -30
```

Expected: failure in whichever test references `KEPR_OP` / `KEPR_UID` —
the production emitter still writes `CREDMAN_*`, so the assertions no
longer match.

- [ ] **Step 3: Apply the full rename to the rest of the file**

```bash
sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' src/audit.rs
```

- [ ] **Step 4: Confirm the key emitted strings**

```bash
grep -n 'SYSLOG_IDENTIFIER=\|MESSAGE=\|KEPR_' src/audit.rs | head -20
```

Expected lines containing `SYSLOG_IDENTIFIER=kepr-daemon`,
`MESSAGE=kepr: op=…`, `KEPR_OP=`, `KEPR_NAME=`, `KEPR_UID=`,
`KEPR_USER=`, `KEPR_RESULT=`.

- [ ] **Step 5: Confirm the file is clean and tests green**

```bash
! grep -iE '\b(credman|CREDMAN|Credman)\b' src/audit.rs && \
cargo test --quiet audit::tests
```

Expected: no unexpected matches, and all tests pass.

---

### Task 5: Rename the unix-group lookup in src/daemon_socket.rs

**Files:**
- Modify: `src/daemon_socket.rs`

Key line (pre-rename, line 29):

```rust
let gid = group_gid("credman").unwrap_or(0);
```

Plus inline doc-comments on lines 3–4 and 28 that mention the old
socket path and group name.

- [ ] **Step 1: Apply the three-pass rename**

```bash
sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' src/daemon_socket.rs
```

- [ ] **Step 2: Confirm the group lookup flipped**

```bash
grep -n 'group_gid(' src/daemon_socket.rs
```

Expected: `let gid = group_gid("kepr").unwrap_or(0);`

- [ ] **Step 3: Confirm the file is clean**

```bash
! grep -iE '\b(credman|CREDMAN|Credman)\b' src/daemon_socket.rs
```

---

### Task 6: Rename remaining Rust sources

**Files (modify each):**
- `src/cli_activity.rs`
- `src/cli_args.rs`
- `src/cli_cmds.rs`
- `src/cli_input.rs`
- `src/cli_mode.rs`
- `src/cli_ui.rs`
- `src/client.rs`
- `src/crypto.rs`
- `src/daemon.rs`
- `src/daemon_cache.rs`
- `src/daemon_handlers.rs`
- `src/daemon_peer.rs`
- `src/daemon_pool.rs`
- `src/framing.rs`
- `src/generate.rs`
- `src/main.rs`

- [ ] **Step 1: Apply the three-pass rename to every remaining src file**

```bash
git ls-files src/*.rs | while read -r f; do
  # Skip files already done in Tasks 2–5.
  case "$f" in
    src/store.rs|src/protocol.rs|src/audit.rs|src/daemon_socket.rs) continue ;;
  esac
  sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' "$f"
done
```

- [ ] **Step 2: Confirm every src file is clean**

```bash
! git grep -iE '\b(credman|CREDMAN|Credman)\b' -- 'src/*.rs'
```

Expected: no output.

- [ ] **Step 3: Pay special attention to crypto.rs sanitize_error**

Open `src/crypto.rs` and re-read `sanitize_error`. Per the project's
`CLAUDE.md`, the encryption backend is referred to generically — the
rename must not expose or regress references to the underlying tool
(for example, `systemd-creds`). The pass above only touches `credman`
variants; confirm no change to backend-name scrubbing logic:

```bash
grep -n 'sanitize_error\|systemd-creds' src/crypto.rs
```

Expected: sanitisation logic and any `systemd-creds` references are
unchanged from the pre-rename file.

- [ ] **Step 4: Run the full crate tests**

```bash
cargo test --quiet
```

Expected: all tests pass. If any test asserts an old string, update
the assertion (not the implementation) and re-run.

---

### Task 7: Rename cargo package, binaries, and regenerate Cargo.lock

**Files:**
- Modify: `Cargo.toml`
- Regenerated: `Cargo.lock` (via `cargo build`)

Pre-rename `Cargo.toml` declares:

```
name = "credman"
version = "0.2.0"
[[bin]] name = "credman"
[[bin]] name = "credman-daemon"
```

(22 total occurrences in the file.) The version bump to `0.3.0` is
intentionally deferred to Task 17 so it lands in its own commit.

- [ ] **Step 1: Apply the rename to Cargo.toml**

```bash
sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' Cargo.toml
```

- [ ] **Step 2: Verify the three top-of-file identifiers**

```bash
grep -E '^(name|version|\[\[bin\]\])' Cargo.toml
```

Expected:

```
name = "kepr"
version = "0.2.0"
[[bin]]
name = "kepr"
[[bin]]
name = "kepr-daemon"
```

(`version` still 0.2.0 — do not touch yet.)

- [ ] **Step 3: Regenerate Cargo.lock**

```bash
cargo build --release 2>&1 | tail -5
```

Expected: successful build, binaries at `target/release/kepr` and
`target/release/kepr-daemon`. `Cargo.lock` now lists `kepr 0.2.0`.

- [ ] **Step 4: Confirm Cargo files are clean**

```bash
! git grep -iE '\b(credman|CREDMAN|Credman)\b' -- Cargo.toml Cargo.lock
```

- [ ] **Step 5: Commit Phase A**

```bash
git add src/ Cargo.toml Cargo.lock
git commit -s -m "$(cat <<'EOF'
refactor(rust): rename to kepr across sources

Updates every Rust source, the cargo package and bin names, and the
regenerated lockfile from credman to kepr. Flips the on-wire socket
path, credential-name prefix, audit-log field names, syslog identifier,
and unix group lookup. Existing unit tests updated first (TDD); no
behaviour changes beyond the rename.
EOF
)"
```

- [ ] **Step 6: Run the full gate**

```bash
cargo test --quiet && cargo clippy -- -D warnings
```

Expected: tests green, clippy clean.

---

## Phase B — Systemd unit and shell completion

### Task 8: Rename systemd unit file and update its body

**Files:**
- Rename: `systemd/credman.service` → `systemd/kepr.service`
- Modify: `systemd/kepr.service` (post-rename)

Pre-rename unit contains `Description=credman — credential manager daemon`,
`Documentation=man:credman(1)`, `RuntimeDirectory=credman`,
`ExecStart=/usr/local/sbin/credman-daemon`,
`ReadWritePaths=/run/credman /etc/credstore.encrypted /var/lib/systemd`,
`SyslogIdentifier=credman-daemon`.

- [ ] **Step 1: git mv the file**

```bash
git mv systemd/credman.service systemd/kepr.service
```

- [ ] **Step 2: Apply the three-pass rename to the body**

```bash
sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' systemd/kepr.service
```

- [ ] **Step 3: Verify the key directives**

```bash
grep -E '^(Description|Documentation|RuntimeDirectory|ExecStart|ReadWritePaths|SyslogIdentifier)=' systemd/kepr.service
```

Expected: every directive now references `kepr` / `kepr-daemon` /
`/run/kepr`. Note: `/etc/credstore.encrypted` stays — it is a
systemd-creds convention, not a credman-specific path (see spec §3).

- [ ] **Step 4: Confirm the file is clean**

```bash
! grep -iE '\b(credman|CREDMAN|Credman)\b' systemd/kepr.service
```

- [ ] **Step 5: Commit**

```bash
git add systemd/
git commit -s -m "systemd: rename unit + internals to kepr"
```

---

### Task 9: Rename bash completion file and update its body

**Files:**
- Rename: `completions/credman.bash` → `completions/kepr.bash`
- Modify: `completions/kepr.bash` (post-rename)

- [ ] **Step 1: git mv the file**

```bash
git mv completions/credman.bash completions/kepr.bash
```

- [ ] **Step 2: Apply the three-pass rename**

```bash
sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' completions/kepr.bash
```

- [ ] **Step 3: Verify the completion registration**

```bash
grep -n '^complete \|_kepr\|_credman' completions/kepr.bash
```

Expected: the trailing `complete -F _kepr kepr` line and internal
function names (for example `_kepr`, `_kepr_get`) all use `kepr`.
No `_credman` identifiers remain.

- [ ] **Step 4: Confirm the file is clean**

```bash
! grep -iE '\b(credman|CREDMAN|Credman)\b' completions/kepr.bash
```

- [ ] **Step 5: Commit**

```bash
git add completions/
git commit -s -m "build: rename bash completion to kepr"
```

---

## Phase C — Install, packaging, tests

### Task 10: Update install.sh and Debian packaging scripts

**Files:**
- Modify: `install.sh`
- Modify: `packaging/debian/postinst`
- Modify: `packaging/debian/prerm`

`install.sh` has 37 occurrences, mostly paths (`/usr/local/bin/credman`,
`/usr/local/sbin/credman-daemon`, the `credman` group, the
`/etc/systemd/system/credman.service` link) and prose.

- [ ] **Step 1: Apply the rename to all three files**

```bash
for f in install.sh packaging/debian/postinst packaging/debian/prerm; do
  sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' "$f"
done
```

- [ ] **Step 2: Spot-check install.sh paths**

```bash
grep -n '/usr/local/\|systemd/system\|groupadd\|usermod' install.sh | head
```

Expected: paths are `/usr/local/bin/kepr`, `/usr/local/sbin/kepr-daemon`,
`/etc/systemd/system/kepr.service`, and the created group is `kepr`.

- [ ] **Step 3: Shellcheck install.sh**

```bash
shellcheck install.sh
```

Expected: clean exit.

- [ ] **Step 4: Confirm the three files are clean**

```bash
! git grep -iE '\b(credman|CREDMAN|Credman)\b' -- install.sh packaging/debian/
```

- [ ] **Step 5: Commit**

```bash
git add install.sh packaging/
git commit -s -m "build: update install + debian scripts for kepr"
```

---

### Task 11: Update the e2e test runner

**Files:**
- Modify: `tests/e2e.sh`

63 occurrences — highest-density file in the repo. The `E2E_` prefix
used for test-credential names stays as `E2E_`; the three-pass sed
only flips `credman`, `CREDMAN`, `Credman` token boundaries and does
not touch `E2E_`.

- [ ] **Step 1: Apply the rename**

```bash
sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' tests/e2e.sh
```

- [ ] **Step 2: Confirm the binary invocations and service references**

```bash
grep -En '\b(kepr|credman)' tests/e2e.sh | head -20
```

Expected: every invocation is `kepr` / `sudo systemctl … kepr.service`;
the `E2E_` test-credential prefix is still present and unchanged.

- [ ] **Step 3: Shellcheck**

```bash
shellcheck tests/e2e.sh
```

Expected: clean exit. The existing `SC2015` suppression is preserved.

- [ ] **Step 4: Confirm the file is clean**

```bash
! grep -iE '\b(credman|CREDMAN|Credman)\b' tests/e2e.sh
```

- [ ] **Step 5: Commit**

```bash
git add tests/e2e.sh
git commit -s -m "test(e2e): rename invocations to kepr"
```

---

## Phase D — GitHub machinery

### Task 12: Update GitHub config, templates, and workflows

**Files:**
- Modify: `.github/CODEOWNERS`
- Modify: `.github/dependabot.yml`
- Modify: `.github/codeql/codeql-config.yml`
- Modify: `.github/ISSUE_TEMPLATE/01-bug-report.yml`
- Modify: `.github/ISSUE_TEMPLATE/02-feature-request.yml`
- Modify: `.github/ISSUE_TEMPLATE/config.yml`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/docs-deploy.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `.github/workflows/security.yml`

Workflow steps that reference `target/release/credman` or
`target/release/credman-daemon` will flip automatically via sed. Check
these carefully during the diff review because they gate CI outputs.

- [ ] **Step 1: Apply the rename to the `.github/` subtree**

```bash
git ls-files .github/ | while read -r f; do
  sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' "$f"
done
```

- [ ] **Step 2: Confirm the subtree is clean**

```bash
! git grep -iE '\b(credman|CREDMAN|Credman)\b' -- '.github/'
```

- [ ] **Step 3: Review the diff for CI-artifact paths**

```bash
git diff --stat -- .github/ && \
git diff -- .github/workflows/release.yml | head -80
```

Manually confirm:
- All artifact paths say `target/release/kepr` or `target/release/kepr-daemon`.
- Any issue-template `labels` that mentioned `credman` are renamed (if
  the repo previously used a `credman` label in GitHub UI, that is a
  post-merge concern — the spec Appendix B notes label management is
  external to this PR).

- [ ] **Step 4: Validate workflow YAML syntax**

```bash
for f in .github/workflows/*.yml; do
  python3 -c "import yaml,sys; yaml.safe_load(open('$f'))" || { echo "YAML FAIL: $f"; exit 1; }
done
```

Expected: no output, exit 0.

- [ ] **Step 5: Commit**

```bash
git add .github/
git commit -s -m "ci: rename workflow + config references to kepr"
```

---

## Phase E — Documentation

### Task 13: Update root documentation

**Files:**
- Modify: `README.md`
- Modify: `DOCS.md`
- Modify: `SECURITY.md`
- Modify: `CONTRIBUTING.md`
- Modify: `CLAUDE.md`

These carry the highest prose-change volume (README 57, DOCS.md 56,
CLAUDE.md 10, others smaller).

- [ ] **Step 1: Apply the rename**

```bash
for f in README.md DOCS.md SECURITY.md CONTRIBUTING.md CLAUDE.md; do
  sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' "$f"
done
```

- [ ] **Step 2: Spot-check references**

```bash
grep -nE '\bkepr\b|\bKEPR\b|\bKepr\b' README.md | head -10 && \
grep -nE 'backend|systemd-creds|/etc/credstore' DOCS.md | head -10
```

Confirm:
- README shows `kepr` in install commands, `journalctl -t kepr-daemon`,
  and the tagline.
- DOCS.md still refers to the encryption backend generically; the
  rename has not re-exposed `systemd-creds` anywhere.

- [ ] **Step 3: Confirm the five files are clean**

```bash
! git grep -iE '\b(credman|CREDMAN|Credman)\b' -- README.md DOCS.md SECURITY.md CONTRIBUTING.md CLAUDE.md
```

- [ ] **Step 4: Commit**

```bash
git add README.md DOCS.md SECURITY.md CONTRIBUTING.md CLAUDE.md
git commit -s -m "docs: rename root markdown to kepr"
```

---

### Task 14: Update the Fumadocs site

**Files (from spec §1.2):**
- Modify: `docs/next.config.mjs`
- Modify: `docs/source.config.ts`
- Modify: `docs/mdx-components.tsx`
- Modify: `docs/app/layout.tsx`
- Modify: `docs/app/manifest.ts`
- Modify: `docs/app/(home)/page.tsx`
- Modify: `docs/app/docs/layout.tsx`
- Modify: `docs/components/test-matrix.tsx`
- Modify: `docs/components/mermaid.tsx`
- Modify: `docs/content/docs/index.mdx`
- Modify: `docs/content/docs/quickstart.mdx`
- Modify: `docs/content/docs/architecture/overview.mdx`
- Modify: `docs/content/docs/architecture/sequence-diagrams.mdx`
- Modify: `docs/content/docs/reference/features.mdx`
- Modify: `docs/content/docs/reference/testing.mdx`
- Modify: `docs/package.json`
- Modify: `docs/package-lock.json`
- Modify: `docs/README.md`
- Modify: `docs/scripts/gen-rust-api.mjs`

- [ ] **Step 1: Apply the rename to every tracked file under `docs/`, excluding node_modules**

```bash
git ls-files 'docs/**' ':!docs/node_modules' | while read -r f; do
  sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' "$f"
done
```

- [ ] **Step 2: Confirm `docs/package.json` name and any bin fields**

```bash
grep -nE '"name"|"bin"|basePath|repoName' docs/package.json docs/next.config.mjs
```

Expected: `"name": "kepr-docs"` (or whatever the prior value was,
renamed), and the `basePath` derivation in `next.config.mjs` is
unchanged (it already derives from `repoName` env var, so no hard-coded
`/credman` survives).

- [ ] **Step 3: Rebuild package-lock.json to match**

```bash
cd docs && npm install --package-lock-only && cd ..
```

Expected: `docs/package-lock.json` is rewritten; no unexpected
dependency changes.

- [ ] **Step 4: Confirm the docs subtree is clean**

```bash
! git grep -iE '\b(credman|CREDMAN|Credman)\b' -- 'docs/' ':!docs/node_modules'
```

- [ ] **Step 5: Build the docs site to catch template breakage**

```bash
cd docs && npm run build 2>&1 | tail -20 && cd ..
```

Expected: successful build. A failure here usually means a React
component prop or MDX frontmatter field referenced the old name and
the sed pass caught it incorrectly — diff-review, fix, rebuild.

- [ ] **Step 6: Commit**

```bash
git add docs/
git commit -s -m "docs: rename fumadocs site to kepr"
```

---

## Phase F — Changelog config, completeness sweep, version bump

### Task 15: Update git-cliff commit-prefix mapping

**Files:**
- Modify: `cliff.toml`

Pre-rename (line 42–43):

```
# The existing repo uses "credman:" / "docs:" prefixes — map those too.
{ message = "^credman:",    group = "credman"      },
```

Per spec §6.1, the legacy `^credman:` fallback is **not** retained.
Pre-0.3.0 commits fall through to the default `Other` group in
generated changelogs — acceptable cosmetic regression.

- [ ] **Step 1: Apply the rename**

```bash
sed -i 's/credman/kepr/g; s/CREDMAN/KEPR/g; s/Credman/Kepr/g' cliff.toml
```

- [ ] **Step 2: Confirm the pattern**

```bash
grep -n '\^kepr:\|\^credman:\|group =' cliff.toml
```

Expected: the pattern is now `^kepr:` with `group = "kepr"`, and no
`^credman:` line remains.

- [ ] **Step 3: Confirm the file is clean**

```bash
! grep -iE '\b(credman|CREDMAN|Credman)\b' cliff.toml
```

- [ ] **Step 4: Commit**

```bash
git add cliff.toml
git commit -s -m "chore(cliff): flip commit-prefix to kepr"
```

---

### Task 16: Global completeness sweep

**Files:** every tracked file.

This is the single assertion from spec §5.2 that proves the rename is
complete.

- [ ] **Step 1: Run the completeness grep**

```bash
git grep -iE '\b(credman|CREDMAN|Credman)\b' -- . \
    ':!docs/node_modules' ':!target' ':!Cargo.lock' ':!.git' \
    ':!docs/superpowers/'
```

Expected: no output, exit code 1 (grep returns 1 when no matches).

The `docs/superpowers/` exclusion keeps the spec and plan files
(which intentionally reference the old name while narrating the
rename) out of the assertion.

If there is output, each remaining match is one of:
- A genuine oversight — apply the three-pass sed to that file and
  re-run.
- A URL or path that looks legitimately untouched (for example a link
  to the old GitHub URL before the repo rename) — flip it anyway;
  GitHub auto-redirects the old URL after `gh repo rename`.

- [ ] **Step 2: Recount, compare to baseline**

```bash
git grep -iE '\b(credman|CREDMAN|Credman)\b' -- . \
    ':!docs/node_modules' ':!target' ':!Cargo.lock' ':!.git' \
    ':!docs/superpowers/' | wc -l
```

Expected: `0`.

- [ ] **Step 3: If any fixes were applied, commit them**

```bash
# Only if Step 1 returned matches:
git add -A
git commit -s -m "refactor: mop up residual credman references"
```

Skip if no fixes were needed.

---

### Task 17: Bump version to 0.3.0

**Files:**
- Modify: `Cargo.toml`
- Regenerated: `Cargo.lock`

- [ ] **Step 1: Bump the version**

Edit `Cargo.toml`:

```toml
version = "0.3.0"
```

- [ ] **Step 2: Regenerate lockfile**

```bash
cargo build --release 2>&1 | tail -3
```

Expected: successful build; lockfile now lists `kepr 0.3.0`.

- [ ] **Step 3: Confirm both files**

```bash
grep -E '^version' Cargo.toml && grep -m1 '"kepr"' Cargo.lock
```

Expected: `version = "0.3.0"` and an adjacent `version = "0.3.0"` in
the `[[package]]` block for `kepr` in `Cargo.lock`.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -s -m "chore: bump version to 0.3.0"
```

---

## Phase G — Final verification and PR

### Task 18: Run the full verification gate

**Files:** read-only.

- [ ] **Step 1: Build + test + lint + shellcheck**

```bash
cargo build --release && \
cargo test && \
cargo clippy -- -D warnings && \
shellcheck install.sh tests/e2e.sh
```

Expected: every command exits 0.

- [ ] **Step 2: Verify the built binaries have the right names**

```bash
ls -la target/release/kepr target/release/kepr-daemon
```

Expected: both files exist and are executables.

- [ ] **Step 3: Re-run the completeness grep one last time**

```bash
git grep -iE '\b(credman|CREDMAN|Credman)\b' -- . \
    ':!docs/node_modules' ':!target' ':!Cargo.lock' ':!.git' \
    ':!docs/superpowers/'
```

Expected: no output.

- [ ] **Step 4: Review the branch log**

```bash
git log --oneline main..HEAD
```

Expected: roughly 11–13 commits on top of `main`, starting with
`bd2ad79 docs: add rename design — credman to kepr` and ending with
`chore: bump version to 0.3.0`. Each subject is ≤ 50 characters, each
commit is signed.

Verify signatures:

```bash
git log --show-signature main..HEAD 2>&1 | grep -c 'Good "git" signature'
```

Expected: the count matches the commit count from the `git log --oneline`
output in the previous sub-step.

- [ ] **Step 5: Push the branch**

```bash
git push -u origin feat/rename-credman-to-kepr
```

Expected: the `check-signed-push.sh` hook passes (every commit is
signed). If the hook blocks, resolve by signing the offending commit —
do not bypass with `--no-verify`.

---

### Task 19: Open the pull request

**Files:** none modified.

- [ ] **Step 1: Confirm no existing PR scopes this work**

```bash
gh pr list --search 'rename credman' --state all --limit 5
```

Expected: no existing PR matching. If one exists, rebase onto it
instead of opening a parallel one (see CLAUDE.md).

- [ ] **Step 2: Check for a PR template**

```bash
ls -la .github/PULL_REQUEST_TEMPLATE* 2>/dev/null || echo 'no template'
```

If a template exists, its body structure is authoritative; adapt the
content below to fit.

- [ ] **Step 3: Open the PR**

```bash
gh pr create \
  --title "Rename project: credman → kepr" \
  --body "$(cat <<'EOF'
## Summary

- Renames the project, both binaries, systemd unit, unix group, socket
  path, credential-file prefix, audit-log identifiers, and every
  reachable code/docs occurrence of `credman` to `kepr`.
- Target version: `0.3.0`. Clean break — no data migration; existing
  users re-enter credentials after upgrade.
- Design: [`docs/superpowers/specs/2026-04-21-rename-credman-to-kepr-design.md`](docs/superpowers/specs/2026-04-21-rename-credman-to-kepr-design.md).
- Plan: [`docs/superpowers/plans/2026-04-21-rename-credman-to-kepr.md`](docs/superpowers/plans/2026-04-21-rename-credman-to-kepr.md).

## Test plan

- [x] `cargo build --release` produces `target/release/kepr` and `target/release/kepr-daemon`
- [x] `cargo test` green
- [x] `cargo clippy -- -D warnings` clean
- [x] `shellcheck install.sh tests/e2e.sh` clean
- [x] Completeness grep returns zero matches (excluding `docs/superpowers/`, `docs/node_modules/`, `target/`, `Cargo.lock`, `.git/`)
- [x] `docs/` Fumadocs build succeeds
- [ ] Install-smoke test on a clean VM (operator, post-merge before tagging)

## Post-merge runbook

Per spec §4.3:

1. `gh repo rename credman kepr`
2. Update `origin` in `~/projects/credman-docs-test/`
3. `gh repo edit` for description and social preview
4. Tag and push `v0.3.0` (signed)
5. Publish release notes noting the clean-break migration

## Notes

- The old encryption-backend references, `/etc/credstore.encrypted/`
  shared directory, and POSIX/kernel symbols (SO_PEERCRED, etc.) are
  deliberately not renamed — they're external conventions, not project
  brand.
- Pre-0.3.0 commit prefixes (`credman:`) drop out of `git-cliff`
  changelog grouping and fall through to `Other`. Cosmetic.
- GitHub Pages URLs do not auto-redirect on repo rename. Docs
  deployment is currently commented out, so no external links break.
EOF
)"
```

Expected: `gh` returns the PR URL. Print it.

- [ ] **Step 4: Record the PR URL**

Copy the URL into the session notes so the review and merge can be
picked up in a later session.

---

## Appendix — Decision log (for reviewer reference)

These are captured in the spec but restated here so a subagent running
this plan without the spec open still has the rationale:

- **Clean-break data migration.** The pre-rename `credman-<uid>-<name>`
  files in `/etc/credstore.encrypted/` are deliberately abandoned. No
  `kepr migrate` subcommand, no dual-prefix list, no automatic import.
  Users re-enter credentials. Acceptable because the project was pre-1.0
  with no declared external adopters.
- **v0.3.0, not v1.0.0.** The 1.0 milestone is reserved for the Phase 0
  crypto rewrite (in-process AEAD, uid+name AAD binding, rollback
  counter), tracked separately.
- **Lowercase brand `kepr`.** Treated as shortened "keeper" in prose;
  no backronym. Capitalized only at sentence start.
- **Single atomic PR.** Staged rename PRs leave intermediate commits
  where the build is broken (binary named `kepr` but install.sh still
  says `credman`), so it must land as one unit.
- **`^credman:` legacy fallback dropped in cliff.toml.** Cosmetic
  regression for changelog grouping of pre-0.3.0 commits. Consistent
  with clean-break policy.
- **No crates.io publish in this PR.** The name `kepr` is free on
  crates.io (verified 2026-04-21) but will not be reserved here.
  Publish when an actual release ships.
