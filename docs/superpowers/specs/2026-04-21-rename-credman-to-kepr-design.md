---
title: Rename credman to kepr
status: Draft
date: 2026-04-21
author: Kamal Pandey
target_version: 0.3.0
landing_branch: feat/rename-credman-to-kepr
supersedes: none
---

# Rename: credman → kepr

## 1. Goal, scope, non-goals

### 1.1 Goal

Rename the project, both binaries, the systemd unit, the system group,
the Unix-socket path, the credential-file prefix, the audit-log
identifiers, and every reachable code or documentation occurrence of
`credman` to `kepr`. Ship as a single atomic pull request on the
branch `feat/rename-credman-to-kepr`, land to `main`, then rename
the GitHub repository.

The rename exists because `credman` collides with several unrelated
projects on GitHub, which dilutes discoverability. `kepr` is free on
both GitHub and crates.io (both returned `404` on 2026-04-21).

### 1.2 Scope

Inside this PR:

- Rust sources under `src/` (13 files) plus `Cargo.toml`; `Cargo.lock`
  regenerates automatically.
- Build, install, and packaging: `install.sh`, `packaging/debian/postinst`,
  `packaging/debian/prerm`, `completions/credman.bash` (filename and body),
  `cliff.toml`.
- Systemd: rename `systemd/credman.service` to `systemd/kepr.service`
  and update the unit body (`RuntimeDirectory`, `ExecStart`, `ReadWritePaths`,
  `SyslogIdentifier`, `Description`, `Documentation`).
- Tests: `tests/e2e.sh` (63 occurrences).
- GitHub machinery: `.github/CODEOWNERS`, `.github/dependabot.yml`,
  `.github/codeql/codeql-config.yml`, every file under
  `.github/ISSUE_TEMPLATE/`, every file under `.github/workflows/`
  (`ci.yml`, `docs-deploy.yml`, `release.yml`, `security.yml`).
- Root docs: `README.md`, `DOCS.md`, `SECURITY.md`, `CONTRIBUTING.md`,
  `CLAUDE.md`.
- Fumadocs site under `docs/` (17 files including `next.config.mjs`,
  `app/manifest.ts`, `app/layout.tsx`, `app/(home)/page.tsx`,
  `app/docs/layout.tsx`, `components/test-matrix.tsx`,
  `content/docs/index.mdx`, `content/docs/quickstart.mdx`,
  `content/docs/architecture/*.mdx`, `content/docs/reference/*.mdx`,
  `package.json`, `package-lock.json`, `README.md`,
  `scripts/gen-rust-api.mjs`).

Outside this PR (post-merge runbook, §4.3):

- `gh repo rename credman kepr`.
- Update `origin` remote in the sibling clone
  `~/projects/credman-docs-test/`.
- GitHub repository description and social-preview image.
- Push the `v0.3.0` tag.

### 1.3 Non-goals

- **No data migration.** Existing users with credentials stored as
  `/etc/credstore.encrypted/credman-<uid>-<name>` are expected to
  uninstall credman, install kepr, and re-enter their credentials.
  Release notes make this explicit. This is acceptable because the
  project is still at `v0.2.0` with no declared external adopters.
- **No Phase 0 security rewrite.** In-process AEAD, uid+name AAD
  binding, rollback-counter protection, and end-to-end zeroization
  all stay on the separate roadmap.
- **No new features.** No `kepr exec`, no docker credential helper,
  no rotation, no TTL, no FIDO2 unlock.
- **No crates.io publish.** The name `kepr` is free but will not be
  reserved in this PR; publish when an actual release ships.
- **No behaviour change.** CLI surface, flag names, output format,
  wire protocol, and on-disk layout (apart from filename prefix) are
  unchanged.

## 2. Rename map

### 2.1 Identifier and string renames

| What | Current | New | Location |
|---|---|---|---|
| Cargo package | `credman` | `kepr` | `Cargo.toml` |
| Cargo `[[bin]]` 1 | `credman` | `kepr` | `Cargo.toml` |
| Cargo `[[bin]]` 2 | `credman-daemon` | `kepr-daemon` | `Cargo.toml` |
| Credential-name prefix | `CRED_PREFIX = "credman"` | `"kepr"` | `src/store.rs:15` |
| Socket path | `/run/credman/credman.sock` | `/run/kepr/kepr.sock` | `src/protocol.rs:16` |
| Socket directory | `/run/credman` | `/run/kepr` | `src/protocol.rs:18` |
| Unix group name | `credman` | `kepr` | `src/daemon_socket.rs:29` |
| Syslog identifier | `credman-daemon` | `kepr-daemon` | `src/audit.rs:112`, `systemd/*.service` |
| Audit field | `CREDMAN_OP` | `KEPR_OP` | `src/audit.rs:128` |
| Audit field | `CREDMAN_NAME` | `KEPR_NAME` | `src/audit.rs:129` |
| Audit field | `CREDMAN_UID` | `KEPR_UID` | `src/audit.rs:130` |
| Audit field | `CREDMAN_USER` | `KEPR_USER` | `src/audit.rs:131` |
| Audit field | `CREDMAN_RESULT` | `KEPR_RESULT` | `src/audit.rs:132` |
| Audit `MESSAGE` format | `credman: op=…` | `kepr: op=…` | `src/audit.rs:123` |
| stderr log-format | `[credman] op=…` | `[kepr] op=…` | `src/audit.rs:72` |
| git-cliff commit-prefix | `^credman:` → group `credman` | `^kepr:` → group `kepr` | `cliff.toml:43` |
| Dependabot commit prefix | `"credman"` | `"kepr"` | `.github/dependabot.yml:12` |

Docs-site basePath in `docs/next.config.mjs:26` derives automatically
from the `repoName` env var sourced from `GITHUB_REPOSITORY`. It needs
no code change; the next docs-deploy workflow run after the repo
rename publishes to `/kepr`.

### 2.2 Filename renames (git `mv`)

| Old | New |
|---|---|
| `systemd/credman.service` | `systemd/kepr.service` |
| `completions/credman.bash` | `completions/kepr.bash` |

### 2.3 Runtime paths (produced by `install.sh`, not in-repo)

| Install target | Current | New |
|---|---|---|
| CLI binary | `/usr/local/bin/credman` | `/usr/local/bin/kepr` |
| Daemon binary | `/usr/local/sbin/credman-daemon` | `/usr/local/sbin/kepr-daemon` |
| Systemd unit | `/etc/systemd/system/credman.service` | `/etc/systemd/system/kepr.service` |
| Runtime directory | `/run/credman` | `/run/kepr` |
| Unix socket | `/run/credman/credman.sock` | `/run/kepr/kepr.sock` |
| System group | `credman` | `kepr` |
| Credential file prefix | `/etc/credstore.encrypted/credman-<uid>-<name>` | `/etc/credstore.encrypted/kepr-<uid>-<name>` |

## 3. Do-not-rename list

These look like targets but must not be renamed:

- `/etc/credstore.encrypted/` — a systemd-creds convention, not a
  project-specific path. The directory is shared with whatever else
  uses systemd-creds on the host.
- `systemd-creds`, `CREDENTIALS_DIRECTORY`, `--with-key=host`, and any
  other external systemd concept. `CLAUDE.md` further directs that
  the encryption backend be referred to generically; the rename must
  not regress that hiding.
- `SO_PEERCRED`, `SCM_CREDENTIALS` and other kernel or POSIX symbols.
- Historical git commit messages. Rewriting git history is not in
  scope; existing `credman:` prefixes on merged commits stay as they
  are in the log.
- Branch names of already-merged pull requests.
- Files under `docs/node_modules/` and compiled output under
  `target/`. These aren't tracked, but the final grep assertion (§5.2)
  will exclude them to avoid false positives.

## 4. Execution

### 4.1 Branching and commit hygiene

- All work lands on `feat/rename-credman-to-kepr` (already created).
- Single pull request against `main`.
- Every commit is cryptographically signed via `git commit -s`, which
  also adds the `Signed-off-by` trailer. Global git config enables SSH
  signing with `~/.ssh/id_rsa.pub`, and the hook at
  `~/.claude/hooks/check-signed-push.sh` blocks pushes containing
  unsigned commits.
- Commit subjects obey the 50/72 rule. Subjects are generic (no
  session-specific or tooling references).
- Direct commits to `main` are blocked by a settings.json hook; this
  PR is the only way in.

### 4.2 Order of operations inside the PR

1. **Rust sources and cargo metadata.** Update `Cargo.toml` package
   name and both `[[bin]]` names; update every `src/*.rs` string
   constant (`CRED_PREFIX`, `SOCKET_PATH`, `SOCKET_DIR`, audit
   field names, message formats, `group_gid("credman")` lookups),
   plus inline doc-comments referencing the old name. Let
   `cargo build` regenerate `Cargo.lock`.
2. **Systemd unit.** `git mv systemd/credman.service systemd/kepr.service`;
   update `Description`, `Documentation`, `RuntimeDirectory`,
   `ExecStart`, `ReadWritePaths`, `SyslogIdentifier` in the unit body.
3. **Bash completion.** `git mv completions/credman.bash
   completions/kepr.bash`; update the `complete -F _kepr kepr` line
   and any internal function names.
4. **Install and packaging.** Update `install.sh` (37 occurrences),
   `packaging/debian/postinst`, `packaging/debian/prerm`.
5. **Tests.** Update `tests/e2e.sh` (63 occurrences). The `E2E_`
   prefix used for test credentials stays as `E2E_`; only the
   surrounding prose and any explicit `credman` command invocations
   flip to `kepr`.
6. **GitHub machinery.** Update `.github/CODEOWNERS`,
   `.github/dependabot.yml`, `.github/codeql/codeql-config.yml`,
   every `.github/ISSUE_TEMPLATE/*`, every `.github/workflows/*.yml`.
   Any workflow step that references `target/release/credman` or
   `target/release/credman-daemon` must flip to the new binary
   names.
7. **Top-level docs.** `README.md`, `DOCS.md`, `SECURITY.md`,
   `CONTRIBUTING.md`, `CLAUDE.md`.
8. **Fumadocs site.** Every file under `docs/` listed in §1.2.
9. **Changelog.** `cliff.toml` prefix pattern flips to `^kepr:`;
   release-notes for `v0.3.0` record the rename explicitly as the
   only content change.
10. **Final rename-completeness sweep.** Run the grep assertion in
    §5.2; fix any remaining matches.
11. **Build and test gates.** `cargo build --release`,
    `cargo test`, `cargo clippy -- -D warnings`,
    `shellcheck install.sh tests/e2e.sh`. All must pass.
12. **Bump `Cargo.toml` version to `0.3.0`** (last change before
    commit, so the version-bump commit is isolated).

### 4.3 Post-merge runbook

Not part of the PR; operator action after CI is green and the PR is
merged.

1. `gh repo rename credman kepr`. GitHub auto-redirects the old URL,
   preserves stars, watchers, issues, and pull requests, and updates
   the default `origin` fetched by new clones.
2. In the sibling working tree `~/projects/credman-docs-test/`:
   `git remote set-url origin git@github.com:justdoGIT/kepr.git` then
   `git fetch`. The local directory name is cosmetic and can stay or
   be renamed at the operator's convenience.
3. Update GitHub repository description and social preview via
   `gh repo edit` or the web UI.
4. Docs site: the next `docs-deploy.yml` run auto-publishes to
   `/kepr`. GitHub Pages does **not** redirect the old URL. The repo
   is currently private and the docs deployment is commented out, so
   no external links break today. If docs go public later, a
   redirect page at the old location must be set up before
   publishing.
5. `git tag -s v0.3.0 -m "v0.3.0 — rename credman to kepr"` and
   `git push origin v0.3.0`.
6. Publish release notes pointing at this design doc and the
   uninstall/reinstall flow for existing users.

## 5. Verification

### 5.1 Build and test gates

- `cargo build --release` succeeds and produces
  `target/release/kepr` plus `target/release/kepr-daemon`; no
  warnings.
- `cargo test` is green. The existing prefix tests in
  `src/store.rs:138-176` (`to_cred_name`, `from_cred_name`) are
  updated to assert `kepr-<uid>-<name>` instead of
  `credman-<uid>-<name>`.
- `cargo clippy -- -D warnings` is clean.
- `shellcheck install.sh tests/e2e.sh` is clean.

### 5.2 Rename-completeness assertion

The following must return zero matches, pre-tag:

```
git grep -iE '\b(credman|CREDMAN|Credman)\b' -- . \
    ':!docs/node_modules' ':!target' ':!Cargo.lock'
```

If any file intentionally retains the old name (for example, a
CHANGELOG entry describing the rename), it is listed in the PR
description and excluded explicitly in this assertion.

### 5.3 Install smoke test

Manual, run by the operator on a clean Debian test VM:

1. `./install.sh` succeeds. A `kepr` system group is created; the
   binaries install at `/usr/local/bin/kepr` and
   `/usr/local/sbin/kepr-daemon`; the systemd unit is enabled and
   active.
2. `sudo usermod -aG kepr "$USER" && newgrp kepr`.
3. `kepr set FOO` prompts for a value; `kepr get FOO` round-trips
   the same value.
4. `journalctl -t kepr-daemon -f` shows `KEPR_OP=set`, `KEPR_NAME=FOO`,
   `KEPR_UID=…`, `KEPR_USER=…`, `KEPR_RESULT=ok`.
5. `sudo ls /etc/credstore.encrypted/` shows a file named
   `kepr-<uid>-foo`.
6. `./tests/e2e.sh` is green against the installed service.

### 5.4 Post-merge sanity

- Fresh clone from the renamed URL builds green.
- `git clone git@github.com:justdoGIT/credman.git` still works via
  GitHub's automatic redirect (verifies the rename did not break
  existing external bookmarks).

## 6. Risk and rollback

### 6.1 Risks

- **Pre-rename installs become inoperable after upgrade.** Users who
  had credentials stored as `credman-<uid>-<name>` see an empty
  `kepr list` because `list_for_uid` filters by the new `kepr-`
  prefix. Mitigation: release notes make the re-entry flow explicit;
  no silent failure, just an empty list. Acceptable per the clean-break
  migration policy.
- **GitHub Pages URL breaks.** GitHub redirects repository URLs on
  rename but does not redirect Pages URLs. The repo is currently
  private and docs deployment is commented out, so there are no live
  external links today. If docs are published publicly in future,
  this must be handled at that time.
- **`git-cliff` loses grouping for pre-rename commits.** The existing
  `^credman:` prefix pattern is replaced outright (not retained as a
  legacy fallback) to keep the clean-break policy consistent.
  Pre-0.3.0 commits fall through to the default `Other` group in
  generated changelogs. Cosmetic; acceptable.
- **Unsigned commits.** Blocked by the `check-signed-push.sh` hook.
  No ad-hoc bypass allowed.

### 6.2 Rollback

- **Before `gh repo rename`.** `git revert` the merged PR. Because
  it merges as a single atomic commit (squash or merge commit), one
  revert restores the tree. CI regains green.
- **After `gh repo rename`.** Revert the PR and then
  `gh repo rename kepr credman`. GitHub permits unlimited renames,
  and stars, issues, and pull requests survive. Past the tag, yank
  `v0.3.0` by deleting the tag from the remote.

## Appendix A: Pre-rename snapshot

- Occurrences (as of 2026-04-21, commit `0b00b9a`):
  - `credman` (lowercase): 462
  - `CREDMAN` (uppercase): 45
  - `Credman` (mixed): 2
  - Total: 509 across 49 files.
- Highest-density files:

  | File | Count |
  |---|---|
  | `tests/e2e.sh` | 63 |
  | `README.md` | 57 |
  | `DOCS.md` | 56 |
  | `install.sh` | 37 |
  | `docs/content/docs/quickstart.mdx` | 28 |
  | `docs/content/docs/architecture/sequence-diagrams.mdx` | 22 |
  | `Cargo.toml` | 22 |
  | `docs/content/docs/architecture/overview.mdx` | 17 |
  | `src/cli_args.rs` | 16 |
  | `src/audit.rs` | 14 |
  | `src/store.rs` | 13 |

## Appendix B: Post-merge runbook checklist

- [ ] PR merged to `main`; CI green
- [ ] `gh repo rename credman kepr`
- [ ] `git remote set-url origin git@github.com:justdoGIT/kepr.git` in
  `~/projects/credman-docs-test/`
- [ ] Repo description updated via `gh repo edit`
- [ ] Social-preview image updated
- [ ] `v0.3.0` tag signed and pushed
- [ ] Release notes published
- [ ] External bookmarks and sibling repos updated
