---
name: pr-review-devmachine
description: PR review for Go/Rust/Bash/YAML dev-machine setup and maintenance repo
version: 1.0.0
---

# PR Review — Dev Machine & Maintenance Repo

## Output Format (STRICT, one line per finding)

FINDING|path|line|severity|description
Severity: P1 (blocks merge), P2 (should fix), P3 (nit)
If nothing found: output exactly "No issues found"
Descriptions under 120 chars. 80%+ confidence only.
`docs/review-criteria.md` is appended to this prompt; where it conflicts with this file, it wins.

---

## Rust Checks

- P1: `unwrap()` or `expect()` on external input, file I/O, network, env vars
- P1: `unsafe` block without safety comment explaining invariants
- P1: Missing `?` on Result in functions that return Result
- P2: `clone()` on large structs inside hot loops
- P2: `panic!` reachable from non-test code paths

## Go Checks

- P1: `err` returned but not checked (`_ = someFunc()` pattern)
- P1: goroutine spawned without WaitGroup or context cancellation path
- P1: unchecked type assertion (`x.(Type)` not `x.(Type), ok` form)
- P2: `defer` inside a loop (runs at function exit, not loop iteration)
- P2: mutex Lock without deferred Unlock

## Bash Checks

- P1: Executable bash script under `scripts/` missing `set -euo pipefail` (NOT runit `run` files, sourced libs with `# shellcheck shell=bash`, or workflow steps in a job with `defaults.run.shell: bash`)
- P1: Variable used in path with `rm`, `chmod`, `chown` without quoting: `rm -rf $VAR`
- P1: `curl | bash` or `wget | sh` without checksum verification
- P1: Hardcoded credentials, tokens, or passwords
- P2: `[ $VAR = "val" ]` instead of `[[ "$VAR" = "val" ]]`
- P2: Command substitution not quoted: `VAR=$(cmd)` used unquoted later
- P1: `|| true` or `# shellcheck disable` used to hide an error (both are forbidden in this repo)

## YAML / Config Checks

- P1: Secret, token, or password value (not reference) in plain YAML
- P1: `chmod 777` or world-writable path in config
- P1: `sudo` without specific command — bare `sudo bash` or `sudo su`
- P2: Cron expression `* * * * *` (every minute) on maintenance job
- P2: Cron job that writes its log outside `~/.local/state/` or `/var/log`
- P3: Inconsistent indentation style within same file

## Dev Machine Setup Specific

- P1: Destructive operation (`rm -rf`, `mkfs`, `dd`) without existence check guard
- P1: Non-idempotent operation — running twice breaks the system
- P1: Service started outside runit (`systemctl`, `service`): the nodes run runit under `/etc/sv`
- P2: `git clone` into existing dir without checking if already cloned
- P3: Missing dry-run or `--check` mode for maintenance scripts

## Maintenance / Automation Specific

- P1: No rollback path on state-mutating operation
- P1: Silent failure — error captured but not logged or surfaced
- P2: No timeout on network operation (curl, wget, git fetch)
- P2: Log file written to unbounded path (no rotation, no size cap)
- P3: Missing idempotency guard on cron job

## Skip Entirely

- Style, formatting, naming conventions
- Comment grammar
- Line length
- Import ordering
