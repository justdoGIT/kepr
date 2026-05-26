---
name: pr-review-kepr
description: PR review for kepr — Rust credential manager with Bash/YAML/TSX
version: 1.0.0
---

# PR Review — kepr

## Output Format (STRICT, one line per finding)

FINDING|path|line|severity|description
Severity: P1 (blocks merge), P2 (should fix), P3 (nit)
If nothing found: output exactly "No issues found"
Descriptions under 120 chars. 80%+ confidence only.

---

## Rust Checks

- P1: `unwrap()` or `expect()` on external input, file I/O, network, env vars
- P1: `unsafe` block without safety comment explaining invariants
- P1: Missing `?` on Result in functions that return Result
- P1: Secret value logged or printed (check audit.rs, crypto.rs error paths)
- P1: `validate_name` not called on user-supplied cred name in daemon handler
- P2: `clone()` on large structs inside hot loops
- P2: `panic!` reachable from non-test code paths
- P2: `ZeroString` converted to plain `String` outside socket boundary
- P2: Missing `mlock` guard on new secret buffer

## Bash Checks

- P1: Script missing `set -euo pipefail` at top
- P1: Variable used in path with `rm`, `chmod`, `chown` without quoting
- P1: Hardcoded credentials, tokens, or passwords
- P2: `[ $VAR = "val" ]` instead of `[[ "$VAR" = "val" ]]`

## YAML / Config Checks

- P1: Secret, token, or password value (not reference) in plain YAML
- P1: `chmod 777` or world-writable path in config
- P1: systemd unit hardening regression (missing ProtectSystem, NoNewPrivileges, etc.)
- P2: Missing `concurrency` group on workflow (prevents cancel-in-progress)

## Documentation / TypeScript (docs/)

- P1: Broken internal link (`[text](./nonexistent-file.md)`)
- P2: Mermaid diagram syntax error
- P2: Import of removed or renamed component

## Skip Entirely

- Style, formatting, naming conventions
- Comment grammar
- Line length
- Import ordering
- dependabot PRs (version bumps only — review the diff, not the bump)
