# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [unreleased]
- Reject cross-credential HTTPS placeholders using immutable destination/slot
  indexes; retain valid aliases for the same credential.
- Bound Git credential names in a separate digest namespace and verify stored
  host/protocol before erasing. Add explicit, identity-checked legacy migration.
- Fail closed when OMP safety checks are missing, malformed, or unavailable;
  reject oversized hook input rather than silently dropping conversation text.
- Bound OMP redaction cache bytes and queued work without retaining sensitive
  input as cache keys; handle child pipe failures without global error suppression.
- Preserve JSON tool-argument structure during PEM redaction and borrow unchanged
  request bodies; map escaped-text matches without per-byte offset allocations.
- Port review-worktree fixes for tracked release Cargo configuration, staged API
  publication, and bounded retry of transient unlock-dialog executable contention.
- Route Cloudflare AI Gateway requests through the gate and protect omp
  harness sessions from broken-pipe (EPIPE) stream terminations.
- Use `/run/user/<uid>/kepr` as the Linux user-socket default instead of a
  home-state runtime; explicit `kepr-daemon --user` overrides inherited
  system mode and keeps password-protected stores locked until unlock.
- Restore daemon policy loading, profile isolation, sealed-key startup,
  idle/sleep locking, per-peer rate limits, absolute request deadlines,
  private file creation, and sealed-descriptor delivery. Reuse existing
  implementations instead of duplicating startup code or suppressing warnings.
- Document boot-time runit/elogind setup and PAM password-token ordering;
  isolate CLI test runtimes, saved checkout tokens, and Git signing/hooks
  from the user's environment.
- Restore `kepr set --profile NAME` implicit generation and the Debian
  removal script's executable permissions.
- Add rsync-backed device sync and an opt-in hourly systemd user timer.

- Recover audit logs that end in crash-written NUL padding, with regression
  coverage for the daemon restart path.
- Support plain `help` and per-command help in both Kepr command binaries;
  complete all CLI verbs and help forms in Bash.
- Accept option names with or without `--`; add bare-option completion and
  optional child-command separators for `exec` and `protect-agent`.

Populated automatically by `git-cliff` on each tagged release via
`.github/workflows/release.yml`.

<!-- git-cliff appends new release sections above this line on tag. -->
