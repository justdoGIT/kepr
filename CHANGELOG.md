# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [unreleased]
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
