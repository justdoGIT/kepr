# Contributing to kepr

Thank you for taking the time to contribute! Every bug report, feature idea,
and pull request makes kepr better. This document explains how to get
involved and what we expect from contributors.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Submitting Changes](#submitting-changes)
- [Commit Message Standard](#commit-message-standard)
- [Coding Style](#coding-style)
- [Pull Request Process](#pull-request-process)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

By participating in this project you agree to be respectful and constructive
in all interactions. Harassment, personal attacks, and discriminatory language
will not be tolerated. Maintainers reserve the right to remove comments or
ban contributors who violate this standard.

---

## How Can I Contribute?

**Reporting bugs** — Open a Bug Report issue using the template provided.
Search existing issues first to avoid duplicates.

**Suggesting features** — Open a Feature Request issue. Describe the problem
you are trying to solve, not just the solution you have in mind.

**Writing code** — Pick an open issue labelled `good first issue` or
`help wanted`, comment to claim it, then open a pull request.

**Improving documentation** — Typos, unclear explanations, and missing
examples are all valid contributions. No issue required for small doc fixes.

**Testing** — Run the test suite on your platform and report failures.
Platform-specific bugs (Windows, macOS, unusual Linux distros) are especially
valuable to catch early.

---

## Development Setup

Requirements: Rust stable toolchain (1.75+), Cargo.

```bash
# Clone the repository
git clone https://github.com/your-org/kepr.git
cd kepr

# Build
cargo build

# Run tests
cargo test

# Run with local changes
cargo run -- --help
```

For shell completions during development:

```bash
cargo run -- completions bash > /tmp/kepr.bash
source /tmp/kepr.bash
```

---

## Submitting Changes

1. Fork the repository and create a feature branch from `main`.

   ```bash
   git checkout -b feat/short-description
   ```

2. Make your changes. Write or update tests where relevant.

3. Run the full test suite and ensure it passes.

   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt --check
   ```

4. Commit your changes following the [commit message standard](#commit-message-standard) below.

5. Push your branch and open a pull request against `main`.

---

## Commit Message Standard

We follow the **50/72 rule** strictly:

- **Subject line**: 50 characters maximum. Use imperative mood ("Add", "Fix",
  "Remove" — not "Added", "Fixed", "Removed"). No period at the end.
- **Blank line** between subject and body.
- **Body**: Wrap at 72 characters. Explain *what* changed and *why*, not *how*.
  The diff shows how.

Always sign off your commits:

```bash
git commit -s -m "Fix credential lookup on empty keychain"
```

The `-s` flag adds a `Signed-off-by` trailer, indicating you certify your
contribution under the project licence.

**Good examples:**

```
Add timeout option for remote credential fetch

Without a timeout, the CLI hangs indefinitely when the remote
endpoint is unreachable. This adds a --timeout flag (default 30s)
and propagates it through the HTTP client.

Signed-off-by: Your Name <you@example.com>
```

```
Remove deprecated --legacy-auth flag

The flag was deprecated in v0.4.0 and has been a no-op since v0.6.0.
Removing it cleans up the help output and simplifies the CLI surface.

Signed-off-by: Your Name <you@example.com>
```

**What to avoid:**

- `fix stuff` — too vague
- `WIP` — do not push work-in-progress to a PR branch
- `Addressed review comments` — squash or amend instead
- Any mention of AI tools in commit messages unless the commit is
  specifically about tooling configuration

---

## Coding Style

- Run `cargo fmt` before every commit. CI will reject unformatted code.
- Run `cargo clippy -- -D warnings`. All warnings are treated as errors.
- Prefer explicit error handling over `.unwrap()` in non-test code.
- Write doc comments (`///`) for all public functions and types.
- Keep functions short and focused. If a function needs a comment explaining
  what it does, consider splitting it.

---

## Pull Request Process

- One logical change per pull request. Split unrelated changes into separate PRs.
- Reference the issue your PR addresses: `Closes #42` in the PR description.
- PRs require at least one maintainer approval before merging.
- CI must pass (build, test, clippy, fmt) before a PR can be merged.
- Maintainers aim to respond within 7 days. If your PR has had no activity
  after two weeks, a polite ping in the thread is welcome.
- Once approved, maintainers will merge. Do not merge your own PR.

---

## Security Vulnerabilities

**Do not open a public issue for security bugs.**

Email the maintainers directly at the address listed in `Cargo.toml`. Include
a description of the vulnerability, reproduction steps, and your assessment
of impact. You will receive a response within 72 hours.

We follow responsible disclosure: we will work with you to understand and fix
the issue before any public announcement.
