# Security policy

## Supported versions

Only the latest released tag on `main` receives security fixes.
Pre-release tags (`-rc.*`) are not supported once the matching
`v<major>.<minor>.<patch>` tag ships.

| Version        | Supported          |
| -------------- | ------------------ |
| latest `main`  | :white_check_mark: |
| older tags     | :x:                |

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting
channel:

> Repository → Security → **Report a vulnerability**

Include a minimal reproduction, the affected commit SHA, and whatever
contact preference you'd like follow-up on. We aim to:

- Acknowledge within **3 business days.**
- Ship a fix or a mitigation within **90 days** of acknowledgement.
- Credit reporters in the release notes (opt-out available).

If GitHub Advisories is unreachable for any reason, email the
maintainer listed in `Cargo.toml`'s `authors` field.

## Repository controls

The following controls are asserted to be enabled on this repo.
Audit via Settings → Code security.

- **Secret scanning** and **Push protection**.
- **CodeQL** (Rust + JavaScript/TypeScript) via
  `.github/workflows/security.yml`.
- **Dependabot alerts** and **Dependabot security updates** for
  `cargo`, `npm`, and `github-actions`.
- **`cargo audit`** on every push/PR and on a weekly cron.
- **`npm audit`** (`--audit-level=high`) against the committed
  `docs/package-lock.json`.
- **SBOM** (SPDX-JSON) generated per push to `main` and attached
  to every release via `anchore/sbom-action`.
- **Private vulnerability reporting** via GitHub Advisories.
- **Release artefact signing** via keyless `cosign sign-blob`
  (GitHub OIDC identity, Sigstore transparency log).
- **Build provenance attestations** via
  `actions/attest-build-provenance` on every release artefact.
- **Branch protection** on `main`: required CI + security checks,
  linear history.

## Runtime security properties

Documented in `DOCS.md` §2 (Design patterns) and §3.4 (Hardening).
Highlights:

- The CLI is unprivileged; all cryptographic operations happen in
  the root daemon over a Unix socket.
- Peer identity is kernel-attested (`SO_PEERCRED`) — request uids
  are never trusted.
- Credential values are kept in `ZeroString` buffers that wipe
  memory on drop; the daemon calls `mlockall` to keep decrypted
  bytes off swap.
- Credential values are never written to the audit log. Only
  `op`, `name`, `uid`, `user`, and `result` fields appear in the
  journal.
- The systemd unit applies `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, `RestrictNamespaces`, `LockPersonality`,
  and related sandboxing flags.

## Out-of-scope

- Denial of service from a kepr-group member against the local
  daemon — by design, group membership is the trust boundary.
- Key extraction from a compromised host — the backend key is
  host-bound; a compromised host can decrypt its own credentials.
- Side-channel attacks against the encryption backend itself.
