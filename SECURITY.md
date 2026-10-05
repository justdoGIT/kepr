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

If GitHub private reporting is unavailable, contact the repository
maintainers through the verified contact method listed in the repository
profile; do not disclose vulnerability details in a public issue.

## Repository controls

The following controls are asserted to be enabled on this repo. Their
availability depends on repository visibility and GitHub plan; audit via
Settings → Code security.

- **Secret scanning** and **Push protection**.
- **CodeQL** is configured in `.github/workflows/security.yml` but remains
  disabled while this repository is private without GitHub Advanced Security.
- **Dependabot alerts** and **Dependabot security updates** for `cargo`,
  `npm`, and `github-actions`.
- **`cargo audit`** on every push/PR and on a weekly cron.
- **`npm audit`** (`--audit-level=high`) against the committed
  `docs/package-lock.json`.
- **SBOM** (SPDX-JSON) generated on pushes to `main` and attached to
  releases by `anchore/sbom-action`.
- **Private vulnerability reporting** via GitHub Advisories.
- **Release artefact signing** via keyless `cosign sign-blob`
  (GitHub OIDC identity, Sigstore transparency log).
- **Build provenance attestations** via
  `actions/attest-build-provenance` when GitHub's attestation API is
  available; private repositories without that capability use cosign
  provenance instead.
- **SLSA provenance** (`kepr-<version>.intoto.jsonl`, SLSA Build L3) from
  `slsa-framework/slsa-github-generator`'s generic generator for the
  `.deb`, `.rpm` and tarball of every release.
- **Branch protection** on `main`: required CI + security checks,
  linear history.

## Verifying a release

Every release page lists these files next to the packages, and its notes
repeat the commands with the version filled in. `REPO` is the repository
that published the release (`OWNER/kepr`), `V` the version without the `v`.

SLSA provenance, checked with
[`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier):

```sh
slsa-verifier verify-artifact kepr-$V-x86_64-linux.tar.gz \
  --provenance-path kepr-$V.intoto.jsonl \
  --source-uri github.com/$REPO --source-tag v$V
```

The same provenance covers `kepr_${V}_amd64.deb` and
`kepr-$V-1.x86_64.rpm`. It proves the file was built by this repository's
`release.yml` from that tag.

Cosign keyless signature (every artefact, including the SBOM):

```sh
cosign verify-blob kepr-$V-x86_64-linux.tar.gz \
  --bundle kepr-$V-x86_64-linux.tar.gz.bundle \
  --certificate-identity-regexp "^https://github.com/$REPO/[.]github/workflows/release[.]yml@" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

GitHub build attestations, while the repository is public:
`gh attestation verify kepr-$V-x86_64-linux.tar.gz --repo $REPO`.

## Runtime security properties

Documented in `DOCS.md` §2 (Design patterns) and §3.4 (Hardening).
Highlights:

- The CLI is unprivileged; cryptographic operations happen in the daemon over
  a Unix socket. User mode runs entirely under the invoking user's account;
  system mode can use the root daemon.
- Peer identity is kernel-attested (`SO_PEERCRED`) and user-mode requests must
  match the daemon owner; request uids are never trusted.
- Credential values are kept in `ZeroString` buffers that wipe memory on drop;
  the daemon calls `mlockall` where permitted to keep decrypted bytes off swap.
- Credential values are never written to the audit log. Only `op`, `name`,
  `uid`, `user`, and `result` fields appear in the journal.
- Credential input should use `kepr set NAME --stdin`; `--value` is retained
  only for compatibility and exposes the value through process arguments.
- `kepr lock` wraps the random AES master key with Argon2id + AES-256-GCM,
  removes the unwrapped local key, and clears the daemon's in-memory key.
  Unlock failures are covered by the daemon's per-peer rate limiter.
- The systemd unit applies `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, `RestrictNamespaces`, `LockPersonality`, and
  related sandboxing flags.

## Out-of-scope

- Denial of service from a kepr-group member against the local
  daemon — by design, group membership is the trust boundary.
- Key extraction from a compromised host — the backend key is
  host-bound; a compromised host can decrypt its own credentials.
- Side-channel attacks against the encryption backend itself.
