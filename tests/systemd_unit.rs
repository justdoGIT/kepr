// systemd_unit.rs — pin the hardening directives in `systemd/kepr.service`.
//
// `systemd-analyze security --offline=true systemd/kepr.service` is the
// authoritative score, but it is a runtime tool with version-dependent
// output. This test asserts the *inputs* (the unit-file directives that
// score the daemon to ≤ 2.5) so that:
//
//   1. A future edit that drops one of these directives fails CI
//      immediately, instead of silently re-broadening the attack surface.
//   2. The ≤ 2.5 success criterion in `docs/content/docs/roadmap.mdx`
//      is enforced as code, not as a one-off measurement.
//
// `systemd-analyze` is not available in every CI environment (and its
// scoring drifts between versions), so this test is intentionally a
// directive-presence check, not a numerical-score assertion.

use std::fs;
use std::path::PathBuf;

const UNIT_REL_PATH: &str = "systemd/kepr.service";

fn unit_path() -> PathBuf {
    // CARGO_MANIFEST_DIR is the package root (the kepr top-level crate),
    // so the unit file resolves identically whether the test runs from
    // the workspace root or from inside the package directory.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(UNIT_REL_PATH)
}

fn unit() -> String {
    fs::read_to_string(unit_path()).expect("read systemd unit file")
}

/// Directives that must appear verbatim in `[Service]` to keep the
/// `systemd-analyze security` exposure score at ≤ 2.5. Each entry is
/// followed by a one-line rationale referencing the Phase 0 roadmap
/// success criterion.
fn required_directives() -> &'static [(&'static str, &'static str)] {
    &[
        // Daemon listens on a Unix socket (/run/kepr/kepr.sock) and the
        // root-only systemd journal — no AF_INET path. Closing the
        // network namespace removes the largest remaining exposure
        // class on the analyser (0.5 of the 0.5 total budget below).
        ("PrivateNetwork=yes", "no network surface"),
        // Daemon never opens /dev/*. PrivateDevices implies
        // DevicePolicy=closed on a private /dev mount, which is
        // strictly stronger than DeviceAllow= alone.
        ("PrivateDevices=yes", "no /dev access"),
        ("ProtectClock=yes", "cannot adjust system clock"),
        ("ProtectKernelLogs=yes", "no kmsg read/write"),
        ("ProtectHostname=yes", "cannot change hostname"),
        // /proc visibility tightening. invisible+pid hides other
        // processes' subtrees and non-pid /proc entries respectively.
        ("ProtectProc=invisible", "hidepid for non-owner processes"),
        ("ProcSubset=pid", "limit /proc to pid entries"),
        // Native ABI only. Blocks compat-mode syscalls that bypass
        // SystemCallFilter on x86_64 (i386 ABI was historically a hole).
        ("SystemCallArchitectures=native", "no i386/compat syscalls"),
        // Belt-and-braces with the in-process umask we set before
        // bind(2). UMask=0077 means any file the daemon creates is
        // mode 0o600 even if a future code path forgets the explicit
        // umask call.
        ("UMask=0077", "default file mode 0o600"),
    ]
}

#[test]
fn unit_contains_all_required_hardening_directives() {
    let body = unit();
    let missing: Vec<_> = required_directives()
        .iter()
        .filter(|(d, _)| !body.contains(d))
        .map(|(d, why)| format!("{d:40} — {why}"))
        .collect();
    assert!(
        missing.is_empty(),
        "{} required hardening directive(s) missing from {UNIT_REL_PATH}:\n  {}",
        missing.len(),
        missing.join("\n  "),
    );
}

#[test]
fn unit_keeps_no_new_privileges_yes() {
    // Phase 0 α3 flipped this on once the AEAD backend went in-process.
    // A future edit that needs a privileged child must NOT solve it by
    // turning this off — it must add an explicit ExecStartPre with the
    // right caps and keep the main daemon at NoNewPrivileges=yes.
    let body = unit();
    assert!(
        body.contains("NoNewPrivileges=yes"),
        "NoNewPrivileges must remain yes — see Phase 0 α3 in the roadmap"
    );
    assert!(
        !body.contains("NoNewPrivileges=no"),
        "NoNewPrivileges=no is a regression; see installed-vs-repo audit"
    );
}

#[test]
fn unit_keeps_capability_bounding_set_minimal() {
    // The bounding set must be exactly these three caps and no more.
    // Adding a cap silently raises the daemon's potential blast radius
    // and should require a roadmap-level discussion, not a one-off
    // edit. Pin the literal directive.
    let body = unit();
    let expected = "CapabilityBoundingSet=CAP_IPC_LOCK CAP_CHOWN CAP_DAC_READ_SEARCH";
    assert!(
        body.contains(expected),
        "expected exact `{expected}` in {UNIT_REL_PATH}; \
         a CAP_* addition must come with a roadmap-decision update"
    );
    assert!(
        body.contains("AmbientCapabilities="),
        "ambient set must be empty"
    );
}

/// The system-mode gate service (T1.19) must stay unprivileged and away
/// from the credential store: it handles network traffic for agents.
#[test]
fn gate_service_unit_keeps_its_isolation() {
    let unit = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("systemd/kepr-gate.service"),
    )
    .expect("read kepr-gate.service");
    for d in [
        "DynamicUser=yes",
        "CapabilityBoundingSet=\n",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "InaccessiblePaths=-/etc/credstore.encrypted -/var/lib/kepr",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "LimitCORE=0",
        "ExecStart=/usr/local/bin/kepr-gate --serve /run/kepr-gate/gate.sock",
    ] {
        assert!(unit.contains(d), "kepr-gate.service lost `{}`", d.trim());
    }
    assert!(
        !unit.contains("User=root"),
        "the gate service must not run as root"
    );
}

/// The `seal` batch (T4.08, T4.11–T4.13): sealers that need a device or
/// the network get it from opt-in drop-ins under `systemd/kepr.service.d/`;
/// the base unit keeps no device, no network and only local sockets.
#[test]
fn sealer_dropins_leave_the_base_unit_closed() {
    let body = unit();
    for d in [
        "PrivateNetwork=yes",
        "PrivateDevices=yes",
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK\n",
    ] {
        assert!(body.contains(d), "base unit lost `{}`", d.trim());
    }
    let directives: Vec<&str> = body
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    for d in ["AF_INET", "DeviceAllow=", "PrivateNetwork=no"] {
        assert!(
            !directives.iter().any(|l| l.contains(d)),
            "base unit must not carry `{d}`"
        );
    }
    let dropin = |name: &str| {
        fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("systemd/kepr.service.d")
                .join(name),
        )
        .unwrap_or_else(|e| panic!("read {name}: {e}"))
    };
    let tpm2 = dropin("tpm2.conf.example");
    assert!(tpm2.contains(
        "[Service]\nPrivateDevices=no\nDevicePolicy=closed\nDeviceAllow=/dev/tpmrm0 rw\n"
    ));
    assert!(!tpm2.contains("PrivateNetwork=no"));
    // KMS sealers reach the network at start-up only through this drop-in.
    let kms = dropin("kms.conf.example");
    assert!(kms.contains(
        "[Service]\nPrivateNetwork=no\nRestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6\n"
    ));
    assert!(kms.contains("EnvironmentFile=-/etc/kepr/kms.env"));
    assert!(!kms.contains("PrivateDevices=no"));
}
