// cli_policy/compliance.rs — `kepr report compliance --framework
// sox|hipaa|pci|nist|gdpr`: one row per control with what kepr can show
// for it today (pass / fail / manual). The evidence comes from replies the
// daemon already gives (status, audit-chain check, policy status, health),
// so no value and no new request is involved. It is evidence for an
// assessor, not a certification; every row says which kepr feature backs it.

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_policy::{AccessRow, PolicyRequest, PolicyResponse};

use crate::cli_mode;

pub const FRAMEWORKS: &[&str] = &["sox", "hipaa", "pci", "nist", "gdpr"];

/// What the daemon reported; `None` = the check could not be run.
#[derive(Debug, Default, Clone)]
pub struct Evidence {
    pub passphrase: Option<bool>,
    pub fips: Option<bool>,
    pub audit_entries: Option<usize>,
    pub policy_active: Option<bool>,
    pub policy_error: bool,
    /// (security score, credentials with weak / breached / reused findings)
    pub health: Option<(u32, usize)>,
}

#[derive(Clone, Copy)]
enum Check {
    /// Values are AES-256-GCM encrypted at rest: always true.
    EncryptedAtRest,
    Passphrase,
    Fips,
    AuditChain,
    Policy,
    Health,
    /// Outside kepr: an organisational control.
    Manual(&'static str),
}

type Control = (&'static str, &'static str, Check);

fn controls(framework: &str) -> Option<&'static [Control]> {
    use Check::*;
    Some(match framework {
        "sox" => &[
            ("ITGC-AC", "Logical access to secrets is restricted", Policy),
            (
                "ITGC-AU",
                "Access and changes leave a tamper-evident trail",
                AuditChain,
            ),
            (
                "ITGC-KEY",
                "Credentials are kept hygienic and rotated",
                Health,
            ),
            (
                "ITGC-SOD",
                "Segregation of duties",
                Manual("assign roles outside kepr"),
            ),
        ],
        "hipaa" => &[
            (
                "164.312(a)(2)(iv)",
                "Encryption of stored data",
                EncryptedAtRest,
            ),
            ("164.312(b)", "Audit controls", AuditChain),
            ("164.312(c)(1)", "Integrity of records", AuditChain),
            ("164.312(d)", "Person or entity authentication", Passphrase),
            (
                "164.308(a)(1)(ii)(B)",
                "Risk management of weak credentials",
                Health,
            ),
        ],
        "pci" => &[
            (
                "3.5",
                "Stored secrets are rendered unreadable",
                EncryptedAtRest,
            ),
            ("3.6", "Cryptographic keys are protected", Passphrase),
            ("3.7", "Validated cryptography for key management", Fips),
            ("8.3", "Strong authentication secrets", Health),
            ("10.2", "Audit logs record access to secrets", AuditChain),
            ("7.2", "Access is limited by need to know", Policy),
        ],
        "nist" => &[
            ("AC-3", "Access enforcement", Policy),
            ("AU-9", "Protection of audit information", AuditChain),
            ("IA-5", "Authenticator management", Health),
            (
                "SC-12",
                "Cryptographic key establishment and management",
                Passphrase,
            ),
            ("SC-13", "Cryptographic protection (FIPS-validated)", Fips),
            (
                "SC-28",
                "Protection of information at rest",
                EncryptedAtRest,
            ),
        ],
        "gdpr" => &[
            (
                "Art. 32(1)(a)",
                "Encryption of personal data",
                EncryptedAtRest,
            ),
            (
                "Art. 32(1)(b)",
                "Ongoing confidentiality and integrity",
                AuditChain,
            ),
            ("Art. 32(1)(d)", "Regular testing of measures", Health),
            (
                "Art. 30",
                "Records of processing",
                Manual("keep the register outside kepr"),
            ),
        ],
        _ => return None,
    })
}

fn judge(check: Check, e: &Evidence) -> (&'static str, String) {
    let unknown = || ("manual", "could not be checked".to_string());
    match check {
        Check::EncryptedAtRest => ("pass", "AES-256-GCM per credential".into()),
        Check::Passphrase => match e.passphrase {
            Some(true) => (
                "pass",
                "master key wrapped by a passphrase (Argon2id)".into(),
            ),
            Some(false) => (
                "fail",
                "master key not passphrase-protected (kepr lock)".into(),
            ),
            None => unknown(),
        },
        Check::Fips => match e.fips {
            Some(true) => ("pass", "FIPS 140-3 validated module in use".into()),
            Some(false) => ("fail", "not the FIPS build (see kepr status)".into()),
            None => unknown(),
        },
        Check::AuditChain => match e.audit_entries {
            Some(n) => (
                "pass",
                format!("hash-chained audit log verified, {n} entries"),
            ),
            None => ("fail", "audit chain did not verify (kepr doctor)".into()),
        },
        Check::Policy => match (e.policy_active, e.policy_error) {
            (_, true) => (
                "fail",
                "policy.toml has an error; governed operations denied".into(),
            ),
            (Some(true), _) => ("pass", "deny-by-default policy.toml enforced".into()),
            (Some(false), _) => ("fail", "no policy.toml: every group member may read".into()),
            (None, _) => unknown(),
        },
        Check::Health => match e.health {
            Some((score, 0)) => (
                "pass",
                format!("security score {score}/100, no weak findings"),
            ),
            Some((score, n)) => (
                "fail",
                format!("security score {score}/100, {n} credential(s) with findings"),
            ),
            None => unknown(),
        },
        Check::Manual(why) => ("manual", why.to_string()),
    }
}

/// The report rows: `kind` = `ID  status`, `detail` = title and evidence.
pub fn build(framework: &str, e: &Evidence) -> Result<Vec<AccessRow>, String> {
    let list = controls(framework)
        .ok_or_else(|| format!("framework: one of {}", FRAMEWORKS.join(", ")))?;
    Ok(list
        .iter()
        .map(|(id, title, check)| {
            let (status, why) = judge(*check, e);
            AccessRow {
                kind: format!("{id}  {status}"),
                detail: format!("{title}: {why}"),
            }
        })
        .collect())
}

fn gather() -> Evidence {
    let mut e = Evidence::default();
    if let Ok(Response::StatusOk {
        password_protected,
        info,
        ..
    }) = crate::client::send_request(&Request::Status)
    {
        e.passphrase = Some(password_protected);
        e.fips = Some(info.fips.unwrap_or(false));
    }
    if let Ok(Response::AuditOk { entries, .. }) =
        crate::client::send_request(&Request::AuditVerify)
    {
        e.audit_entries = Some(entries);
    }
    let policy = Request::Policy(PolicyRequest::PolicyStatus { reload: false });
    if let Ok(Response::Policy(PolicyResponse::PolicyStatusOk { active, error, .. })) =
        crate::client::send_request(&policy)
    {
        e.policy_active = Some(active);
        e.policy_error = error.is_some();
    }
    let health = Request::Health {
        max_age_days: None,
        policy: None,
    };
    if let Ok(Response::HealthOk { items }) = crate::client::send_request(&health) {
        let bad = items.iter().filter(|i| !i.issues.is_empty()).count();
        e.health = Some((crate::cli_recordsx::health_score::overall(&items), bad));
    }
    e
}

/// `kepr report compliance --framework F`.
pub fn cmd_compliance(args: &[&str]) -> Response {
    let (f, html) = match args {
        ["--framework", f] => (f, None),
        ["--framework", f, "--html", path] => (f, Some(*path)),
        _ => {
            return Response::fail(format!(
                "usage: kepr report compliance --framework {} [--html FILE]",
                FRAMEWORKS.join("|")
            ))
        }
    };
    let rows = match build(&f.to_lowercase(), &gather()) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    if let Some(path) = html {
        if let Err(e) = super::compliance_html::write(path, &f.to_lowercase(), &rows) {
            return Response::fail(e);
        }
    } else if !cli_mode::json_mode() {
        for r in &rows {
            println!("{:28}  {}", r.kind, r.detail);
        }
    }
    Response::Policy(PolicyResponse::AccessReportOk {
        name: f.to_lowercase(),
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Evidence {
        Evidence {
            passphrase: Some(true),
            fips: Some(true),
            audit_entries: Some(12),
            policy_active: Some(true),
            policy_error: false,
            health: Some((100, 0)),
        }
    }

    fn statuses(f: &str, e: &Evidence) -> Vec<String> {
        build(f, e)
            .unwrap()
            .iter()
            .map(|r| r.kind.rsplit("  ").next().unwrap().to_string())
            .collect()
    }

    #[test]
    fn every_framework_has_controls_and_unknown_is_refused() {
        for f in FRAMEWORKS {
            assert!(!build(f, &good()).unwrap().is_empty(), "{f}");
        }
        assert!(build("iso", &good()).unwrap_err().contains("sox"));
    }

    #[test]
    fn good_evidence_passes_and_manual_rows_stay_manual() {
        assert_eq!(statuses("pci", &good()), ["pass"; 6]);
        assert_eq!(statuses("sox", &good()), ["pass", "pass", "pass", "manual"]);
    }

    #[test]
    fn missing_protections_fail_and_unknown_checks_are_manual() {
        let bad = Evidence {
            passphrase: Some(false),
            fips: Some(false),
            audit_entries: None,
            policy_active: Some(false),
            policy_error: false,
            health: Some((70, 3)),
        };
        assert_eq!(
            statuses("nist", &bad),
            ["fail", "fail", "fail", "fail", "fail", "pass"]
        );
        let none = Evidence::default();
        assert_eq!(statuses("hipaa", &none)[3], "manual");
        let rows = build("pci", &bad).unwrap();
        assert!(rows[3].detail.contains("3 credential(s)"));
    }

    #[test]
    fn a_broken_policy_file_is_a_failure_not_a_pass() {
        let e = Evidence {
            policy_error: true,
            ..good()
        };
        assert_eq!(statuses("nist", &e)[0], "fail");
    }
}
