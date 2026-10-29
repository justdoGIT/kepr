// cli_status.rs — `kepr status`: store lock state, then (T11.24) mode,
// profile, store backend, what seals the master key, running gates,
// escrow and the recovery key (T12.31), then the crypto backend line with
// the FIPS flag (T7.16). An
// older daemon sends only the lock state; then only that line prints.

use crate::cli_args::Args;
use crate::cli_cmds::dispatch;
use crate::cli_ui::{err, info};
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_session::StatusInfo;

pub fn cmd_status(a: &Args) -> Response {
    let resp = dispatch(a, &Request::Status);
    if !a.json {
        match &resp {
            Response::StatusOk {
                locked,
                password_protected,
                info: more,
            } => {
                info(&format!(
                    "Store: {} ({})",
                    if *locked { "locked" } else { "unlocked" },
                    if *password_protected {
                        "password protected"
                    } else {
                        "local key protection"
                    }
                ));
                status_lines(more).iter().for_each(|l| info(l));
            }
            Response::Err { error } => err(error),
            _ => err("unexpected response"),
        }
        crate::cli_eco::print_status_crypto(&resp); // T7.16
        crate::cli_sharing::print_status(); // T6.14 escrow, T6.06 emergency requests
    }
    resp
}

/// One line per `key_sealer` token (T12.33); never a tool's name.
fn sealer_text(s: &str) -> String {
    match s {
        "passphrase" => "store passphrase (Argon2id)".into(),
        "passphrase+fido2" => "store passphrase (Argon2id) and a FIDO2 security key".into(),
        "file" => "owner-only key file".into(),
        "host" => "host key only, no TPM (the credential backend)".into(),
        "tpm2" => "TPM2 only (the credential backend)".into(),
        "host+tpm2" => "host key and TPM2 (the credential backend)".into(),
        "host-unrecorded" => "host-bound (TPM use was not recorded for this key)".into(),
        "aws-kms" => "wrapped by an AWS KMS key".into(),
        "gcp-kms" => "wrapped by a Google Cloud KMS key".into(),
        "azure-kv" => "wrapped by an Azure Key Vault key".into(),
        "pkcs11" => "wrapped by a PKCS#11 token or HSM key".into(),
        "key-service" => "wrapped by a key service".into(),
        "keychain" => "macOS login keychain".into(),
        "unseal-failed" => "did not unseal at start-up; run `kepr recovery-key unlock`".into(),
        other => match other.strip_prefix("tpm2+") {
            Some(opts) => tpm2_text(opts),
            None => other.into(),
        },
    }
}

/// `tpm2+pin+pcrs+counter` and its subsets, from the TPM2 PIN / counter
/// sealer.
fn tpm2_text(opts: &str) -> String {
    let parts: Vec<&str> = opts
        .split('+')
        .filter_map(|o| match o {
            "pin" => Some("a PIN"),
            "pcrs" => Some("PCR binding"),
            "counter" => Some("an anti-rollback counter"),
            _ => None,
        })
        .collect();
    match parts.as_slice() {
        [] => "TPM2".into(),
        [one] => format!("TPM2 with {one}"),
        [rest @ .., last] => format!("TPM2 with {} and {last}", rest.join(", ")),
    }
}

/// The T11.24 lines, each only when the daemon sent its fields.
pub fn status_lines(s: &StatusInfo) -> Vec<String> {
    let mut out = Vec::new();
    match (&s.mode, &s.profile) {
        (Some(m), Some(p)) => out.push(format!("Mode: {m} daemon, profile {p}")),
        (Some(m), None) => out.push(format!("Mode: {m} daemon")),
        (None, Some(p)) => out.push(format!("Profile: {p}")),
        (None, None) => {}
    }
    if let Some(b) = &s.store_backend {
        let kind = if b == "image" { "vault image" } else { "files" };
        out.push(format!("Store backend: {kind}"));
    }
    if let Some(k) = &s.key_sealer {
        out.push(format!("Master key: {}", sealer_text(k)));
    }
    if let Some(n) = s.gates {
        out.push(format!("Agent gates: {n} running"));
    }
    if let Some(e) = s.escrow {
        out.push(format!("Escrow: {}", if e { "on" } else { "off" }));
    }
    if let Some(r) = s.recovery_key {
        let state = if r {
            "enrolled"
        } else {
            "none (kepr recovery-key enrol)"
        };
        out.push(format!("Recovery key: {state}"));
    }
    if let Some(n) = s.login_failures {
        let max = kepr_core::login_unlock::MAX_FAILURES;
        out.push(if u32::from(n) >= max {
            format!("Login unlock: stopped after {n} failed attempts; `kepr unlock` resumes it")
        } else {
            format!("Login unlock: {n} failed attempt(s) in a row (is the passphrase your login password?)")
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prints_every_field_it_gets() {
        let s = StatusInfo {
            mode: Some("user".into()),
            profile: Some("work".into()),
            store_backend: Some("image".into()),
            key_sealer: Some("passphrase".into()),
            gates: Some(2),
            escrow: Some(true),
            fips: Some(false),
            recovery_key: Some(true),
            login_failures: Some(1),
        };
        assert_eq!(
            status_lines(&s),
            [
                "Mode: user daemon, profile work",
                "Store backend: vault image",
                "Master key: store passphrase (Argon2id)",
                "Agent gates: 2 running",
                "Escrow: on",
                "Recovery key: enrolled",
                "Login unlock: 1 failed attempt(s) in a row (is the passphrase your login password?)",
            ]
        );
        let closed = StatusInfo {
            login_failures: Some(5),
            ..Default::default()
        };
        assert_eq!(
            status_lines(&closed),
            ["Login unlock: stopped after 5 failed attempts; `kepr unlock` resumes it"]
        );
        let none = StatusInfo {
            recovery_key: Some(false),
            ..Default::default()
        };
        assert_eq!(
            status_lines(&none),
            ["Recovery key: none (kepr recovery-key enrol)"]
        );
    }

    #[test]
    fn every_sealer_token_has_its_line() {
        let line = |t: &str| sealer_text(t);
        assert_eq!(
            line("host"),
            "host key only, no TPM (the credential backend)"
        );
        assert_eq!(
            line("host+tpm2"),
            "host key and TPM2 (the credential backend)"
        );
        assert_eq!(line("tpm2"), "TPM2 only (the credential backend)");
        assert_eq!(
            line("host-unrecorded"),
            "host-bound (TPM use was not recorded for this key)"
        );
        assert_eq!(
            line("tpm2+pin+pcrs+counter"),
            "TPM2 with a PIN, PCR binding and an anti-rollback counter"
        );
        assert_eq!(
            line("tpm2+pin+counter"),
            "TPM2 with a PIN and an anti-rollback counter"
        );
        assert_eq!(line("tpm2+counter"), "TPM2 with an anti-rollback counter");
        assert_eq!(line("aws-kms"), "wrapped by an AWS KMS key");
        assert_eq!(line("pkcs11"), "wrapped by a PKCS#11 token or HSM key");
        assert_eq!(line("keychain"), "macOS login keychain");
        assert!(line("passphrase+fido2").contains("FIDO2"));
        for t in [
            "passphrase",
            "passphrase+fido2",
            "file",
            "host",
            "tpm2",
            "host+tpm2",
            "host-unrecorded",
            "tpm2+pin+pcrs+counter",
            "aws-kms",
            "gcp-kms",
            "azure-kv",
            "pkcs11",
            "key-service",
            "keychain",
            "unseal-failed",
        ] {
            let l = line(t);
            assert_ne!(l, t, "{t} has no line of its own");
            assert!(!l.contains("systemd") && !l.contains("tpm2-tools"), "{l}");
        }
        // A token from a newer daemon is shown as is.
        assert_eq!(line("something-new"), "something-new");
    }

    #[test]
    fn an_old_daemon_prints_only_the_store_line() {
        assert!(status_lines(&StatusInfo::default()).is_empty());
        let s = StatusInfo {
            key_sealer: Some("host".into()),
            ..Default::default()
        };
        let lines = status_lines(&s);
        assert_eq!(
            lines,
            ["Master key: host key only, no TPM (the credential backend)"]
        );
        let s = StatusInfo {
            key_sealer: Some("unseal-failed".into()),
            ..Default::default()
        };
        assert_eq!(
            status_lines(&s),
            ["Master key: did not unseal at start-up; run `kepr recovery-key unlock`"]
        );
    }
}
