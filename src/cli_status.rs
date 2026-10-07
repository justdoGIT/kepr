// cli_status.rs — `kepr status`: store lock state, then (T11.24) mode,
// profile, store backend, what seals the master key, running gates and
// escrow, then the crypto backend line with the FIPS flag (T7.16). An
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
    }
    resp
}

fn sealer_text(s: &str) -> String {
    match s {
        "passphrase" => "store passphrase (Argon2id)".into(),
        "host" => "host-bound (the credential backend)".into(),
        "file" => "owner-only key file".into(),
        other => other.into(),
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
        };
        assert_eq!(
            status_lines(&s),
            [
                "Mode: user daemon, profile work",
                "Store backend: vault image",
                "Master key: store passphrase (Argon2id)",
                "Agent gates: 2 running",
                "Escrow: on",
            ]
        );
    }

    #[test]
    fn an_old_daemon_prints_only_the_store_line() {
        assert!(status_lines(&StatusInfo::default()).is_empty());
        let s = StatusInfo {
            key_sealer: Some("host".into()),
            ..Default::default()
        };
        let lines = status_lines(&s);
        assert_eq!(lines, ["Master key: host-bound (the credential backend)"]);
    }
}
