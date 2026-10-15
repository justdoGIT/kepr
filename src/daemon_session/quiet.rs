// daemon_session/quiet.rs — `GetQuiet`, the `Get` behind `kepr serve`
// (T11.19). It never prompts: a credential needing consent (polkit or a
// T9.04 approval), FIDO2, re-authentication or M-of-N approvals (T7.12)
// reads as unavailable, even while a reveal or use window is open, so an
// HTTP client holding the serve token can't borrow a prompt or a window
// meant for the user's own `kepr get`, and can't hold a daemon worker on
// a prompt.

use kepr_core::protocol::Response;

use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};

pub fn handle_get_quiet(uid: u32, peer_pid: i32, username: &str, name: &str) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(e);
    }
    let upper = name.to_uppercase();
    let target = crate::daemon_store::resolve_alias(uid, &upper);
    // `handle_get` takes the same (re-entrant) lock, so the flags checked
    // here are the ones it decrypts under.
    let _lock = crate::daemon_credlock::lock(uid, &target);
    let meta = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, &target)));
    if let Some(Ok(m)) = &meta {
        if needs_prompt(m) {
            super::audit_op("get", Some(&target), uid, username, Err("needs a prompt"));
            return Response::fail("credential unavailable");
        }
    }
    crate::daemon_handlers_get::handle_get(uid, peer_pid, username, name, None)
}

fn needs_prompt(m: &CredMeta) -> bool {
    [m.requires_consent, m.requires_fido2, m.requires_reauth].contains(&Some(true))
        || m.approvals.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_handlers_get::handle_get;
    use crate::daemon_store::testkit;

    #[test]
    fn prompts_of_any_kind_are_refused() {
        assert!(!needs_prompt(&CredMeta::default()));
        for m in [
            CredMeta {
                requires_consent: Some(true),
                ..Default::default()
            },
            CredMeta {
                requires_fido2: Some(true),
                ..Default::default()
            },
            CredMeta {
                requires_reauth: Some(true),
                ..Default::default()
            },
            CredMeta {
                approvals: Some(2),
                ..Default::default()
            },
        ] {
            assert!(needs_prompt(&m), "{m:?}");
        }
    }

    #[test]
    fn an_open_reveal_window_is_not_borrowed() {
        let uid = testkit::uid();
        testkit::set(uid, "QG_PLAIN", "v1");
        testkit::set(uid, "QG_REAUTH", "v2");
        let mp = expiry::meta_path_for(&cred_path(uid, "QG_REAUTH"));
        let mut m = testkit::meta(uid, "QG_REAUTH");
        m.requires_reauth = Some(true);
        expiry::write_meta(&mp, &m).unwrap();
        crate::daemon_session::reauth::open_window_for_test(uid, "QG_REAUTH");
        // The user's own `kepr get` may use the window ...
        assert!(handle_get(uid, 0, "t", "QG_REAUTH", None).is_success());
        // ... `kepr serve` may not.
        match handle_get_quiet(uid, 0, "t", "qg_reauth") {
            Response::Err { error } => assert_eq!(error, "credential unavailable"),
            other => panic!("{other:?}"),
        }
        assert!(handle_get_quiet(uid, 0, "t", "QG_PLAIN").is_success());
        assert!(!handle_get_quiet(uid, 0, "t", "../X").is_success());
    }
}
