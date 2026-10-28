// daemon_gatex/rotate.rs — `GateRequest::RotateCommit` (T13.03): the gate
// of a `rotate:` session stores the new value of the sealed credential it
// just rotated at the provider.
//
// Only that gate may: the credential must be one of the session's
// `rotate:` routes (`GateOwner::rotatable`, set from the CLI's StartGate
// and nothing an agent session has), and it must already be sealed, so a
// commit can only replace a sealed key with another. The seal and the
// bindings stay (the same path `set` takes over a sealed credential); the
// old value's history slots are purged, since the old key is revoked at the
// provider and nothing should restore it; every gate re-fetches at once.
// The value is never logged and never returned.

use kepr_core::gate_protocol::GateResponse;
use kepr_core::generate::ZeroString;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_gate::GateOwner;
use crate::daemon_handlers::{handle_set, SetFlags};
use crate::expiry;
use crate::store::cred_path;

/// Longest value a rotation may store (API keys are far shorter).
const MAX_VALUE: usize = 8 * 1024;

pub fn commit(owner: &GateOwner, id: u64, name: &str, value: &ZeroString) -> GateResponse {
    let fail = || GateResponse::Err {
        id,
        error: "credential unavailable".into(),
    };
    let upper = name.to_uppercase();
    if !owner.rotatable.contains(&upper)
        || value.as_str().is_empty()
        || value.as_str().len() > MAX_VALUE
    {
        return fail();
    }
    let (uid, username) = (owner.uid, owner.username.as_str());
    let sealed = matches!(
        expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, &upper))),
        Some(Ok(m)) if m.sealed == Some(true)
    );
    let log = |result| {
        audit::log(&AuditEvent {
            op: "rotate-commit",
            name: Some(&upper),
            uid,
            username,
            result,
        })
    };
    if !sealed {
        log(AuditResult::Fail("not a sealed credential".into()));
        return fail();
    }
    match handle_set(
        uid,
        username,
        &upper,
        Some(value.as_str()),
        None,
        SetFlags::default(),
    ) {
        r if r.is_success() => {
            crate::daemon_history::purge_slots(uid, &upper);
            crate::daemon_cache::invalidate(uid);
            crate::daemon_gate::bump_generation();
            log(AuditResult::Ok);
            GateResponse::Rotated { id }
        }
        _ => {
            log(AuditResult::Fail("store refused the new value".into()));
            fail()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn owner(uid: u32, rotatable: &[&str]) -> GateOwner {
        GateOwner {
            uid,
            username: "t".into(),
            pid: std::process::id() as i32,
            creds: rotatable.iter().map(|s| s.to_string()).collect(),
            rec: crate::daemon_gatex::recording::Recorder::new(uid, "0123456789abcdef", false),
            harness: None,
            deadlines: Default::default(),
            rotatable: rotatable.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn a_rotating_session_replaces_the_value_and_keeps_the_seal() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "ROT", "old-key");
        let before = crate::daemon_gate::generation();
        let r = commit(
            &owner(uid, &["ROT"]),
            7,
            "rot",
            &ZeroString::from("new-key"),
        );
        assert!(matches!(r, GateResponse::Rotated { id: 7 }), "{r:?}");
        assert_eq!(testkit::value(uid, "ROT").as_deref(), Some("new-key"));
        let m = testkit::meta(uid, "ROT");
        assert_eq!(m.sealed, Some(true));
        assert!(m.bindings.is_some(), "bindings kept");
        assert!(crate::daemon_gate::generation() > before, "gates re-fetch");
    }

    #[test]
    fn an_ordinary_session_cannot_commit() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "KEEP", "old-key");
        let r = commit(&owner(uid, &[]), 1, "KEEP", &ZeroString::from("attacker"));
        assert!(matches!(r, GateResponse::Err { .. }));
        assert_eq!(testkit::value(uid, "KEEP").as_deref(), Some("old-key"));
        // A rotating session for another credential cannot reach this one.
        let r = commit(
            &owner(uid, &["OTHER"]),
            1,
            "KEEP",
            &ZeroString::from("attacker"),
        );
        assert!(matches!(r, GateResponse::Err { .. }));
        assert_eq!(testkit::value(uid, "KEEP").as_deref(), Some("old-key"));
    }

    #[test]
    fn a_plain_credential_is_not_replaced_and_empty_or_huge_values_are_refused() {
        let uid = testkit::uid();
        testkit::set(uid, "PLAINROT", "plain");
        let o = owner(uid, &["PLAINROT", "SEALEDROT"]);
        assert!(matches!(
            commit(&o, 1, "PLAINROT", &ZeroString::from("x")),
            GateResponse::Err { .. }
        ));
        assert_eq!(testkit::value(uid, "PLAINROT").as_deref(), Some("plain"));
        testkit::set_sealed(uid, "SEALEDROT", "old");
        assert!(matches!(
            commit(&o, 1, "SEALEDROT", &ZeroString::from("")),
            GateResponse::Err { .. }
        ));
        let huge = ZeroString::from("x".repeat(MAX_VALUE + 1).as_str());
        assert!(matches!(
            commit(&o, 1, "SEALEDROT", &huge),
            GateResponse::Err { .. }
        ));
        assert_eq!(testkit::value(uid, "SEALEDROT").as_deref(), Some("old"));
    }

    #[test]
    fn the_old_value_is_not_kept_as_history() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "HIST", "old-key");
        let o = owner(uid, &["HIST"]);
        assert!(matches!(
            commit(&o, 1, "HIST", &ZeroString::from("new-1")),
            GateResponse::Rotated { .. }
        ));
        // handle_set saved the old value to slot 0 before replacing it.
        assert!(
            crate::store::cred_exists(uid, "HIST~0") == false,
            "history slot kept"
        );
        assert!(crate::daemon_history::version_value(uid, "HIST", 1).is_err());
    }
}
