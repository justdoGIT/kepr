use crate::daemon_handlers::*;
use crate::daemon_store::testkit;
use kepr_core::binding::{Binding, Inject};
use kepr_core::protocol::Request;

fn get(uid: u32, name: &str) -> Response {
    crate::daemon_handlers_get::handle_get(uid, 0, "t", name, None)
}

fn refused(r: &Response) -> bool {
    matches!(r, Response::Err { error } if error == crypto::SANITIZED_LOOKUP_ERROR)
}

fn bound_to(host: &str) -> Vec<Binding> {
    vec![Binding {
        host: host.into(),
        port: 443,
        inject: Inject::Bearer,
    }]
}

/// The request `kepr set NAME`, `kepr rotate NAME --hook`, the AWS IAM
/// rotator, `kepr sync-pull` and the docker / git helpers send: no
/// policy flags at all.
fn plain_set(name: &str, value: &str) -> Request {
    Request::Set {
        name: name.into(),
        value: Some(value.into()),
        generate: None,
        ttl_secs: None,
        requires_consent: None,
        requires_fido2: None,
        sealed: None,
        bindings: None,
    }
}

fn set(uid: u32, name: &str, value: &str, flags: SetFlags) -> Response {
    handle_set(uid, "t", name, Some(value), None, flags)
}

#[test]
fn a_plain_set_over_a_sealed_credential_keeps_it_sealed() {
    let uid = testkit::uid();
    testkit::set_sealed(uid, "KS_KEY", "old-value");
    let r = crate::daemon_dispatch::dispatch(uid, 0, "t", plain_set("ks_key", "rotated"));
    assert!(r.is_success(), "{r:?}");
    assert_eq!(testkit::value(uid, "KS_KEY").as_deref(), Some("rotated"));
    assert!(
        refused(&get(uid, "KS_KEY")),
        "the new value must stay sealed"
    );
    let m = testkit::meta(uid, "KS_KEY");
    assert_eq!(m.sealed, Some(true));
    assert_eq!(m.bindings, Some(bound_to("api.example.com")));
    // A generated value (`kepr set NAME --generate`) keeps it too.
    assert!(handle_set(uid, "t", "KS_KEY", None, None, SetFlags::default()).is_success());
    assert!(refused(&get(uid, "KS_KEY")));
    // The replaced sealed version restores into the still-sealed
    // credential (same bindings), and stays unreadable there.
    let r = crate::daemon_history::handle_restore(uid, "t", "KS_KEY", 2);
    assert!(r.is_success(), "{r:?}");
    assert_eq!(testkit::value(uid, "KS_KEY").as_deref(), Some("old-value"));
    assert!(refused(&get(uid, "KS_KEY")));
    assert_eq!(testkit::meta(uid, "KS_KEY").sealed, Some(true));
}

#[test]
fn a_set_never_unseals() {
    let uid = testkit::uid();
    testkit::set_sealed(uid, "KS_UNSEAL", "old-value");
    let unseal = SetFlags {
        sealed: Some(false),
        ..Default::default()
    };
    match set(uid, "KS_UNSEAL", "readable?", unseal) {
        Response::Err { error } => {
            assert!(error.contains("sealed"), "{error}");
            assert!(error.contains("kepr delete KS_UNSEAL"), "{error}");
        }
        other => panic!("unseal accepted: {other:?}"),
    }
    assert_eq!(
        testkit::value(uid, "KS_UNSEAL").as_deref(),
        Some("old-value")
    );
    let m = testkit::meta(uid, "KS_UNSEAL");
    assert_eq!(m.sealed, Some(true));
    assert_eq!(m.bindings, Some(bound_to("api.example.com")));
    // Bindings without `sealed` stay malformed: they don't re-seal.
    let half = SetFlags {
        bindings: Some(bound_to("evil.example")),
        ..Default::default()
    };
    assert!(!set(uid, "KS_UNSEAL", "x", half).is_success());
    assert_eq!(testkit::meta(uid, "KS_UNSEAL").bindings, m.bindings);
}

#[test]
fn a_set_may_reseal_with_new_bindings() {
    let uid = testkit::uid();
    testkit::set_sealed(uid, "KS_MOVE", "old-value");
    let reseal = SetFlags {
        sealed: Some(true),
        bindings: Some(bound_to("api.other.example")),
        ..Default::default()
    };
    assert!(set(uid, "KS_MOVE", "new-value", reseal).is_success());
    let m = testkit::meta(uid, "KS_MOVE");
    assert_eq!(m.sealed, Some(true));
    assert_eq!(m.bindings, Some(bound_to("api.other.example")));
    assert!(refused(&get(uid, "KS_MOVE")));
}

#[test]
fn consent_and_fido2_survive_a_plain_replacement() {
    let uid = testkit::uid();
    let consent = SetFlags {
        requires_consent: Some(true),
        ..Default::default()
    };
    assert!(set(uid, "KS_ASK", "v1", consent).is_success());
    let r = crate::daemon_dispatch::dispatch(uid, 0, "t", plain_set("KS_ASK", "v2"));
    assert!(r.is_success(), "{r:?}");
    assert_eq!(testkit::meta(uid, "KS_ASK").requires_consent, Some(true));
    assert!(
        !get(uid, "KS_ASK").is_success(),
        "consent still gates the new value"
    );
    // The owner may still clear it explicitly.
    let clear = SetFlags {
        requires_consent: Some(false),
        ..Default::default()
    };
    assert!(set(uid, "KS_ASK", "v3", clear).is_success());
    assert_eq!(testkit::meta(uid, "KS_ASK"), expiry::CredMeta::default());

    let fido2 = SetFlags {
        requires_fido2: Some(true),
        ..Default::default()
    };
    assert!(set(uid, "KS_TOUCH", "v1", fido2).is_success());
    testkit::set(uid, "KS_TOUCH", "v2");
    assert_eq!(testkit::meta(uid, "KS_TOUCH").requires_fido2, Some(true));
}

#[test]
fn sealed_and_fido2_still_never_combine() {
    let uid = testkit::uid();
    testkit::set_sealed(uid, "KS_SF", "old-value");
    let fido2 = SetFlags {
        requires_fido2: Some(true),
        ..Default::default()
    };
    assert!(!set(uid, "KS_SF", "new", fido2).is_success());
    assert_eq!(testkit::value(uid, "KS_SF").as_deref(), Some("old-value"));
    assert_eq!(testkit::meta(uid, "KS_SF").requires_fido2, None);

    // Sealing a FIDO2-gated credential would drop its FIDO2: refused.
    let fido2 = SetFlags {
        requires_fido2: Some(true),
        ..Default::default()
    };
    assert!(set(uid, "KS_FS", "old-value", fido2).is_success());
    let seal = SetFlags {
        sealed: Some(true),
        bindings: Some(bound_to("api.example.com")),
        ..Default::default()
    };
    assert!(!set(uid, "KS_FS", "new", seal).is_success());
    assert_eq!(testkit::value(uid, "KS_FS").as_deref(), Some("old-value"));
    assert_eq!(testkit::meta(uid, "KS_FS").sealed, None);
}

#[test]
fn an_ssh_key_over_a_sealed_name_takes_no_seal() {
    // A gate releases whatever is sealed to a bound host: an SSH seed
    // must never pick up the replaced credential's seal.
    let uid = testkit::uid();
    testkit::set_sealed(uid, "KS_SSH", "old-value");
    let gen = Request::SshGenerate {
        name: "KS_SSH".into(),
        comment: "c".into(),
        requires_consent: None,
        key_type: None,
    };
    let r = crate::daemon_ssh::dispatch(uid, 0, "t", gen);
    assert!(matches!(r, Response::SshKeyOk { .. }), "{r:?}");
    let m = testkit::meta(uid, "KS_SSH");
    assert!(m.ssh.is_some());
    assert_eq!((m.sealed, m.bindings), (None, None));
}

#[test]
fn a_failed_value_write_puts_the_old_policy_back() {
    // The kept seal goes to disk before the value; if the value then
    // can't be written, the old sidecar (its TTL here) must come back.
    let uid = testkit::uid();
    let sealed_ttl = SetFlags {
        ttl_secs: Some(3600),
        sealed: Some(true),
        bindings: Some(bound_to("api.example.com")),
        ..Default::default()
    };
    assert!(set(uid, "KS_FAIL", "old-value", sealed_ttl).is_success());
    let before = testkit::meta(uid, "KS_FAIL");
    assert!(before.expires_at_unix.is_some());
    let cp = cred_path(uid, "KS_FAIL");
    std::fs::remove_file(&cp).unwrap();
    std::fs::create_dir_all(cp.join("blocker")).unwrap(); // the value can't land
    assert!(!set(uid, "KS_FAIL", "new", SetFlags::default()).is_success());
    assert_eq!(testkit::meta(uid, "KS_FAIL"), before);
    std::fs::remove_dir_all(&cp).unwrap();
}

#[test]
fn an_unreadable_old_policy_refuses_the_replacement() {
    let uid = testkit::uid();
    testkit::set_sealed(uid, "KS_BAD", "old-value");
    let mp = expiry::meta_path_for(&cred_path(uid, "KS_BAD"));
    std::fs::write(&mp, b"{not json").unwrap();
    assert!(!set(uid, "KS_BAD", "new", SetFlags::default()).is_success());
    assert_eq!(testkit::value(uid, "KS_BAD").as_deref(), Some("old-value"));
}
