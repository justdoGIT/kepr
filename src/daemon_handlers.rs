// daemon_handlers.rs — operation handlers invoked from dispatch().
//
// Each handler: validate input, call crypto/store, emit audit log, build Response.
// No socket I/O, no FFI — pure business logic over the backing store.
//
// handle_get (the most complex handler, with FIDO2 and polkit gates)
// lives in daemon_handlers_get.rs — split in Phase 2 η to keep this
// file under the 350-LOC ceiling.

use std::collections::HashMap;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::crypto;
use crate::daemon_cache;
use crate::expiry;
use crate::store::{self, cred_path, validate_name};
use kepr_core::generate::{self, generate_secret, GenKind};
use kepr_core::protocol::Response;

/// Optional per-credential policy carried by `Request::Set`.
#[derive(Default)]
pub struct SetFlags {
    pub ttl_secs: Option<u64>,
    pub requires_consent: Option<bool>,
    pub requires_fido2: Option<bool>,
    pub sealed: Option<bool>,
    pub bindings: Option<Vec<kepr_core::binding::Binding>>,
    /// P2.4: the value is an SSH key seed (sign-only).
    pub ssh: Option<expiry::SshMeta>,
    /// P5.1: the value is a typed record (JSON object of fields).
    pub record_type: Option<String>,
    /// P6.1: the value is the user's share key (never readable).
    pub share_key: Option<bool>,
}

/// What a `set` replacing a value keeps unless it says otherwise: a sealed
/// credential stays sealed to its hosts (`sealed: true` + new bindings
/// re-seals; `sealed: false` is refused, a set never unseals); consent and
/// FIDO2 stay on unless `false`. SSH / share keys take no seal (a gate
/// releases what is sealed). An unreadable old policy is never guessed at.
fn keep_protection(uid: u32, upper: &str, f: &mut SetFlags) -> Result<(), String> {
    let delete_first = |why: &str| Err(format!("{upper} {why}; `kepr delete {upper}` first"));
    let old = match expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))) {
        None => return Ok(()),
        Some(Ok(old)) => old,
        Some(Err(_)) => return delete_first("has an unreadable policy"),
    };
    if f.sealed == Some(true) && f.requires_fido2.is_none() && old.requires_fido2 == Some(true) {
        return delete_first("requires FIDO2, which sealed credentials can't use yet");
    }
    if old.sealed == Some(true) && f.ssh.is_none() && f.share_key.is_none() {
        match (f.sealed, &f.bindings) {
            (Some(false), _) => return delete_first("is sealed and a set never unseals it"),
            (_, None) => (f.sealed, f.bindings) = (Some(true), old.bindings),
            _ => {} // new bindings: `sealed: true` re-seals, without it they're refused
        }
    }
    f.requires_consent = f.requires_consent.or(old.requires_consent);
    f.requires_fido2 = f.requires_fido2.or(old.requires_fido2);
    Ok(())
}

pub fn handle_set(
    uid: u32,
    username: &str,
    name: &str,
    value: Option<&str>,
    generate: Option<&str>,
    mut flags: SetFlags,
) -> Response {
    if let Err(e) = validate_name(name) {
        audit::log(&AuditEvent {
            op: "set",
            name: Some(name),
            uid,
            username,
            result: AuditResult::Fail(e.clone()),
        });
        return Response::fail(e);
    }

    let upper = name.to_uppercase();

    let _lock = crate::daemon_credlock::lock(uid, &upper);

    // The share private key is written only by `kepr share key`.
    if upper == "KEPR_SHARE_KEY" && flags.share_key != Some(true) {
        return Response::fail("KEPR_SHARE_KEY is reserved");
    }

    // Validate every flag before touching the store, so a bad binding
    // never leaves a half-written credential behind.
    let kept = keep_protection(uid, &upper, &mut flags); // seal, consent, FIDO2
    let meta = match expiry::CredMeta::from_flags(
        expiry::now_unix(),
        flags.ttl_secs,
        flags.requires_consent,
        flags.requires_fido2,
    )
    .and_then(|m| kept.and_then(|()| m.with_seal(flags.sealed, flags.bindings)))
    .map(|mut m| {
        (m.ssh, m.record_type, m.share_key) = (flags.ssh, flags.record_type, flags.share_key);
        crate::daemon_store::carry_over(uid, &upper, &mut m); // T5.01: keep tags / folder
        crate::daemon_recordsx::carry_over(uid, &upper, &mut m); // T5.03: attachments
        crate::daemon_session::reauth::carry_over(uid, &upper, &mut m); // T11.14
        crate::daemon_aws::carry_over(uid, &upper, &mut m); // T7.07, T7.10
        crate::daemon_platform::exe::carry_over(uid, &upper, &mut m); // T10.09
        crate::daemon_syncx::quorum_carry_over(uid, &upper, &mut m); // T7.12
        m
    }) {
        Ok(m) => m,
        Err(e) => {
            audit::log(&AuditEvent {
                op: "set",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Fail(e.clone()),
            });
            return Response::fail(e);
        }
    };

    let secret = if let Some(v) = value {
        generate::ZeroString::from_string(v.to_string())
    } else {
        let kind = generate.and_then(GenKind::from_str).unwrap_or(GenKind::Hex);
        match generate_secret(kind) {
            Ok(s) => s,
            Err(e) => {
                audit::log(&AuditEvent {
                    op: "set",
                    name: Some(&upper),
                    uid,
                    username,
                    result: AuditResult::Fail(e.clone()),
                });
                return Response::fail(e);
            }
        }
    };

    // A sealed value must never be readable, even for an instant: write
    // its sidecar *before* the value, so a concurrent Get already sees
    // `sealed`. (Other flags keep the write-after order with rollback.)
    let meta_path = expiry::meta_path_for(&cred_path(uid, &upper));
    let meta_first = meta.sealed == Some(true) || meta.ssh.is_some() || meta.share_key.is_some();
    // P5.3: keep the value being replaced (before any meta rewrite).
    crate::daemon_history::save_current(uid, &upper);
    let old_meta = expiry::read_meta(&meta_path).and_then(Result::ok); // put back on failure
    if meta_first {
        if let Err(e) = expiry::write_meta(&meta_path, &meta) {
            audit::log(&AuditEvent {
                op: "set",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Fail(format!("meta write: {e}")),
            });
            return Response::fail(format!("meta write failed: {e}"));
        }
    }

    match crypto::default_backend().encrypt(uid, &upper, secret.as_bytes()) {
        Ok(()) => {
            if meta_first {
                // already written above
            } else if !meta.is_empty() {
                let cp = cred_path(uid, &upper);
                let mp = expiry::meta_path_for(&cp);
                if let Err(e) = expiry::write_meta(&mp, &meta) {
                    let rollback = crypto::default_backend().delete(uid, &upper);
                    let audit_msg = match &rollback {
                        Ok(()) => format!("meta write: {e} (cred rolled back)"),
                        Err(re) => format!("meta write: {e}; rollback also failed: {re}"),
                    };
                    audit::log(&AuditEvent {
                        op: "set",
                        name: Some(&upper),
                        uid,
                        username,
                        result: AuditResult::Fail(audit_msg),
                    });
                    let user_msg = match rollback {
                        Ok(()) => format!("meta write failed: {e}"),
                        Err(re) => format!(
                            "meta write failed: {e}; \
                             cred rollback also failed: {re} \
                             (cred {upper} may persist without flags — delete manually)"
                        ),
                    };
                    return Response::fail(user_msg);
                }
            } else {
                // Nothing is left to keep (a TTL never carries over): clear
                // the old sidecar, so an old expiry can't hit the new value.
                expiry::delete_meta(&expiry::meta_path_for(&cred_path(uid, &upper)));
            }

            let cred_name = store::to_cred_name(uid, &upper);
            daemon_cache::invalidate(uid);
            crate::daemon_gate::bump_generation();
            audit::log(&AuditEvent {
                op: "set",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Ok,
            });
            Response::SetOk {
                name: upper,
                cred_name,
                password_protected: crate::protected_master_key_path().exists(),
            }
        }
        Err(e) => {
            // The value didn't change, so neither does its policy (TTL, …).
            match (meta_first, &old_meta) {
                (true, Some(old)) => drop(expiry::write_meta(&meta_path, old)),
                (true, None) => expiry::delete_meta(&meta_path),
                (false, _) => {}
            }
            audit::log(&AuditEvent {
                op: "set",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(e)
        }
    }
}

pub fn handle_delete(uid: u32, username: &str, name: &str) -> Response {
    if let Err(e) = validate_name(name) {
        audit::log(&AuditEvent {
            op: "delete",
            name: Some(name),
            uid,
            username,
            result: AuditResult::Fail(e.clone()),
        });
        return Response::fail(e);
    }

    let upper = name.to_uppercase();
    let _lock = crate::daemon_credlock::lock(uid, &upper);

    match crypto::default_backend().delete(uid, &upper) {
        Ok(()) => {
            expiry::delete_meta(&expiry::meta_path_for(&cred_path(uid, &upper)));
            crate::daemon_history::purge(uid, &upper);
            daemon_cache::invalidate(uid);
            audit::log(&AuditEvent {
                op: "delete",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Ok,
            });
            crate::daemon_gate::bump_generation();
            Response::DeleteOk { name: upper }
        }
        Err(e) => {
            audit::log(&AuditEvent {
                op: "delete",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(crypto::sanitize_lookup_error(&e))
        }
    }
}

pub fn handle_check(uid: u32, username: &str) -> Response {
    let entries = daemon_cache::list_for_uid(uid);
    let count = entries.len();

    let par = std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(2)
        .min(count.max(1));

    let mut buckets: Vec<Vec<String>> = (0..par).map(|_| Vec::new()).collect();
    for (i, (name, _)) in entries.iter().enumerate() {
        buckets[i % par].push(name.clone());
    }

    let mut results: HashMap<String, String> = HashMap::new();
    let mut all_ok = true;

    std::thread::scope(|s| {
        let handles: Vec<_> = buckets
            .into_iter()
            .map(|bucket| {
                s.spawn(move || {
                    bucket
                        .into_iter()
                        .map(|name| {
                            let ok = crypto::default_backend().verify(uid, &name);
                            (name, ok)
                        })
                        .collect::<Vec<(String, bool)>>()
                })
            })
            .collect();

        for h in handles {
            for (name, ok) in h.join().unwrap() {
                results.insert(name, if ok { "ok".into() } else { "failed".into() });
                if !ok {
                    all_ok = false;
                }
            }
        }
    });

    audit::log(&AuditEvent {
        op: "check",
        name: None,
        uid,
        username,
        result: if all_ok {
            AuditResult::Ok
        } else {
            AuditResult::Fail("some credentials failed".to_string())
        },
    });

    Response::CheckOk {
        results,
        count,
        all_ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
