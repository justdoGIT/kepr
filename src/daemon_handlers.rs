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
    /// Keep an absolute deadline during internal credential migrations.
    pub preserve_expires_at: Option<u64>,
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
            // Sealed with no binding (the local CA key): nothing to carry.
            (_, None) if old.bindings.as_ref().is_none_or(|b| b.is_empty()) => {
                return delete_first("is sealed and a set never unseals it")
            }
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
        if flags.preserve_expires_at.is_some() {
            m.expires_at_unix = flags.preserve_expires_at;
        }
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
#[path = "daemon_handlers_tests.rs"]
mod tests;
