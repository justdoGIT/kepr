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

pub fn handle_set(
    uid: u32,
    username: &str,
    name: &str,
    value: Option<&str>,
    generate: Option<&str>,
    flags: SetFlags,
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
    let meta = match expiry::CredMeta::from_flags(
        expiry::now_unix(),
        flags.ttl_secs,
        flags.requires_consent,
        flags.requires_fido2,
    )
    .and_then(|m| m.with_seal(flags.sealed, flags.bindings))
    .map(|mut m| {
        (m.ssh, m.record_type, m.share_key) = (flags.ssh, flags.record_type, flags.share_key);
        crate::daemon_store::carry_over(uid, &upper, &mut m); // T5.01: keep tags / folder
        crate::daemon_recordsx::carry_over(uid, &upper, &mut m); // T5.03: attachments
        crate::daemon_session::reauth::carry_over(uid, &upper, &mut m); // T11.14
        crate::daemon_platform::exe::carry_over(uid, &upper, &mut m); // T10.09
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
    let cred_existed = crate::store::cred_exists(uid, &upper);
    // P5.3: keep the value being replaced (before any meta rewrite).
    crate::daemon_history::save_current(uid, &upper);
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
                // Replacing a flagged credential without flags must clear
                // the old sidecar, otherwise TTL/consent/FIDO2 policy leaks
                // into the replacement and can make it inaccessible.
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
            if meta_first && !cred_existed {
                expiry::delete_meta(&meta_path);
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
