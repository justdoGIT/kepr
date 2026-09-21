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
use crate::store::{self, cred_path, file_mtime_str, file_size, validate_name};
use kepr_core::generate::{self, generate_secret, GenKind};
use kepr_core::protocol::{CredInfo, Response};

#[allow(clippy::too_many_arguments)]
pub fn handle_set(
    uid: u32,
    username: &str,
    name: &str,
    value: Option<&str>,
    generate: Option<&str>,
    ttl_secs: Option<u64>,
    requires_consent: Option<bool>,
    requires_fido2: Option<bool>,
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

    match crypto::default_backend().encrypt(uid, &upper, secret.as_bytes()) {
        Ok(()) => {
            let meta = match expiry::CredMeta::from_flags(
                expiry::now_unix(),
                ttl_secs,
                requires_consent,
                requires_fido2,
            ) {
                Ok(m) => m,
                Err(e) => {
                    let _ = crypto::default_backend().delete(uid, &upper);
                    audit::log(&AuditEvent {
                        op: "set",
                        name: Some(&upper),
                        uid,
                        username,
                        result: AuditResult::Fail(format!("{e} (cred rolled back)")),
                    });
                    return Response::fail(e);
                }
            };

            if !meta.is_empty() {
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
            }
        }
        Err(e) => {
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

pub fn handle_list(uid: u32, username: &str) -> Response {
    let entries = daemon_cache::list_for_uid(uid);
    let creds: Vec<CredInfo> = entries
        .iter()
        .map(|(name, path)| {
            let meta_opt = expiry::read_meta(&expiry::meta_path_for(path)).and_then(|r| r.ok());
            let expires_at = meta_opt
                .as_ref()
                .and_then(|m| m.expires_at_unix.map(expiry::format_expires_at));
            let requires_consent = meta_opt
                .as_ref()
                .and_then(|m| m.requires_consent)
                .filter(|v| *v)
                .map(|_| true);
            let requires_fido2 = meta_opt
                .as_ref()
                .and_then(|m| m.requires_fido2)
                .filter(|v| *v)
                .map(|_| true);
            CredInfo {
                name: name.clone(),
                cred_name: store::to_cred_name(uid, name),
                size: file_size(path),
                modified: file_mtime_str(path),
                expires_at,
                requires_consent,
                requires_fido2,
            }
        })
        .collect();

    audit::log(&AuditEvent {
        op: "list",
        name: None,
        uid,
        username,
        result: AuditResult::Ok,
    });

    let count = creds.len();
    Response::ListOk {
        credentials: creds,
        count,
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

    match crypto::default_backend().delete(uid, &upper) {
        Ok(()) => {
            expiry::delete_meta(&expiry::meta_path_for(&cred_path(uid, &upper)));
            daemon_cache::invalidate(uid);
            audit::log(&AuditEvent {
                op: "delete",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Ok,
            });
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
