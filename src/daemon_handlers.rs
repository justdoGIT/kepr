// daemon_handlers.rs — operation handlers invoked from dispatch().
//
// Each handler: validate input, call crypto/store, emit audit log, build Response.
// No socket I/O, no FFI — pure business logic over the backing store.

use std::collections::HashMap;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::crypto;
use crate::daemon_cache;
use crate::expiry;
use crate::store::{self, cred_path, file_mtime_str, file_size, validate_name};
use kepr_core::generate::{self, generate_secret, GenKind};
use kepr_core::protocol::{CredInfo, Response};

pub fn handle_set(
    uid: u32,
    username: &str,
    name: &str,
    value: Option<&str>,
    generate: Option<&str>,
    ttl_secs: Option<u64>,
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
        generate_secret(kind)
    };

    match crypto::default_backend().encrypt(uid, &upper, secret.as_bytes()) {
        Ok(()) => {
            // TTL handling lives in the success branch ONLY: if the
            // encrypt failed, there's no cred on disk for the meta
            // file to attach to. A meta-write failure on the success
            // path is reported as a soft failure — the cred IS
            // written and readable, but the expiry constraint isn't
            // durable. The handler returns Err so the user retries
            // with a fresh `--ttl`, picking up a new
            // `now + ttl_secs` window.
            if let Some(ttl) = ttl_secs {
                let cp = cred_path(uid, &upper);
                let mp = expiry::meta_path_for(&cp);
                let now = expiry::now_unix();
                let expires = match expiry::compute_expires_at(now, ttl) {
                    Some(t) => t,
                    None => {
                        audit::log(&AuditEvent {
                            op: "set",
                            name: Some(&upper),
                            uid,
                            username,
                            result: AuditResult::Fail("ttl overflow".into()),
                        });
                        return Response::fail("ttl too large to fit in u64");
                    }
                };
                if let Err(e) = expiry::write_meta(&mp, expires) {
                    audit::log(&AuditEvent {
                        op: "set",
                        name: Some(&upper),
                        uid,
                        username,
                        result: AuditResult::Fail(format!("meta write: {e}")),
                    });
                    return Response::fail(format!("ttl metadata write failed: {e}"));
                }
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

pub fn handle_get(uid: u32, username: &str, name: &str) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(e);
    }

    let upper = name.to_uppercase();

    // Phase 2 α: expiry check BEFORE decrypt. A cred that's past
    // its TTL must look identical (on the wire) to a cred that
    // never existed — same sanitised "credential unavailable"
    // string the lookup-error path produces. The audit log carries
    // the precise reason (`expired`) so post-mortem inspection can
    // distinguish.
    let cp = cred_path(uid, &upper);
    let mp = expiry::meta_path_for(&cp);
    if let Some(meta_result) = expiry::read_meta(&mp) {
        match meta_result {
            Ok(meta) if expiry::now_unix() >= meta.expires_at_unix => {
                audit::log(&AuditEvent {
                    op: "get",
                    name: Some(&upper),
                    uid,
                    username,
                    result: AuditResult::Fail("expired".into()),
                });
                return Response::fail("credential unavailable");
            }
            Ok(_) => {} // valid + not yet expired → fall through
            Err(e) => {
                // Malformed meta — fail-closed. The alternative
                // (silently ignore the meta and decrypt anyway)
                // would let an attacker who corrupts the meta file
                // bypass the expiry constraint.
                audit::log(&AuditEvent {
                    op: "get",
                    name: Some(&upper),
                    uid,
                    username,
                    result: AuditResult::Fail(format!("meta parse: {e}")),
                });
                return Response::fail("credential unavailable");
            }
        }
    }

    match crypto::default_backend().decrypt(uid, &upper) {
        Ok(secret) => {
            audit::log(&AuditEvent {
                op: "get",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Ok,
            });
            // Move the ZeroString directly into the response — the
            // protocol field is `value: ZeroString`, so the secret
            // bytes never touch a non-zeroising String on the way
            // out. The previous `secret.to_owned_string()` cloned
            // into a plain String that the serializer would then
            // walk; that String dropped without zeroizing.
            Response::GetOk {
                name: upper,
                value: secret,
            }
        }
        Err(e) => {
            audit::log(&AuditEvent {
                op: "get",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(crypto::sanitize_lookup_error(&e))
        }
    }
}

pub fn handle_list(uid: u32, username: &str) -> Response {
    let entries = daemon_cache::list_for_uid(uid);
    let creds: Vec<CredInfo> = entries
        .iter()
        .map(|(name, path)| {
            // Phase 2 α: surface `expires_at` for creds with a TTL
            // sidecar. A malformed meta is intentionally rendered
            // as None here (the GET path treats malformed-meta as
            // fail-closed), so list output stays clean.
            let expires_at = expiry::read_meta(&expiry::meta_path_for(path))
                .and_then(|r| r.ok())
                .map(|m| expiry::format_expires_at(m.expires_at_unix));
            CredInfo {
                name: name.clone(),
                cred_name: store::to_cred_name(uid, name),
                size: file_size(path),
                modified: file_mtime_str(path),
                expires_at,
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
        return Response::fail(e);
    }

    let upper = name.to_uppercase();

    match crypto::default_backend().delete(uid, &upper) {
        Ok(()) => {
            // Phase 2 α: best-effort meta cleanup AFTER the cred is
            // removed. If meta-delete fails, the cred is gone and a
            // stale meta is harmless (no decrypt can succeed against
            // a missing cred, so the expiry-check path is moot).
            // Logging this would just clutter the audit pipeline.
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

    // Parallelise verify across a bounded thread fan-out.
    // Each verify is a fork+exec of the credential backend, so CPU isn't the
    // bottleneck — the gain is overlapping the round-trip latency.
    let par = std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(2)
        .min(count.max(1));

    // Round-robin names into `par` buckets to balance load.
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
