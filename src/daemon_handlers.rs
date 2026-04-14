// daemon_handlers.rs — operation handlers invoked from dispatch().
//
// Each handler: validate input, call crypto/store, emit audit log, build Response.
// No socket I/O, no FFI — pure business logic over the backing store.

use std::collections::HashMap;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::crypto;
use crate::daemon_cache;
use crate::generate::{self, generate_secret, GenKind};
use crate::protocol::{CredInfo, Response};
use crate::store::{self, file_mtime_str, file_size, validate_name};

pub fn handle_set(
    uid:      u32,
    username: &str,
    name:     &str,
    value:    Option<&str>,
    generate: Option<&str>,
) -> Response {
    if let Err(e) = validate_name(name) {
        audit::log(&AuditEvent {
            op: "set", name: Some(name), uid, username,
            result: AuditResult::Fail(e.clone()),
        });
        return Response::fail(&e);
    }

    let upper = name.to_uppercase();

    let secret = if let Some(v) = value {
        generate::ZeroString::from_string(v.to_string())
    } else {
        let kind = generate.and_then(GenKind::from_str).unwrap_or(GenKind::Hex);
        generate_secret(kind)
    };

    match crypto::encrypt(uid, &upper, secret.as_bytes()) {
        Ok(()) => {
            let cred_name = store::to_cred_name(uid, &upper);
            daemon_cache::invalidate(uid);
            audit::log(&AuditEvent {
                op: "set", name: Some(&upper), uid, username,
                result: AuditResult::Ok,
            });
            Response {
                ok: true,
                name: Some(upper),
                cred_name: Some(cred_name),
                ..Response::empty()
            }
        }
        Err(e) => {
            audit::log(&AuditEvent {
                op: "set", name: Some(&upper), uid, username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(&e)
        }
    }
}

pub fn handle_get(uid: u32, username: &str, name: &str) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(&e);
    }

    let upper = name.to_uppercase();

    match crypto::decrypt(uid, &upper) {
        Ok(secret) => {
            audit::log(&AuditEvent {
                op: "get", name: Some(&upper), uid, username,
                result: AuditResult::Ok,
            });
            Response {
                ok:    true,
                name:  Some(upper),
                value: Some(secret.to_owned_string()),
                ..Response::empty()
            }
        }
        Err(e) => {
            audit::log(&AuditEvent {
                op: "get", name: Some(&upper), uid, username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(&e)
        }
    }
}

pub fn handle_list(uid: u32, username: &str) -> Response {
    let entries = daemon_cache::list_for_uid(uid);
    let creds: Vec<CredInfo> = entries.iter().map(|(name, path)| {
        CredInfo {
            name:      name.clone(),
            cred_name: store::to_cred_name(uid, name),
            size:      file_size(path),
            modified:  file_mtime_str(path),
        }
    }).collect();

    let count = creds.len();
    audit::log(&AuditEvent {
        op: "list", name: None, uid, username,
        result: AuditResult::Ok,
    });

    Response {
        ok: true,
        credentials: Some(creds),
        count: Some(count),
        ..Response::empty()
    }
}

pub fn handle_delete(uid: u32, username: &str, name: &str) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(&e);
    }

    let upper = name.to_uppercase();

    match crypto::delete(uid, &upper) {
        Ok(()) => {
            daemon_cache::invalidate(uid);
            audit::log(&AuditEvent {
                op: "delete", name: Some(&upper), uid, username,
                result: AuditResult::Ok,
            });
            Response { ok: true, name: Some(upper), ..Response::empty() }
        }
        Err(e) => {
            audit::log(&AuditEvent {
                op: "delete", name: Some(&upper), uid, username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(&e)
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
        let handles: Vec<_> = buckets.into_iter()
            .map(|bucket| s.spawn(move || {
                bucket.into_iter()
                    .map(|name| {
                        let ok = crypto::verify(uid, &name);
                        (name, ok)
                    })
                    .collect::<Vec<(String, bool)>>()
            }))
            .collect();

        for h in handles {
            for (name, ok) in h.join().unwrap() {
                results.insert(name, if ok { "ok".into() } else { "failed".into() });
                if !ok { all_ok = false; }
            }
        }
    });

    audit::log(&AuditEvent {
        op: "check", name: None, uid, username,
        result: if all_ok {
            AuditResult::Ok
        } else {
            AuditResult::Fail("some credentials failed".to_string())
        },
    });

    Response {
        ok: all_ok,
        results: Some(results),
        count: Some(count),
        ..Response::empty()
    }
}
