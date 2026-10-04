// daemon_gate_registry.rs — the gates this daemon started (pid, uid):
// tracking, the per-uid cap, and `kepr panic` (T3.05). Split out of
// daemon_gate.rs (LOC ceiling); the channel and resolve logic stay there.

use crate::audit::{self, AuditEvent, AuditResult};
use crate::crypto;
use kepr_core::protocol::Response;

/// Gates this daemon started: (gate pid, uid). Used by `kepr panic`.
pub(crate) static GATES: std::sync::Mutex<Vec<(i32, u32)>> = std::sync::Mutex::new(Vec::new());

pub(crate) fn track_gate(pid: i32, uid: u32, add: bool) {
    if let Ok(mut g) = GATES.lock() {
        if add {
            g.push((pid, uid));
        } else {
            g.retain(|(p, _)| *p != pid);
        }
    }
}

/// SIGKILL every gate serving `uid`. Returns how many were signalled.
pub fn stop_gates_for(uid: u32) -> usize {
    let Ok(g) = GATES.lock() else { return 0 };
    g.iter()
        .filter(|(_, u)| *u == uid)
        // SAFETY: kill(2) on a pid this daemon spawned and still tracks
        // (removed from the list when its channel thread reaps it).
        .filter(|(p, _)| unsafe { libc::kill(*p, libc::SIGKILL) } == 0)
        .count()
}

/// Concurrent gates one uid may run (each is a process).
pub(crate) const MAX_GATES_PER_UID: usize = 16;

pub(crate) fn gates_for(uid: u32) -> usize {
    GATES
        .lock()
        .map(|g| g.iter().filter(|(_, u)| *u == uid).count())
        .unwrap_or(0)
}

/// `kepr panic` (T3.05): stop the caller's gates (their key caches die
/// with them) and, if the store is passphrase-protected, lock it so the
/// master key leaves memory until `kepr unlock`.
/// Stop `uid`'s gates and lock the store if allowed and protected.
/// Returns (gates stopped, locked). Used by `kepr panic` and the
/// suspend/screen-lock watcher.
pub fn panic_now(uid: u32) -> (usize, bool) {
    let gates_stopped = stop_gates_for(uid);
    let may_lock = crate::user_mode() || uid == 0;
    let locked =
        may_lock && crate::protected_master_key_path().exists() && crypto::lock_backend().is_ok();
    (gates_stopped, locked)
}

/// `kepr leaked NAME` (P9.8): a value is known to be exposed. Stop every
/// agent gate of the caller (their caches hold it), delete it with its
/// history, and record the incident in the audit chain.
pub fn handle_leaked(uid: u32, username: &str, name: &str) -> Response {
    if let Err(e) = crate::store::validate_name(name) {
        return Response::fail(e);
    }
    let upper = name.to_uppercase();
    let hosts: Vec<String> = crate::expiry::read_meta(&crate::expiry::meta_path_for(
        &crate::store::cred_path(uid, &upper),
    ))
    .and_then(Result::ok)
    .and_then(|m| m.bindings)
    .map(|bs| bs.into_iter().map(|b| b.host).collect())
    .unwrap_or_default();
    let gates_stopped = stop_gates_for(uid);
    let deleted = crate::daemon_handlers::handle_delete(uid, username, &upper);
    audit::log(&AuditEvent {
        op: "leak-incident",
        name: Some(&upper),
        uid,
        username,
        result: match &deleted {
            Response::DeleteOk { .. } => AuditResult::Ok,
            _ => AuditResult::Fail("credential not deleted".into()),
        },
    });
    match deleted {
        Response::DeleteOk { name } => Response::LeakedOk {
            name,
            gates_stopped,
            hosts,
        },
        other => other,
    }
}

pub fn handle_panic(uid: u32, username: &str) -> Response {
    let (gates_stopped, locked) = panic_now(uid);
    audit::log(&AuditEvent {
        op: "panic",
        name: None,
        uid,
        username,
        result: AuditResult::Ok,
    });
    Response::PanicOk {
        gates_stopped,
        locked,
    }
}
