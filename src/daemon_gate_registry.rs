// daemon_gate_registry.rs — the gates this daemon started (pid, uid):
// tracking, the per-uid cap, and `kepr panic` (T3.05). Split out of
// daemon_gate.rs (LOC ceiling); the channel and resolve logic stay there.

use crate::audit::{self, AuditEvent, AuditResult};
use crate::crypto;
use kepr_core::protocol::Response;

/// How to stop a gate: a child this daemon spawned (user mode) gets
/// SIGKILL; a session run by the kepr-gate service (system mode) is
/// stopped by closing its control connection.
pub(crate) enum Handle {
    Pid(i32),
    Conn(std::os::unix::net::UnixStream),
}

/// Running gates: (key, uid, handle). The key is the gate pid in user
/// mode and a negative serial for service-run gates.
pub(crate) static GATES: std::sync::Mutex<Vec<(i32, u32, Handle)>> =
    std::sync::Mutex::new(Vec::new());

/// `Some(handle)` tracks a gate, `None` forgets it.
pub(crate) fn track_gate(key: i32, uid: u32, handle: Option<Handle>) {
    if let Ok(mut g) = GATES.lock() {
        match handle {
            Some(h) => g.push((key, uid, h)),
            None => g.retain(|(k, _, _)| *k != key),
        }
    }
}

/// Stop every gate serving `uid`. Returns how many were signalled.
pub fn stop_gates_for(uid: u32) -> usize {
    stop_where(|u| u == uid)
}

/// Stop every gate of every user (root's `kepr panic` in system mode).
pub(crate) fn stop_all_gates() -> usize {
    stop_where(|_| true)
}

fn stop_where(serves: impl Fn(u32) -> bool) -> usize {
    let Ok(g) = GATES.lock() else { return 0 };
    g.iter()
        .filter(|(_, u, _)| serves(*u))
        .filter(|(_, _, h)| match h {
            // SAFETY: kill(2) on a pid this daemon spawned and still
            // tracks (removed when its channel thread reaps it).
            Handle::Pid(p) => (unsafe { libc::kill(*p, libc::SIGKILL) }) == 0,
            Handle::Conn(c) => c.shutdown(std::net::Shutdown::Both).is_ok(),
        })
        .count()
}

/// Concurrent gates one uid may run (each is a process).
pub(crate) const MAX_GATES_PER_UID: usize = 16;

pub(crate) fn gates_for(uid: u32) -> usize {
    GATES
        .lock()
        .map(|g| g.iter().filter(|(_, u, _)| *u == uid).count())
        .unwrap_or(0)
}

/// Whose gates a panic stops: `None` = every user's (root in system
/// mode, plan P3.5), else the caller's own.
pub(crate) fn panic_scope(user_mode: bool, uid: u32) -> Option<u32> {
    (user_mode || uid != 0).then_some(uid)
}

/// `kepr panic` (T3.05): stop the caller's gates (their key caches die
/// with them; root in system mode stops every user's, T12.23) and, if
/// the store is passphrase-protected, lock it so the master key leaves
/// memory until `kepr unlock`. Returns (gates stopped, locked). Used by
/// `kepr panic`, the idle timer and the sleep / key-removal watchers.
pub fn panic_now(uid: u32) -> (usize, bool) {
    let gates_stopped = match panic_scope(crate::user_mode(), uid) {
        Some(u) => stop_gates_for(u),
        None => stop_all_gates(),
    };
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
    crate::daemon_platform::fingerprint::forget(); // T10.03: a hard stop
    let (gates_stopped, locked) = panic_now(uid);
    if locked {
        crate::daemon_session::login::panicked(); // T13.25: no login undoes it
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    /// T12.23: only root's panic in system mode reaches every gate.
    #[test]
    fn panic_scope_rules() {
        assert_eq!(panic_scope(false, 0), None);
        assert_eq!(panic_scope(false, 1000), Some(1000));
        assert_eq!(panic_scope(true, 1000), Some(1000));
        assert_eq!(panic_scope(true, 0), Some(0));
    }

    #[test]
    fn stop_all_gates_reaches_every_uid() {
        let (a, mut peer_a) = UnixStream::pair().unwrap();
        let (b, mut peer_b) = UnixStream::pair().unwrap();
        track_gate(-3_998_001, 3_998_001, Some(Handle::Conn(a)));
        track_gate(-3_998_002, 3_998_002, Some(Handle::Conn(b)));
        let stopped = stop_all_gates();
        track_gate(-3_998_001, 3_998_001, None);
        track_gate(-3_998_002, 3_998_002, None);
        assert!(stopped >= 2, "{stopped}");
        // Each gate's lifeline is closed: the service side reads EOF.
        assert_eq!(peer_a.read(&mut [0u8; 1]).unwrap(), 0);
        assert_eq!(peer_b.read(&mut [0u8; 1]).unwrap(), 0);
    }
}
