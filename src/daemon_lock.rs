// daemon_lock.rs — handlers for Request::Lock / Request::Unlock.
//
// Split out for the same reason as daemon_audit.rs: daemon.rs sits at its
// LOC allowlist ceiling, and lock/unlock are a genuinely distinct concept
// from the accept-loop/bootstrap code that fills the rest of the file —
// giving the uid gate below its own file makes it easy to find and review
// in isolation.
//
// Security-critical (C1 fix): in system mode (root daemon serving multiple
// `kepr`-group members), only uid 0 may lock or unlock the shared master
// key. Before this gate, any group member could send an unauthenticated
// `lock`/`unlock` and ransomware or destroy every other user's secrets
// with one request. User mode already restricts every connection to the
// daemon's own uid (the owner check in `daemon::handle_client`), so the
// gate is a no-op there.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::{crypto, key_unlock, user_mode};
use kepr_core::protocol::Response;

fn master_key_path() -> std::path::PathBuf {
    crate::state_dir().join("master.key")
}

fn protected_master_key_path() -> std::path::PathBuf {
    crate::state_dir().join("master.key.argon2id")
}

fn write_protected_master_key(envelope: &[u8]) -> Result<(), String> {
    let path = protected_master_key_path();
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("cannot create protected master-key file: {e}"))?;
    file.write_all(envelope)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("cannot write protected master-key file: {e}"))?;
    drop(file);
    fs::rename(&tmp, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("cannot commit protected master-key file: {e}")
    })
}

/// Recovery restore: make `envelope` the master key (passphrase-wrapped)
/// and drop any unwrapped key file it replaces.
pub fn install_protected_key(envelope: &[u8]) -> Result<(), String> {
    let _ = fs::remove_file(protected_master_key_path());
    write_protected_master_key(envelope)?;
    match fs::remove_file(master_key_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove old master key: {e}")),
    }
}

fn handle_lock(password: &[u8]) -> Response {
    if password.is_empty() {
        return Response::fail("password cannot be empty");
    }
    if protected_master_key_path().exists() {
        return Response::fail("credential store is already password protected");
    }
    let key = match crypto::snapshot_key() {
        Ok(key) => key,
        Err(e) => return Response::fail(e),
    };
    let envelope = match key_unlock::wrap(&key, password) {
        Ok(envelope) => envelope,
        Err(e) => return Response::fail(e),
    };
    if let Err(e) = write_protected_master_key(&envelope) {
        return Response::fail(e);
    }
    if let Err(e) = fs::remove_file(master_key_path()) {
        let _ = fs::remove_file(protected_master_key_path());
        return Response::fail(format!("cannot remove old master key: {e}"));
    }
    if let Err(e) = crypto::lock_backend() {
        return Response::fail(e);
    }
    Response::LockedOk
}

fn handle_unlock(password: &[u8]) -> Response {
    if password.is_empty() {
        return Response::fail("password cannot be empty");
    }
    let envelope = match fs::read(protected_master_key_path()) {
        Ok(envelope) => envelope,
        Err(_) => return Response::fail("credential store is not password protected"),
    };
    let key = match key_unlock::unwrap(&envelope, password) {
        Ok(key) => key,
        Err(e) => return Response::fail(e),
    };
    match crypto::unlock_backend(*key) {
        Ok(()) => Response::UnlockedOk,
        Err(e) => Response::fail(e),
    }
}

/// System-mode gate: only uid 0 may lock or unlock the shared master key.
fn require_root_in_system_mode(uid: u32, op: &'static str, username: &str) -> Option<Response> {
    if !user_mode() && uid != 0 {
        audit::log(&AuditEvent {
            op,
            name: None,
            uid,
            username,
            result: AuditResult::Fail("unauthorized: root required in system mode".to_string()),
        });
        return Some(Response::fail(
            "only root may lock or unlock the shared credential store",
        ));
    }
    None
}

pub fn handle_lock_gated(uid: u32, username: &str, password: &[u8]) -> Response {
    if let Some(denied) = require_root_in_system_mode(uid, "lock", username) {
        return denied;
    }
    let response = handle_lock(password);
    audit::log(&AuditEvent {
        op: "lock",
        name: None,
        uid,
        username,
        result: match &response {
            Response::Err { error } => AuditResult::Fail(error.clone()),
            _ => AuditResult::Ok,
        },
    });
    response
}

pub fn handle_unlock_gated(uid: u32, username: &str, password: &[u8]) -> Response {
    if let Some(denied) = require_root_in_system_mode(uid, "unlock", username) {
        return denied;
    }
    let response = handle_unlock(password);
    audit::log(&AuditEvent {
        op: "unlock",
        name: None,
        uid,
        username,
        result: match &response {
            Response::Err { error } => AuditResult::Fail(error.clone()),
            _ => AuditResult::Ok,
        },
    });
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_root_in_system_mode_never_denies_uid_zero() {
        // uid 0 must never be denied regardless of user_mode(), since the
        // condition is `!user_mode() && uid != 0` — this is the one branch
        // that doesn't depend on the process's own effective uid, so it's
        // safe to assert without root.
        assert!(require_root_in_system_mode(0, "lock", "root").is_none());
    }

    #[test]
    fn handle_lock_rejects_empty_password() {
        match handle_lock(b"") {
            Response::Err { error } => assert!(error.contains("empty")),
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn handle_unlock_rejects_empty_password() {
        match handle_unlock(b"") {
            Response::Err { error } => assert!(error.contains("empty")),
            other => panic!("expected Err, got {other:?}"),
        }
    }
}
