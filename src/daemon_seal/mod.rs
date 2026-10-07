// daemon_seal/ — the `seal` ticket batch, daemon side: how the master key
// is protected at rest and recovered.
// batch: seal
//
//   recovery   T4.10 recovery words (create / restore), fenced like the
//              recovery kit in daemon_recovery.rs

mod recovery;

use kepr_core::protocol::Response;
use kepr_core::protocol_seal::SealRequest;

use crate::audit::{self, AuditEvent, AuditResult};

pub fn dispatch(uid: u32, _peer_pid: i32, username: &str, request: SealRequest) -> Response {
    match request {
        SealRequest::RecoveryWordsCreate { password } => {
            recovery::handle_create(uid, username, password.as_bytes())
        }
        SealRequest::RecoveryWordsRestore {
            words,
            new_password,
        } => recovery::handle_restore(uid, username, &words, new_password.as_bytes()),
    }
}

/// One audit line (op only; never a value or a key).
fn audit_result(op: &'static str, uid: u32, username: &str, r: &Result<(), String>) {
    audit::log(&AuditEvent {
        op,
        name: None,
        uid,
        username,
        result: match r {
            Ok(()) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}
