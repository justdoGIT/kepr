// daemon_session/ — the `session` ticket batch, daemon side: idle
// auto-lock (T11.12), unlock backoff and opt-in wipe (T11.13).

pub mod idle;
pub mod unlock_guard;

use crate::audit::{self, AuditEvent, AuditResult};

/// One audit line for a session-batch operation (op and name only).
pub(crate) fn audit_op(
    op: &'static str,
    name: Option<&str>,
    uid: u32,
    username: &str,
    r: Result<(), &str>,
) {
    audit::log(&AuditEvent {
        op,
        name,
        uid,
        username,
        result: match r {
            Ok(()) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.to_string()),
        },
    });
}
