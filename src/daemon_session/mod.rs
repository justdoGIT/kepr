// daemon_session/ — the `session` ticket batch, daemon side: idle
// auto-lock (T11.12), unlock backoff and opt-in wipe (T11.13),
// re-authentication before reveal (T11.14), `kepr status` (T11.24).
// Requests arrive as `Request::Session` via daemon_extra.rs.

pub mod idle;
pub mod reauth;
pub mod status;
pub mod unlock_guard;

use kepr_core::protocol::Response;
use kepr_core::protocol_session::SessionRequest;

use crate::audit::{self, AuditEvent, AuditResult};

pub fn dispatch(uid: u32, _peer_pid: i32, username: &str, r: SessionRequest) -> Response {
    match r {
        SessionRequest::Reauth { name, passphrase } => {
            reauth::handle_reauth(uid, username, &name, &passphrase)
        }
        SessionRequest::ReauthFlag { name, on } => reauth::handle_flag(uid, username, &name, on),
    }
}

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
