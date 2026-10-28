// daemon_session/ — the `session` ticket batch, daemon side: idle
// auto-lock (T11.12), unlock backoff and opt-in wipe (T11.13),
// re-authentication before reveal (T11.14), `kepr status` (T11.24),
// profiles (T11.16), `kepr ssh rotate` commit (T11.21), `GetQuiet` for
// `kepr serve` (T11.19), `FetchFd` (T3.06), unlock at login, waiting for
// an unlock and passphrase change (T13.25). Requests arrive
// as `Request::Session` via daemon_extra.rs.

pub mod fetchfd;
pub mod idle;
pub mod login;
pub mod quiet;
pub mod reauth;
pub mod ssh_rotate;
pub mod status;
pub mod unlock_guard;
pub mod unlock_wait;

use kepr_core::protocol::Response;
use kepr_core::protocol_session::SessionRequest;

use crate::audit::{self, AuditEvent, AuditResult};

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, r: SessionRequest) -> Response {
    match r {
        SessionRequest::Reauth { name, passphrase } => {
            reauth::handle_reauth(uid, username, &name, &passphrase)
        }
        SessionRequest::ReauthFlag { name, on } => reauth::handle_flag(uid, username, &name, on),
        SessionRequest::SshRotateCommit { name, next } => {
            ssh_rotate::handle_commit(uid, username, &name, &next)
        }
        SessionRequest::GetQuiet { name } => {
            quiet::handle_get_quiet(uid, peer_pid, username, &name)
        }
        SessionRequest::FetchFd { name } => fetchfd::handle(uid, peer_pid, username, &name),
        SessionRequest::LoginUnlock { password } => {
            login::handle_login_unlock(uid, username, password.as_bytes())
        }
        SessionRequest::ChangePassphrase { old, new, login } => {
            login::handle_change(uid, username, (old.as_bytes(), new.as_bytes()), login)
        }
    }
}

/// T11.16: refuse to start with an invalid `KEPR_PROFILE` (or one in
/// system mode) instead of serving some other store.
pub fn check_profile_or_exit() {
    match kepr_core::profile::current() {
        Ok(Some(p)) => eprintln!("[kepr-daemon] profile: {p}"),
        Ok(None) => {}
        Err(e) => {
            eprintln!("[kepr-daemon] {e}");
            std::process::exit(1);
        }
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
