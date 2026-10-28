// daemon_dispatch.rs — routes one parsed request to its handler. Split
// out of daemon.rs (LOC ceiling) so daemon.rs keeps to setup and the
// accept loop. Store-maintenance and reporting requests go on to
// daemon_extra.rs; the P2–P11 ticket batches route from there.

use kepr_core::protocol::{Request, Response};

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_audit::handle_audit_verify;
use crate::daemon_handlers::{handle_check, handle_set, SetFlags};
use crate::daemon_handlers_list::handle_list;
use crate::{
    audit_chain_path, daemon_extra, daemon_gate_registry, daemon_handlers_get, daemon_lock,
    daemon_ssh, fido2,
};

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, request: Request) -> Response {
    if let Some(denied) = crate::daemon_policy::enforce(uid, peer_pid, username, &request) {
        return denied; // T6.11 policy.toml
    }
    crate::daemon_session::unlock_wait::before(&request); // T13.25
    match request {
        Request::Lock { password } => {
            daemon_lock::handle_lock_gated(uid, peer_pid, username, password.as_bytes())
        }
        Request::Unlock { password } => {
            daemon_lock::handle_unlock_gated(uid, username, password.as_bytes())
        }
        Request::Panic => daemon_gate_registry::handle_panic(uid, username),
        Request::SshGenerate { .. }
        | Request::SshImport { .. }
        | Request::SshList
        | Request::SshSign { .. } => daemon_ssh::dispatch(uid, peer_pid, username, request),
        Request::Status => crate::daemon_session::status::handle(uid), // T11.24
        Request::Ping => {
            audit::log(&AuditEvent {
                op: "ping",
                name: None,
                uid,
                username,
                result: AuditResult::Ok,
            });
            Response::Pong
        }
        Request::Set {
            name,
            value,
            generate,
            ttl_secs,
            requires_consent,
            requires_fido2,
            sealed,
            bindings,
        } => handle_set(
            uid,
            username,
            &name,
            value.as_deref(),
            generate.as_deref(),
            SetFlags {
                ttl_secs,
                requires_consent,
                requires_fido2,
                sealed,
                bindings,
                ..Default::default()
            },
        ),
        Request::Get {
            name,
            fido2_assertion,
        } => daemon_handlers_get::handle_get(
            uid,
            peer_pid,
            username,
            &name,
            fido2_assertion.as_ref(),
        ),
        Request::List => handle_list(uid, username),
        Request::Delete { name } => crate::daemon_store::handle_rm(uid, username, &name),
        Request::Check => handle_check(uid, username),
        Request::AuditVerify => handle_audit_verify(uid, username, &audit_chain_path()),
        Request::Fido2Register {
            label,
            credential_id,
            public_key_cose,
        } => fido2::handle_register(
            (uid, peer_pid, username),
            &label,
            &credential_id,
            &public_key_cose,
        ),
        Request::Fido2List => {
            audit::log(&AuditEvent {
                op: "fido2-list",
                name: None,
                uid,
                username,
                result: AuditResult::Ok,
            });
            Response::Fido2ListOk {
                credentials: fido2::list_for_uid(uid),
            }
        }
        // History, restore, usage, health, leak response, recovery kit:
        // routed (and unknown variants refused) in daemon_extra.rs.
        other => daemon_extra::dispatch(uid, peer_pid, username, other),
    }
}
