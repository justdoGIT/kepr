// daemon_dispatch.rs — authenticated request handling for daemon connections.

use std::os::unix::net::UnixStream;

use kepr_core::framing::{read_frame, write_frame};
use kepr_core::protocol::{Request, Response, MAX_MSG_BYTES, TIMEOUT_SECS};

use crate::audit::{self, username_for_uid, AuditEvent, AuditResult};
use crate::daemon_audit::handle_audit_verify;
use crate::daemon_handlers::{handle_check, handle_delete, handle_list, handle_set};
use crate::daemon_peer::get_peer_creds;
use crate::daemon_socket::effective_uid;
use crate::{crypto, daemon_handlers_get, daemon_lock, fido2};

use super::{audit_chain_path, protected_master_key_path, rate_limiter, user_mode};

pub(crate) fn handle_client(mut stream: UnixStream) {
    let timeout = std::time::Duration::from_secs(TIMEOUT_SECS);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let (peer_pid, peer_uid) = match get_peer_creds(&stream) {
        Some(c) => (c.pid, c.uid),
        None => {
            send_error(&mut stream, "cannot verify caller identity");
            return;
        }
    };
    if user_mode() && peer_uid != effective_uid() {
        send_error(&mut stream, "caller is not the daemon owner");
        return;
    }
    if !rate_limiter().check(peer_uid) {
        // Reply immediately and return the worker to the pool. Sleeping here
        // would let a peer saturate every bounded worker with rejected calls.
        send_error(&mut stream, "rate limited");
        return;
    }

    let buf = match read_frame(&mut stream, MAX_MSG_BYTES) {
        Ok(b) => b,
        Err(_) => return,
    };

    let request: Request = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            send_error(&mut stream, &format!("invalid request: {e}"));
            return;
        }
    };

    let username = username_for_uid(peer_uid);
    let response = dispatch(peer_uid, peer_pid, &username, request);
    send_response(&mut stream, &response);
}

fn dispatch(uid: u32, peer_pid: i32, username: &str, request: Request) -> Response {
    match request {
        Request::Lock { password } => {
            daemon_lock::handle_lock_gated(uid, username, password.as_bytes())
        }
        Request::Unlock { password } => {
            daemon_lock::handle_unlock_gated(uid, username, password.as_bytes())
        }
        Request::Status => Response::StatusOk {
            locked: crypto::backend_is_locked(),
            password_protected: protected_master_key_path().exists(),
        },
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
        } => handle_set(
            uid,
            username,
            &name,
            value.as_deref(),
            generate.as_deref(),
            ttl_secs,
            requires_consent,
            requires_fido2,
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
        Request::Delete { name } => handle_delete(uid, username, &name),
        Request::Check => handle_check(uid, username),
        Request::AuditVerify => {
            let path = audit_chain_path();
            handle_audit_verify(uid, username, path.to_str().unwrap_or_default())
        }
        Request::Fido2Register {
            label,
            credential_id,
            public_key_cose,
        } => match fido2::register(uid, &label, &credential_id, &public_key_cose) {
            Ok(()) => {
                audit::log(&AuditEvent {
                    op: "fido2-register",
                    name: Some(&label),
                    uid,
                    username,
                    result: AuditResult::Ok,
                });
                Response::Fido2RegisterOk { credential_id }
            }
            Err(e) => {
                audit::log(&AuditEvent {
                    op: "fido2-register",
                    name: Some(&label),
                    uid,
                    username,
                    result: AuditResult::Fail(e.clone()),
                });
                Response::fail(e)
            }
        },
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
    }
}

fn send_response(stream: &mut UnixStream, response: &Response) {
    if let Ok(json) = serde_json::to_vec(response).map(zeroize::Zeroizing::new) {
        let _ = write_frame(stream, &json);
    }
}

fn send_error(stream: &mut UnixStream, message: &str) {
    send_response(stream, &Response::fail(message));
}
