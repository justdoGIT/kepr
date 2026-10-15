// daemon_session/fetchfd.rs — `FetchFd` (T3.06): a credential handed
// over as a sealed, read-only memfd instead of a value in the reply.
//
// The policy is `Get`'s, by calling it: validation, aliases, sealed /
// SSH / share-key refusal, expiry, re-authentication, consent and the
// `get` audit line. A FIDO2-gated credential is refused (this request
// carries no assertion). The memfd is created close-on-exec, so no
// process the daemon starts inherits it, and parked in a thread-local
// until daemon.rs has written the `FdOk` frame; `send_pending` then
// passes it on the same connection (SCM_RIGHTS) and closes ours.

use std::cell::RefCell;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use kepr_core::protocol::Response;
use kepr_core::protocol_session::SessionResponse;

thread_local! {
    /// The memfd for the reply this worker thread is about to send.
    static PENDING: RefCell<Option<OwnedFd>> = const { RefCell::new(None) };
}

fn park(fd: Option<OwnedFd>) {
    PENDING.with(|p| *p.borrow_mut() = fd);
}

pub fn handle(uid: u32, peer_pid: i32, username: &str, name: &str) -> Response {
    park(None);
    let value = match crate::daemon_handlers_get::handle_get(uid, peer_pid, username, name, None) {
        Response::GetOk { value, .. } => value,
        // Needs a FIDO2 touch, which only `kepr get` / `kepr exec` run.
        Response::Fido2Needed { .. } => return Response::fail("credential unavailable"),
        refusal => return refusal, // exactly what `Get` answered
    };
    let upper = name.to_uppercase();
    let r = kepr_core::memfd::create_sealed_memfd_cloexec(&upper, value.as_str().as_bytes());
    super::audit_op(
        "fetch-fd",
        Some(&upper),
        uid,
        username,
        r.as_ref().map(drop).map_err(String::as_str),
    );
    match r {
        Ok(fd) => {
            park(Some(fd));
            Response::Session(SessionResponse::FdOk {
                len: value.as_str().len() as u64,
            })
        }
        Err(_) => Response::fail("credential unavailable"),
    }
}

/// Called by daemon.rs after every reply: when it was `FdOk`, pass the
/// parked memfd on `stream`. Any parked fd is closed here either way, so
/// none outlives its own connection.
pub fn send_pending(stream: &UnixStream, response: &Response) {
    let Some(fd) = PENDING.with(|p| p.borrow_mut().take()) else {
        return;
    };
    if matches!(response, Response::Session(SessionResponse::FdOk { .. })) {
        if let Err(e) = kepr_core::fdpass::send_fd(stream, fd.as_raw_fd()) {
            eprintln!("[kepr-daemon] fetch-fd: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;
    use crate::expiry::{self, SshMeta};
    use crate::store::cred_path;
    use kepr_core::protocol_session::SessionRequest;

    fn fetch(uid: u32, name: &str) -> Response {
        let r = SessionRequest::FetchFd { name: name.into() };
        crate::daemon_session::dispatch(uid, 0, "t", r)
    }

    fn get(uid: u32, name: &str) -> Response {
        crate::daemon_handlers_get::handle_get(uid, 0, "t", name, None)
    }

    #[test]
    fn the_value_goes_out_as_a_sealed_fd_after_the_reply() {
        let uid = testkit::uid();
        testkit::set(uid, "FD_A", "fd-value-1");
        let resp = fetch(uid, "fd_a");
        assert!(matches!(
            resp,
            Response::Session(SessionResponse::FdOk { len: 10 })
        ));
        let (daemon, client) = UnixStream::pair().unwrap();
        send_pending(&daemon, &resp);
        let raw = kepr_core::fdpass::recv_fd(&client).unwrap().unwrap();
        // SAFETY: recv_fd handed us this descriptor.
        let fd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) };
        assert_eq!(
            kepr_core::fdfetch::read_value(&fd).unwrap().as_slice(),
            b"fd-value-1"
        );
        // SAFETY: F_GET_SEALS only reads descriptor state.
        let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
        assert_ne!(seals & libc::F_SEAL_WRITE, 0);
        assert!(
            PENDING.with(|p| p.borrow().is_none()),
            "nothing left parked"
        );
    }

    #[test]
    fn sealed_ssh_and_share_key_credentials_are_refused_like_get() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "FD_SEALED", "v");
        testkit::set(uid, "FD_SSH", "v");
        testkit::set(uid, "FD_SHARE", "v");
        let edit = |name: &str, f: &dyn Fn(&mut expiry::CredMeta)| {
            let mut m = testkit::meta(uid, name);
            f(&mut m);
            expiry::write_meta(&expiry::meta_path_for(&cred_path(uid, name)), &m).unwrap();
        };
        edit("FD_SSH", &|m| {
            m.ssh = Some(SshMeta {
                public_b64: "AAAA".into(),
                comment: "c".into(),
            })
        });
        edit("FD_SHARE", &|m| m.share_key = Some(true));
        for name in ["FD_SEALED", "FD_SSH", "FD_SHARE", "FD_MISSING", "bad-name"] {
            let (f, g) = (fetch(uid, name), get(uid, name));
            assert!(f.err_msg().is_some(), "{name}: {f:?}");
            assert_eq!(f.err_msg(), g.err_msg(), "{name}");
            assert!(PENDING.with(|p| p.borrow().is_none()), "{name}: no fd");
        }
        assert_eq!(
            fetch(uid, "FD_SSH").err_msg(),
            Some("credential unavailable")
        );
    }

    #[test]
    fn a_parked_fd_never_reaches_another_reply() {
        let uid = testkit::uid();
        testkit::set(uid, "FD_B", "v");
        assert!(fetch(uid, "FD_B").is_success());
        let (daemon, client) = UnixStream::pair().unwrap();
        send_pending(&daemon, &Response::Pong);
        assert!(PENDING.with(|p| p.borrow().is_none()), "dropped");
        drop(daemon);
        assert_eq!(kepr_core::fdpass::recv_fd(&client).unwrap(), None);
    }
}
