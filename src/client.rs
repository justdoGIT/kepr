// client.rs — CLI-side transport: framed JSON over Unix socket.

use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use kepr_core::framing::{read_frame, write_frame};
use kepr_core::protocol::{socket_path, Request, Response, MAX_MSG_BYTES, TIMEOUT_SECS};
use zeroize::Zeroizing;

/// May a value be sent to the process on the other end? In user mode only
/// the caller's own daemon, in system mode only root's. An explicitly
/// configured runtime directory may be controlled by another user, so the
/// client authenticates the daemon as well as the daemon checking the client.
fn trusted_peer(peer_uid: u32, own_uid: u32, system_mode: bool) -> bool {
    peer_uid == if system_mode { 0 } else { own_uid }
}

/// Connect, then check who answered (`SO_PEERCRED`).
fn connect_checked(socket: &std::path::Path) -> Option<UnixStream> {
    use kepr_core::auth::{PeerAuthenticator, PlatformPeerAuthenticator};
    use std::os::unix::io::AsRawFd;
    let stream = UnixStream::connect(socket).ok()?;
    let peer = PlatformPeerAuthenticator
        .authenticate(stream.as_raw_fd())
        .ok()?;
    // SAFETY: getuid(2) has no preconditions.
    let own = unsafe { libc::getuid() };
    trusted_peer(
        peer.uid,
        own,
        std::env::var_os("KEPR_SYSTEM_MODE").is_some(),
    )
    .then_some(stream)
}

fn connect_socket(start: bool) -> Result<UnixStream, String> {
    let socket = socket_path();
    if let Some(stream) = connect_checked(&socket) {
        return Ok(stream);
    }

    if start && std::env::var_os("KEPR_SYSTEM_MODE").is_none() {
        let _ = Command::new("kepr-daemon")
            .arg("--user")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        for _ in 0..40 {
            thread::sleep(Duration::from_millis(50));
            if let Some(stream) = connect_checked(&socket) {
                return Ok(stream);
            }
        }
    }

    Err(format!(
        "cannot connect to credential service at {}. \
         Start `kepr-daemon --user` or configure an approved system service",
        socket.display()
    ))
}

pub fn send_request(req: &Request) -> Result<Response, String> {
    send_over(connect_socket(true)?, req)
}

/// `send_request` to a daemon that is already running; never starts one
/// (T13.25: the PAM helpers run with a login's bare environment, and a
/// daemon started from it would miss the user's settings).
#[allow(dead_code)] // the credential helpers include this file too
pub fn send_existing(req: &Request) -> Result<Response, String> {
    send_over(connect_socket(false)?, req)
}

fn send_over(mut stream: UnixStream, req: &Request) -> Result<Response, String> {
    let timeout = Duration::from_secs(TIMEOUT_SECS);
    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
        eprintln!("kepr: warning: failed to set read timeout: {e}");
    }
    if let Err(e) = stream.set_write_timeout(Some(timeout)) {
        eprintln!("kepr: warning: failed to set write timeout: {e}");
    }

    let json = Zeroizing::new(
        serde_json::to_vec(req).map_err(|e| format!("request encoding error: {e}"))?,
    );

    exchange(&mut stream, &json)
}

fn exchange(stream: &mut UnixStream, json: &[u8]) -> Result<Response, String> {
    if let Err(e) = write_frame(stream, json) {
        // The daemon can refuse before reading the request (rate limit, not
        // the owner) and close; its reply is still readable, and it names
        // the real reason better than a broken pipe does.
        return match read_frame(stream, MAX_MSG_BYTES) {
            Ok(buf) => {
                serde_json::from_slice(&Zeroizing::new(buf)).map_err(|_| format!("send error: {e}"))
            }
            Err(_) => Err(format!("send error: {e}")),
        };
    }

    let buf = Zeroizing::new(
        read_frame(stream, MAX_MSG_BYTES).map_err(|e| format!("receive error: {e}"))?,
    );

    serde_json::from_slice(&buf).map_err(|e| format!("response decode error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_sent_before_the_request_is_read_still_arrives() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let reply = serde_json::to_vec(&Response::fail("rate limited")).unwrap();
        write_frame(&mut daemon, &reply).unwrap();
        drop(daemon);
        // Bigger than the socket buffer, so the write hits the closed peer.
        let big = vec![b' '; 4 << 20];
        match exchange(&mut client, &big) {
            Ok(Response::Err { error }) => assert_eq!(error, "rate limited"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_closed_socket_with_no_reply_is_a_send_error() {
        let (mut client, daemon) = UnixStream::pair().unwrap();
        drop(daemon);
        let err = exchange(&mut client, &vec![b' '; 4 << 20]).unwrap_err();
        assert!(err.starts_with("send error"), "{err}");
    }

    #[test]
    fn only_the_expected_uid_may_receive_a_request() {
        assert!(trusted_peer(1000, 1000, false), "own daemon in user mode");
        assert!(!trusted_peer(1001, 1000, false), "another user's socket");
        assert!(
            !trusted_peer(0, 1000, false),
            "root is not the user's daemon"
        );
        assert!(trusted_peer(0, 1000, true), "root's daemon in system mode");
        assert!(
            !trusted_peer(1000, 1000, true),
            "a user posing as the service"
        );
    }
}
