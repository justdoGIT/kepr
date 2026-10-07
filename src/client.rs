// client.rs — CLI-side transport: framed JSON over Unix socket.

use std::os::unix::net::UnixStream;
use std::process::Command;
use std::thread;
use std::time::Duration;

use kepr_core::framing::{read_frame, write_frame};
use kepr_core::protocol::{socket_path, Request, Response, MAX_MSG_BYTES, TIMEOUT_SECS};
use zeroize::Zeroizing;

fn connect_socket() -> Result<UnixStream, String> {
    let socket = socket_path();
    if let Ok(stream) = UnixStream::connect(&socket) {
        return Ok(stream);
    }

    if std::env::var_os("KEPR_SYSTEM_MODE").is_none() {
        let _ = Command::new("kepr-daemon").arg("--user").spawn();
        for _ in 0..40 {
            thread::sleep(Duration::from_millis(50));
            if let Ok(stream) = UnixStream::connect(&socket) {
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
    let mut stream = connect_socket()?;

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
}
