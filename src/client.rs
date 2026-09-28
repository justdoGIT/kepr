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

    write_frame(&mut stream, &json).map_err(|e| format!("send error: {e}"))?;

    let buf = Zeroizing::new(
        read_frame(&mut stream, MAX_MSG_BYTES).map_err(|e| format!("receive error: {e}"))?,
    );

    serde_json::from_slice(&buf).map_err(|e| format!("response decode error: {e}"))
}
