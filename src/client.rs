// client.rs — CLI-side transport: framed JSON over Unix socket.

use std::os::unix::net::UnixStream;
use std::time::Duration;

use kepr_core::framing::{read_frame, write_frame};
use kepr_core::protocol::{Request, Response, MAX_MSG_BYTES, SOCKET_PATH, TIMEOUT_SECS};

pub fn send_request(req: &Request) -> Result<Response, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH).map_err(|e| {
        format!(
            "cannot connect to credential service: {e}\n  \
             Is kepr-daemon running? Check: systemctl status kepr"
        )
    })?;

    let timeout = Duration::from_secs(TIMEOUT_SECS);
    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
        eprintln!("kepr: warning: failed to set read timeout: {e}");
    }
    if let Err(e) = stream.set_write_timeout(Some(timeout)) {
        eprintln!("kepr: warning: failed to set write timeout: {e}");
    }

    let json = serde_json::to_vec(req).map_err(|e| format!("request encoding error: {e}"))?;

    write_frame(&mut stream, &json).map_err(|e| format!("send error: {e}"))?;

    let buf = read_frame(&mut stream, MAX_MSG_BYTES).map_err(|e| format!("receive error: {e}"))?;

    serde_json::from_slice(&buf).map_err(|e| format!("response decode error: {e}"))
}
