// Unix socket client to the kepr daemon. Mirrors the main crate's
// client.rs — duplicated intentionally rather than moving to kepr-core
// to avoid a workspace refactor for Phase 2. Merge into kepr-core in
// Phase 3 when the client surface stabilises.

use std::os::unix::net::UnixStream;
use std::time::Duration;

use kepr_core::framing::{read_frame, write_frame};
use kepr_core::protocol::{socket_path, Request, Response, MAX_MSG_BYTES, TIMEOUT_SECS};

pub fn send_request(req: &Request) -> Result<Response, String> {
    let path = socket_path();
    let mut stream = UnixStream::connect(&path).map_err(|e| {
        format!(
            "cannot connect to kepr daemon at {}: {e}\n\
             Is kepr-daemon running? Run `kepr` once to start user mode.",
            path.display()
        )
    })?;

    let timeout = Duration::from_secs(TIMEOUT_SECS);
    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
        eprintln!("kepr-eso-provider: set_read_timeout failed: {e}");
    }
    if let Err(e) = stream.set_write_timeout(Some(timeout)) {
        eprintln!("kepr-eso-provider: set_write_timeout failed: {e}");
    }

    let json = serde_json::to_vec(req).map_err(|e| format!("encode: {e}"))?;
    write_frame(&mut stream, &json).map_err(|e| format!("send: {e}"))?;
    let buf = read_frame(&mut stream, MAX_MSG_BYTES).map_err(|e| format!("recv: {e}"))?;
    serde_json::from_slice(&buf).map_err(|e| format!("decode: {e}"))
}
