use std::os::unix::net::UnixStream;
use std::time::Duration;

use zeroize::Zeroizing;

use kepr_core::protocol::{Request, Response, MAX_MSG_BYTES};

use crate::daemon_peer::get_peer_creds;

pub fn handle_client(mut stream: UnixStream) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let Some(response) = receive(&stream) else {
        return;
    };
    let sent = serde_json::to_vec(&response)
        .map(Zeroizing::new)
        .ok()
        .is_some_and(|json| kepr_core::framing::write_frame(&mut stream, &json).is_ok());
    // Close a parked descriptor even when the frame could not be delivered.
    crate::daemon_session::fetchfd::send_pending(
        &stream,
        if sent { &response } else { &Response::Pong },
    );
}

fn receive(stream: &UnixStream) -> Option<Response> {
    let creds = get_peer_creds(stream)?;
    if crate::user_mode() && creds.uid != crate::daemon_socket::effective_uid() {
        return Some(Response::fail("permission denied"));
    }
    if !crate::rate_limiter().check(creds.uid) {
        return Some(Response::fail("rate limited"));
    }
    let mut reader = crate::daemon_socket::Deadline::new(stream, Duration::from_secs(5));
    let bytes = Zeroizing::new(kepr_core::framing::read_frame(&mut reader, MAX_MSG_BYTES).ok()?);
    let request = serde_json::from_slice::<Request>(&bytes).ok()?;
    drop(bytes);
    crate::daemon_session::idle::touch(&request);
    let username = crate::audit::username_for_uid(creds.uid);
    Some(crate::daemon_dispatch::dispatch(
        creds.uid, creds.pid, &username, request,
    ))
}
