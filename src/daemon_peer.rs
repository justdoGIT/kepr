// daemon_peer.rs — peer uid extraction via PeerAuthenticator.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use kepr_core::auth::{PeerAuthenticator, PlatformPeerAuthenticator};

/// Peer credentials captured at connect-time via PeerAuthenticator.
#[derive(Debug, Clone, Copy)]
pub struct PeerCreds {
    pub pid: i32,
    pub uid: u32,
}

pub fn get_peer_creds(stream: &UnixStream) -> Option<PeerCreds> {
    let authenticator = PlatformPeerAuthenticator;
    match authenticator.authenticate(stream.as_raw_fd()) {
        Ok(identity) => Some(PeerCreds {
            pid: identity.pid,
            uid: identity.uid,
        }),
        Err(_) => None,
    }
}

/// Backwards-compatible thin wrapper. Prefer `get_peer_creds`
/// for new code that needs the PID for polkit subjects.
pub fn get_peer_uid(stream: &UnixStream) -> Option<u32> {
    get_peer_creds(stream).map(|c| c.uid)
}
