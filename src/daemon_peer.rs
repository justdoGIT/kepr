// daemon_peer.rs — peer uid extraction via SO_PEERCRED.
//
// SO_PEERCRED returns the credentials captured at connect(2), so the uid
// here is the real uid of the connecting process — never trust a uid from
// a request payload.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

#[repr(C)]
struct UCred {
    pid: i32,
    uid: u32,
    gid: u32,
}

extern "C" {
    fn getsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *mut std::ffi::c_void,
        optlen: *mut u32,
    ) -> i32;
}

/// Peer credentials captured at connect-time via SO_PEERCRED.
/// `pid` is the kernel's view of which process opened the socket;
/// `uid` is the namespacing key the daemon uses for cred isolation.
/// Both are required for the polkit consent gate (Phase 2 ε) so
/// pkcheck authorises the actual caller, not the daemon.
#[derive(Debug, Clone, Copy)]
pub struct PeerCreds {
    pub pid: i32,
    pub uid: u32,
}

pub fn get_peer_creds(stream: &UnixStream) -> Option<PeerCreds> {
    let mut cred = UCred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<UCred>() as u32;
    // SOL_SOCKET = 1, SO_PEERCRED = 17 on Linux.
    let ret = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            1,
            17,
            &mut cred as *mut _ as *mut _,
            &mut len,
        )
    };
    if ret == 0 {
        Some(PeerCreds {
            pid: cred.pid,
            uid: cred.uid,
        })
    } else {
        None
    }
}

/// Backwards-compatible thin wrapper. Prefer `get_peer_creds`
/// for new code that needs the PID for polkit subjects.
pub fn get_peer_uid(stream: &UnixStream) -> Option<u32> {
    get_peer_creds(stream).map(|c| c.uid)
}
