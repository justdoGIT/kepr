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

pub fn get_peer_uid(stream: &UnixStream) -> Option<u32> {
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
        Some(cred.uid)
    } else {
        None
    }
}
