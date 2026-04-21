// daemon_socket.rs — Unix socket path/permissions setup and minimal FFI.
//
// The daemon owns the socket at /run/kepr/kepr.sock (root:kepr 0660).
// Only members of the `kepr` group can connect.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::protocol::{SOCKET_DIR, SOCKET_PATH};

extern "C" {
    fn geteuid() -> u32;
    fn chown(path: *const i8, owner: u32, group: u32) -> i32;
}

pub fn effective_uid() -> u32 {
    unsafe { geteuid() }
}

pub fn setup_socket_dir() {
    fs::create_dir_all(SOCKET_DIR).expect("cannot create socket dir");
    fs::set_permissions(SOCKET_DIR, fs::Permissions::from_mode(0o755))
        .expect("cannot chmod socket dir");
}

pub fn set_socket_permissions() {
    // Get gid of 'kepr' group; fall back to root if missing.
    let gid = group_gid("kepr").unwrap_or(0);

    if let Ok(path) = CString::new(SOCKET_PATH) {
        unsafe {
            chown(path.as_ptr(), 0, gid);
        }
    }

    fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o660))
        .expect("cannot chmod socket");
}

fn group_gid(name: &str) -> Option<u32> {
    let content = fs::read_to_string("/etc/group").ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[0] == name {
            return fields[2].parse().ok();
        }
    }
    None
}
