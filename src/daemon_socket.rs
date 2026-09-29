// daemon_socket.rs — Unix socket path/permissions setup and minimal FFI.
//
// The daemon owns the socket at /run/kepr/kepr.sock (root:kepr 0660).
// Only members of the `kepr` group can connect.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use kepr_core::protocol::{socket_dir, socket_path};

extern "C" {
    fn geteuid() -> u32;
    fn chown(path: *const i8, owner: u32, group: u32) -> i32;
    fn umask(mask: u32) -> u32;
}

pub fn effective_uid() -> u32 {
    unsafe { geteuid() }
}

/// Tighten the process umask before binding the listening socket so the
/// inode is created at 0660 from the moment `bind(2)` returns.
///
/// `bind(2)` materialises the socket with `0666 & ~umask`, and only after
/// that do the explicit `chown` + `chmod` calls in `set_socket_permissions`
/// run. With a permissive ambient umask (anyone overriding the systemd
/// default of 0022 — `UMask=0000`, a non-systemd launcher, a manual
/// invocation under sudo) that window leaves the socket world-connectable
/// until the chmod lands. Setting umask to 0117 collapses the window:
/// the socket arrives at `root:root 0660`, and the subsequent chown to
/// `root:kepr` is the only remaining transition before kepr-group
/// processes can connect.
pub fn tighten_umask_for_socket() {
    unsafe {
        umask(0o117);
    }
}

pub fn setup_socket_dir() {
    let dir = socket_dir();
    fs::create_dir_all(&dir).expect("cannot create socket dir");
    let mode = if std::env::var_os("KEPR_USER_MODE").is_some() {
        0o700
    } else {
        0o755
    };
    fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).expect("cannot chmod socket dir");
}

pub fn set_socket_permissions() {
    let socket = socket_path();
    let user = std::env::var_os("KEPR_USER_MODE").is_some();
    if !user {
        if let Ok(path) = CString::new(socket.as_os_str().as_encoded_bytes()) {
            unsafe {
                chown(path.as_ptr(), 0, group_gid("kepr").unwrap_or(0));
            }
        }
    }
    fs::set_permissions(
        &socket,
        fs::Permissions::from_mode(if user { 0o600 } else { 0o660 }),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn current_umask() -> u32 {
        // umask(2) atomically swaps and returns the previous mask. Set-and-
        // restore is the standard idiom to read it without changing it.
        let prev = unsafe { umask(0) };
        unsafe {
            umask(prev);
        }
        prev
    }

    #[test]
    fn tighten_umask_sets_0117() {
        let saved = current_umask();
        tighten_umask_for_socket();
        let after = current_umask();
        // Restore before any assertion so a panic doesn't leak a tightened
        // mask into sibling tests sharing the test process.
        let _ = unsafe { umask(saved) };
        assert_eq!(
            after, 0o117,
            "tighten_umask_for_socket must leave the process umask at 0117"
        );
    }
}
