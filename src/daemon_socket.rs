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
    // SAFETY: geteuid has no preconditions and cannot fail.
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
    // SAFETY: the umask call only swaps the process's file-creation mask.
    unsafe {
        umask(0o117);
    }
}

/// After the socket exists: everything else the daemon creates (meta
/// sidecars, audit log, state files) is private, so use a 0077 umask
/// rather than leaving the socket's group-friendly 0117 in force.
pub fn private_umask_after_bind() {
    // SAFETY: the umask call only swaps the process's file-creation mask.
    unsafe {
        umask(0o077);
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
            // SAFETY: `path` is a valid NUL-terminated string that outlives the call.
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

/// A reader with one deadline for the whole request, not per `read`:
/// the socket's own timeout restarts on every byte, so a client sending
/// one byte every few seconds could hold a worker forever.
pub struct Deadline<'a> {
    stream: &'a std::os::unix::net::UnixStream,
    until: std::time::Instant,
}

impl<'a> Deadline<'a> {
    pub fn new(stream: &'a std::os::unix::net::UnixStream, limit: std::time::Duration) -> Self {
        Self {
            stream,
            until: std::time::Instant::now() + limit,
        }
    }
}

impl std::io::Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self
            .until
            .saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        (&mut &*self.stream).read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_later_byte_does_not_restart_the_request_deadline() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut reader = Deadline::new(&receiver, Duration::from_millis(50));
        sender.write_all(b"a").unwrap();
        let mut byte = [0];
        reader.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"a");
        std::thread::sleep(Duration::from_millis(75));
        sender.write_all(b"b").unwrap();
        assert_eq!(
            reader.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    fn current_umask() -> u32 {
        // umask(2) atomically swaps and returns the previous mask. Set-and-
        // restore is the standard idiom to read it without changing it.
        // SAFETY: the umask call only swaps the process's file-creation mask.
        let prev = unsafe { umask(0) };
        // SAFETY: the umask call only swaps the process's file-creation mask.
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
        // SAFETY: the umask call only swaps the process's file-creation mask.
        let _ = unsafe { umask(saved) };
        assert_eq!(
            after, 0o117,
            "tighten_umask_for_socket must leave the process umask at 0117"
        );
    }
}
