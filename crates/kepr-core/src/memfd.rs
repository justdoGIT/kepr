//! Anonymous sealed memory file descriptor creation (`memfd`) for RAM-based secret delivery.
//!
//! Provides `create_sealed_memfd` which writes secret bytes into an in-memory
//! anonymous file, seals it against further writes, growth, shrinking, or unsealing,
//! and returns a raw file descriptor configured to be inherited across `exec`.

use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::io::RawFd;

/// Creates an anonymous sealed memory descriptor containing `secret` bytes.
///
/// On Linux:
/// 1. Calls `memfd_create("kepr_<name>", MFD_CLOEXEC | MFD_ALLOW_SEALING)`.
/// 2. Writes `secret` to the memfd.
/// 3. Repositions the offset to 0 (`lseek`).
/// 4. Applies seals: `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`.
/// 5. Clears `FD_CLOEXEC` on the raw FD so child processes retain access post-`exec`.
///
/// Returns the open `RawFd` on success.
///
/// Consumer contract: because `FD_CLOEXEC` is cleared, the descriptor is
/// inherited by the exec'd program *and by every child it spawns*. The
/// consumer must read the secret once and `close()` the fd before starting
/// subprocesses. Never hand these fds to programs that run arbitrary tools
/// (AI agent harnesses, shells): any child could read the secret.
pub fn create_sealed_memfd(name: &str, secret: &[u8]) -> Result<RawFd, String> {
    let fd = create_sealed_memfd_cloexec(name, secret)?.into_raw_fd();
    // Clear FD_CLOEXEC so the descriptor is inherited across process exec
    // SAFETY: `fd` is the open, sealed memfd from above; `fcntl`
    // (F_GETFD/F_SETFD) only reads/writes the descriptor's own flag
    // word and cannot invalidate it.
    // SAFETY: fcntl on an open descriptor only reads or writes its flag word.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags >= 0 {
        // SAFETY: fcntl on an open descriptor only reads or writes its flag word.
        unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    }
    Ok(fd)
}

/// Steps 1-4 of `create_sealed_memfd`: the descriptor stays
/// close-on-exec, so nothing this process starts inherits it. For
/// handing a secret over a socket (T3.06 `FetchFd`).
pub fn create_sealed_memfd_cloexec(name: &str, secret: &[u8]) -> Result<OwnedFd, String> {
    let name_clean = name.replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_");
    let c_name = match std::ffi::CString::new(format!("kepr_{name_clean}")) {
        Ok(c) => c,
        Err(e) => return Err(format!("invalid memfd name: {e}")),
    };

    #[cfg(target_os = "linux")]
    {
        // MFD_CLOEXEC = 0x0001, MFD_ALLOW_SEALING = 0x0002
        // SAFETY: `memfd_create` is a Linux-only syscall with no `libc`
        // wrapper (added in kernel 3.17, glibc added a wrapper later than
        // the MSRV floor this crate targets, so we go through
        // `libc::syscall` directly). `c_name` is a valid, NUL-terminated
        // `CString` owned by this function and outlives the call; the
        // flags are the two documented bit constants above. The syscall
        // returns either a valid new fd (>= 0) or -1 with `errno` set — no
        // aliasing or lifetime hazards are introduced by making the call.
        // SAFETY: memfd_create gets a valid NUL-terminated name and two documented flag bits.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c_name.as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        } as RawFd;

        if fd < 0 {
            return Err(format!(
                "memfd_create failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        if !secret.is_empty() {
            // SAFETY: `fd` was just returned by the successful
            // `memfd_create` call above and is not yet closed or aliased.
            // `secret.as_ptr()` is valid for `secret.len()` bytes for the
            // duration of this call (borrowed from the caller's slice).
            let written =
                // SAFETY: `secret` is valid for its length for the whole call.
                unsafe { libc::write(fd, secret.as_ptr() as *const libc::c_void, secret.len()) };
            if written < 0 || (written as usize) != secret.len() {
                let err = std::io::Error::last_os_error();
                // SAFETY: `fd` is the sole owner of this memfd at this
                // point (never duplicated or handed to another owner);
                // closing it once here and returning is the error-cleanup
                // path, so no double-close or use-after-close follows.
                // SAFETY: closing a descriptor this code owns and does not use again.
                unsafe { libc::close(fd) };
                return Err(format!("memfd write failed: {err}"));
            }
        }

        // SAFETY: `fd` is the open memfd from above; `lseek` only repositions
        // its cursor and cannot invalidate the descriptor.
        let seek_res = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
        if seek_res < 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: see the write-failure cleanup path above — single,
            // terminal close of an fd we still exclusively own.
            unsafe { libc::close(fd) };
            return Err(format!("memfd lseek failed: {err}"));
        }

        // Apply read-only seals
        // F_SEAL_SEAL = 0x0001, F_SEAL_SHRINK = 0x0002, F_SEAL_GROW = 0x0004, F_SEAL_WRITE = 0x0008
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        // SAFETY: `fd` is the open memfd from above; `fcntl(F_ADD_SEALS)`
        // only mutates kernel-side seal state for this inode, no memory
        // hazard on our side.
        // SAFETY: fcntl(F_ADD_SEALS) only changes kernel-side seal state.
        let seal_res = unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) };
        if seal_res < 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: see the write-failure cleanup path above.
            unsafe { libc::close(fd) };
            return Err(format!("memfd sealing failed: {err}"));
        }

        // SAFETY: `fd` is the open, sealed memfd from above, owned only here.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = c_name;
        let _ = secret;
        Err("memfd RAM delivery requires Linux 3.17+".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::fd::FromRawFd;
    #[test]
    #[cfg(target_os = "linux")]
    fn test_create_sealed_memfd() {
        let secret = b"test_secret_ram_token_12345";
        let fd = create_sealed_memfd("TEST_KEY", secret).expect("memfd creation failed");

        assert!(fd >= 0, "fd should be valid positive integer");

        // Verify content by reading /proc/self/fd/<fd>
        let path = format!("/proc/self/fd/{fd}");
        let read_bytes = fs::read(&path).expect("failed to read from proc self fd");
        assert_eq!(read_bytes, secret);

        // Verify seals by attempting to write (must fail with EPERM / EBADF)
        // SAFETY: test only; `fd` is open and owned here, forgotten below so it is not closed twice.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let write_res = file.write_all(b"override");
        assert!(write_res.is_err(), "write to sealed memfd must fail");
        std::mem::forget(file); // Don't close raw fd twice
                                // SAFETY: closing a descriptor this code owns and does not use again.
        unsafe { libc::close(fd) };
    }
}
