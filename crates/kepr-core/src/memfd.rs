//! Anonymous sealed memory file descriptor creation (`memfd`) for RAM-based secret delivery.
//!
//! Provides `create_sealed_memfd` which writes secret bytes into an in-memory
//! anonymous file, seals it against further writes, growth, shrinking, or unsealing,
//! and returns a raw file descriptor configured to be inherited across `exec`.

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
pub fn create_sealed_memfd(name: &str, secret: &[u8]) -> Result<RawFd, String> {
    let name_clean = name.replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_");
    let c_name = match std::ffi::CString::new(format!("kepr_{name_clean}")) {
        Ok(c) => c,
        Err(e) => return Err(format!("invalid memfd name: {e}")),
    };

    #[cfg(target_os = "linux")]
    {
        // MFD_CLOEXEC = 0x0001, MFD_ALLOW_SEALING = 0x0002
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
            let written = unsafe {
                libc::write(
                    fd,
                    secret.as_ptr() as *const libc::c_void,
                    secret.len(),
                )
            };
            if written < 0 || (written as usize) != secret.len() {
                let err = std::io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(format!("memfd write failed: {err}"));
            }
        }

        let seek_res = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
        if seek_res < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!("memfd lseek failed: {err}"));
        }

        // Apply read-only seals
        // F_SEAL_SEAL = 0x0001, F_SEAL_SHRINK = 0x0002, F_SEAL_GROW = 0x0004, F_SEAL_WRITE = 0x0008
        let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        let seal_res = unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) };
        if seal_res < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(format!("memfd sealing failed: {err}"));
        }

        // Clear FD_CLOEXEC so the descriptor is inherited across process exec
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        }

        Ok(fd)
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
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let write_res = file.write_all(b"override");
        assert!(write_res.is_err(), "write to sealed memfd must fail");
        std::mem::forget(file); // Don't close raw fd twice
        unsafe { libc::close(fd) };
    }
}
