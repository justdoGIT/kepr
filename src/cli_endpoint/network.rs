//! The scanner may not use mounted Unix sockets or io_uring to escape locality.
use std::os::fd::OwnedFd;

pub fn program() -> Vec<libc::sock_filter> {
    let mut denied = kepr_core::seccomp::sandbox_denied();
    denied.extend([
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_pidfd_getfd,
        libc::SYS_open_by_handle_at,
        libc::SYS_userfaultfd,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_setns,
        libc::SYS_unshare,
    ]);
    kepr_core::seccomp::program(&denied)
}

pub fn filter_fd() -> Result<OwnedFd, String> {
    let mut bytes = Vec::new();
    for instruction in program() {
        bytes.extend_from_slice(&instruction.code.to_ne_bytes());
        bytes.extend_from_slice(&[instruction.jt, instruction.jf]);
        bytes.extend_from_slice(&instruction.k.to_ne_bytes());
    }
    kepr_core::memfd::create_sealed_memfd_cloexec("endpoint_filter", &bytes)
        .map_err(|_| "scanner network filter is unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_filter_denies_unix_and_internet_socket_creation() {
        let program = program();
        // SAFETY: the child runs raw syscalls and _exit only after installation.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let mut code = 0;
            if kepr_core::seccomp::install(&program).is_err() {
                code = 2;
            } else {
                for family in [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6] {
                    // SAFETY: socket has documented scalar arguments.
                    let result = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
                    if result != -1
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                    {
                        code = 1;
                    }
                }
            }
            // SAFETY: no child destructors may run after fork.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: this waits for the child created above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
