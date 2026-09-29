//! Cross-platform peer authentication trait and OS-specific implementations.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub pid: i32,
    pub uid: u32,
    pub domain_sid: Option<String>,
}

/// Abstract peer authenticator for IPC streams and Unix sockets.
pub trait PeerAuthenticator: Send + Sync {
    fn authenticate(&self, fd: i32) -> Result<PeerIdentity, String>;
}

/// Linux `SO_PEERCRED` authenticator.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxPeerAuthenticator;

impl PeerAuthenticator for LinuxPeerAuthenticator {
    fn authenticate(&self, fd: i32) -> Result<PeerIdentity, String> {
        #[cfg(target_os = "linux")]
        {
            #[repr(C)]
            struct UCred {
                pid: i32,
                uid: u32,
                gid: u32,
            }
            let mut cred = UCred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut len = std::mem::size_of::<UCred>() as libc::socklen_t;
            // SAFETY: `fd` is a caller-owned, open socket file descriptor
            // (the accepted end of a `UnixStream`) valid for the duration of
            // this call. `cred` is a stack-local `UCred` sized exactly to
            // the kernel's `struct ucred` layout, and `len` starts at that
            // exact size, so the kernel writes at most `size_of::<UCred>()`
            // bytes into `cred` — no buffer overrun regardless of which
            // architecture's `SO_PEERCRED` numeric value is in effect.
            let ret = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut UCred as *mut libc::c_void,
                    &mut len,
                )
            };
            if ret == 0 {
                Ok(PeerIdentity {
                    pid: cred.pid,
                    uid: cred.uid,
                    domain_sid: None,
                })
            } else {
                Err(format!(
                    "getsockopt SO_PEERCRED failed: {}",
                    std::io::Error::last_os_error()
                ))
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = fd;
            Err("SO_PEERCRED is only available on Linux".to_string())
        }
    }
}

/// macOS `LOCAL_PEERCRED` / `getpeereid` authenticator.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacOSPeerAuthenticator;

impl PeerAuthenticator for MacOSPeerAuthenticator {
    fn authenticate(&self, fd: i32) -> Result<PeerIdentity, String> {
        #[cfg(target_os = "macos")]
        {
            let mut uid: u32 = 0;
            let mut gid: u32 = 0;
            extern "C" {
                fn getpeereid(s: i32, euid: *mut u32, egid: *mut u32) -> i32;
            }
            let ret = unsafe { getpeereid(fd, &mut uid, &mut gid) };
            if ret == 0 {
                Ok(PeerIdentity {
                    pid: 0,
                    uid,
                    domain_sid: None,
                })
            } else {
                Err(format!(
                    "getpeereid failed: {}",
                    std::io::Error::last_os_error()
                ))
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = fd;
            Err("LOCAL_PEERCRED / getpeereid is only available on macOS".to_string())
        }
    }
}

/// Windows Named Pipe SID authenticator.
///
/// NOT YET IMPLEMENTED: real SID extraction requires
/// `GetNamedPipeClientProcessId` + `OpenProcessToken` +
/// `GetTokenInformation(TokenUser)` FFI against the Win32 API, which is
/// unverified in this codebase (no Windows CI runner). Fails closed
/// rather than fabricating a `PeerIdentity` — returning a made-up uid/SID
/// here would silently defeat the peer-isolation guarantee this trait
/// exists to provide.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsPeerAuthenticator;

impl PeerAuthenticator for WindowsPeerAuthenticator {
    fn authenticate(&self, fd: i32) -> Result<PeerIdentity, String> {
        let _ = fd;
        Err("Windows named-pipe SID authentication is not yet implemented".to_string())
    }
}

/// Default platform-aware peer authenticator.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformPeerAuthenticator;

impl PeerAuthenticator for PlatformPeerAuthenticator {
    fn authenticate(&self, fd: i32) -> Result<PeerIdentity, String> {
        #[cfg(target_os = "linux")]
        {
            LinuxPeerAuthenticator.authenticate(fd)
        }
        #[cfg(target_os = "macos")]
        {
            MacOSPeerAuthenticator.authenticate(fd)
        }
        #[cfg(target_os = "windows")]
        {
            WindowsPeerAuthenticator.authenticate(fd)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = fd;
            Err("Unsupported OS for peer authentication".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_peer_authenticator() {
        use std::os::unix::io::AsRawFd;
        let (s1, _s2) = UnixStream::pair().expect("unix stream pair");
        let auth = PlatformPeerAuthenticator;
        let identity = auth
            .authenticate(s1.as_raw_fd())
            .expect("authenticate socket");
        assert_eq!(identity.uid, unsafe { libc::getuid() });
        assert_eq!(identity.pid, std::process::id() as i32);
    }
}
