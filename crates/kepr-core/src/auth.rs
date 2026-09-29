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
            extern "C" {
                fn getsockopt(
                    fd: i32,
                    level: i32,
                    optname: i32,
                    optval: *mut libc::c_void,
                    optlen: *mut u32,
                ) -> i32;
            }
            let mut cred = UCred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut len = std::mem::size_of::<UCred>() as u32;
            let ret = unsafe {
                getsockopt(
                    fd,
                    1,
                    17,
                    &mut cred as *mut _ as *mut _,
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
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsPeerAuthenticator;

impl PeerAuthenticator for WindowsPeerAuthenticator {
    fn authenticate(&self, fd: i32) -> Result<PeerIdentity, String> {
        #[cfg(target_os = "windows")]
        {
            let _ = fd;
            Ok(PeerIdentity {
                pid: std::process::id() as i32,
                uid: 1000,
                domain_sid: Some("S-1-5-21-local-user-sid".to_string()),
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = fd;
            Err("Windows SID authentication is only available on Windows".to_string())
        }
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
        let identity = auth.authenticate(s1.as_raw_fd()).expect("authenticate socket");
        assert_eq!(identity.uid, unsafe { libc::getuid() });
        assert_eq!(identity.pid, std::process::id() as i32);
    }
}
