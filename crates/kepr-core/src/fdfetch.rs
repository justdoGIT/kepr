//! T3.06 pull-on-demand fd delivery, client side: a cooperating process
//! fetches one credential as a sealed, read-only memfd over the daemon
//! socket instead of inheriting it. The descriptor arrives close-on-exec
//! (`MSG_CMSG_CLOEXEC`), so nothing the process starts afterwards gets
//! it; read it (`read_value`) and drop it.
//!
//! ```no_run
//! let fd = kepr_core::fdfetch::fetch("DB_PASSWORD")?;
//! let value = kepr_core::fdfetch::read_value(&fd)?;
//! # Ok::<(), String>(())
//! ```
//!
//! `kepr exec --pull NAME[,NAME…] -- CMD` lists the names in `KEPR_PULL`
//! (`pulled()`). The daemon applies `Get`'s policy: sealed, SSH and
//! share-key credentials are refused the same way, and nothing prompts
//! (consent, FIDO2 and re-authentication refuse instead).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::framing::{read_frame, write_frame};
use crate::protocol::{Request, Response, MAX_MSG_BYTES, TIMEOUT_SECS};
use crate::protocol_session::{SessionRequest, SessionResponse};

/// Set by `kepr exec --pull`: the names the program may fetch.
pub const ENV: &str = "KEPR_PULL";

/// Fetch `name` from the daemon this environment points at.
pub fn fetch(name: &str) -> Result<OwnedFd, String> {
    fetch_at(&crate::protocol::socket_path(), name)
}

pub fn fetch_at(socket: &Path, name: &str) -> Result<OwnedFd, String> {
    let s = UnixStream::connect(socket).map_err(|e| format!("daemon unreachable: {e}"))?;
    let t = Some(Duration::from_secs(TIMEOUT_SECS));
    s.set_read_timeout(t)
        .and_then(|()| s.set_write_timeout(t))
        .map_err(|e| format!("socket timeout: {e}"))?;
    exchange(&s, name)
}

/// One `FetchFd` round trip on a connected daemon socket: the `FdOk`
/// frame, then the descriptor.
pub fn exchange(s: &UnixStream, name: &str) -> Result<OwnedFd, String> {
    let req = Request::Session(SessionRequest::FetchFd {
        name: name.to_uppercase(),
    });
    let json = serde_json::to_vec(&req).map_err(|e| format!("request encoding error: {e}"))?;
    write_frame(&mut &*s, &json).map_err(|e| format!("send error: {e}"))?;
    // Exactly one frame: the descriptor rides on the byte after it.
    let buf = read_frame(&mut &*s, MAX_MSG_BYTES).map_err(|e| format!("receive error: {e}"))?;
    let len = match serde_json::from_slice::<Response>(&buf) {
        Ok(Response::Session(SessionResponse::FdOk { len })) => len,
        Ok(other) => {
            return Err(other
                .err_msg()
                .unwrap_or("unexpected daemon response")
                .to_string())
        }
        Err(e) => return Err(format!("response decode error: {e}")),
    };
    let raw = crate::fdpass::recv_fd(s)?.ok_or("the daemon sent no descriptor")?;
    // SAFETY: recv_fd just handed us this descriptor; nothing else owns it.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    check(&fd, len)?;
    Ok(fd)
}

/// It must be what `FdOk` promised: `len` bytes, sealed against writes
/// and resizing.
fn check(fd: &OwnedFd, len: u64) -> Result<(), String> {
    let need = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;
    // SAFETY: F_GET_SEALS only reads the seal set of an open descriptor.
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    // SAFETY: an all-zero `stat` is a valid value of this plain C struct.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat writes into the stack-local `st` it is given.
    let stat_ok = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0;
    if seals < 0 || seals & need != need || !stat_ok || st.st_size as u64 != len {
        return Err("the daemon sent an unexpected descriptor".into());
    }
    Ok(())
}

/// The whole value, read from offset 0 (the descriptor's own offset is
/// left alone); wiped when dropped.
pub fn read_value(fd: &OwnedFd) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut out = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        // SAFETY: pread writes at most `chunk.len()` bytes into `chunk`.
        let n = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                chunk.as_mut_ptr().cast(),
                chunk.len(),
                out.len() as libc::off_t,
            )
        };
        match n {
            0 => return Ok(out),
            n if n > 0 => out.extend_from_slice(&chunk[..n as usize]),
            _ => return Err(format!("read: {}", std::io::Error::last_os_error())),
        }
    }
}

/// The names in `KEPR_PULL`, in order.
pub fn pulled() -> Vec<String> {
    std::env::var(ENV)
        .map(|v| parse_list(&v))
        .unwrap_or_default()
}

pub fn parse_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memfd::create_sealed_memfd_cloexec;

    /// A daemon on the other end of a socket pair: checks the request,
    /// answers `reply`, then sends `fd` if there is one.
    fn daemon(reply: Response, fd: Option<OwnedFd>) -> UnixStream {
        let (client, server) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let req = read_frame(&mut &server, MAX_MSG_BYTES).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&req).unwrap();
            assert_eq!(v, serde_json::json!({"cmd": "fetch_fd", "name": "DB"}));
            write_frame(&mut &server, &serde_json::to_vec(&reply).unwrap()).unwrap();
            if let Some(fd) = fd {
                crate::fdpass::send_fd(&server, fd.as_raw_fd()).unwrap();
            }
            server
        });
        client
    }

    fn fd_ok(value: &[u8]) -> (Response, Option<OwnedFd>) {
        let fd = create_sealed_memfd_cloexec("DB", value).unwrap();
        let len = value.len() as u64;
        (Response::Session(SessionResponse::FdOk { len }), Some(fd))
    }

    #[test]
    fn the_fd_is_sealed_close_on_exec_and_holds_the_value() {
        let (reply, fd) = fd_ok(b"pa55word");
        let fd = exchange(&daemon(reply, fd), "db").unwrap();
        // SAFETY: F_GETFD / F_GET_SEALS only read descriptor state.
        let (flags, seals) = unsafe {
            (
                libc::fcntl(fd.as_raw_fd(), libc::F_GETFD),
                libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS),
            )
        };
        assert_ne!(flags & libc::FD_CLOEXEC, 0, "FD_CLOEXEC set");
        assert_ne!(seals & libc::F_SEAL_WRITE, 0, "F_SEAL_WRITE set");
        assert_eq!(read_value(&fd).unwrap().as_slice(), b"pa55word");
        assert_eq!(read_value(&fd).unwrap().as_slice(), b"pa55word", "again");
        // SAFETY: writing to the sealed memfd must fail, not corrupt it.
        let w = unsafe { libc::write(fd.as_raw_fd(), b"x".as_ptr().cast(), 1) };
        assert_eq!(w, -1);
    }

    #[test]
    fn a_child_started_after_the_fetch_cannot_read_it() {
        let (reply, fd) = fd_ok(b"child-must-not-see");
        let fd = exchange(&daemon(reply, fd), "DB").unwrap();
        let n = fd.as_raw_fd();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("readlink /proc/self/fd/{n}; cat /proc/self/fd/{n}"))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!out.status.success(), "{text}");
        assert!(!text.contains("memfd:") && !text.contains("child-must-not-see"));
        // While this process still can.
        let own = std::fs::read(format!("/proc/self/fd/{n}")).unwrap();
        assert_eq!(own, b"child-must-not-see");
    }

    #[test]
    fn a_refusal_comes_back_as_the_daemons_error() {
        let c = daemon(Response::fail("credential unavailable"), None);
        assert_eq!(exchange(&c, "DB").unwrap_err(), "credential unavailable");
    }

    #[test]
    fn an_unsealed_or_wrong_sized_descriptor_is_refused() {
        let (r, w) = UnixStream::pair().unwrap();
        drop(w);
        let reply = Response::Session(SessionResponse::FdOk { len: 0 });
        let e = exchange(&daemon(reply, Some(OwnedFd::from(r))), "DB").unwrap_err();
        assert_eq!(e, "the daemon sent an unexpected descriptor");
        let (_, fd) = fd_ok(b"abc");
        let reply = Response::Session(SessionResponse::FdOk { len: 4 });
        assert!(exchange(&daemon(reply, fd), "DB").is_err());
    }

    #[test]
    fn pull_list_parsing() {
        assert_eq!(parse_list(" A, B ,,C "), ["A", "B", "C"]);
        assert!(parse_list("").is_empty());
    }
}
