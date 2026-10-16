// cli_clip/mod.rs — `kepr copy` owns the clipboard selection itself
// (T12.47 Wayland data-control, T12.48 X11 CLIPBOARD), so it can offer the value as text plus
// `x-kde-passwordManagerHint` = `secret`: clipboard managers that honour
// the hint (KDE Klipper, and others that follow it) don't store it. The
// detached internal verb `kepr __clipboard-serve` reads the job and the
// value on stdin, serves until SECS, then drops the selection unless
// another client took it. The value is never in argv, env, logs or
// errors, and lives in a `ZeroString`.

pub mod wayland;
pub mod wl_wire;
pub mod x11;
pub mod x11_auth;
pub mod x11_wire;

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::process::Stdio;
use std::time::{Duration, Instant};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use zeroize::Zeroizing;

pub const HINT_MIME: &str = "x-kde-passwordManagerHint";
pub const HINT_VALUE: &[u8] = b"secret";
pub const TEXT_TYPES: &[&str] = &[
    "text/plain;charset=utf-8",
    "text/plain",
    "UTF8_STRING",
    "TEXT",
    "STRING",
];
pub const MAX_VALUE: usize = 1 << 20;

/// Exit status of `__clipboard-serve` when the desktop has no protocol
/// for it (no data-control manager).
pub const UNSUPPORTED: i32 = 3;
const READY: &[u8] = b"ready\n";
const READY_WAIT: Duration = Duration::from_secs(5);
const HEADER_MAX: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Wayland,
    X11,
}

impl Backend {
    fn id(self) -> &'static str {
        match self {
            Backend::Wayland => "wayland",
            Backend::X11 => "x11",
        }
    }
    fn from_id(s: &str) -> Option<Self> {
        [Backend::Wayland, Backend::X11]
            .into_iter()
            .find(|b| b.id() == s)
    }
}

/// Start `kepr __clipboard-serve` detached, hand it the job on stdin and
/// wait up to 5 s for `ready`. False means: use a clipboard tool instead
/// (no data-control protocol, an error, or no answer; a server that did
/// not answer in time is killed so it can't take the clipboard late).
pub fn handed_off(b: Backend, secs: u64, value: &ZeroString) -> bool {
    if value.len() > MAX_VALUE {
        return false;
    }
    let Ok(mut cmd) = crate::cli_copy::detached_kepr("__clipboard-serve") else {
        return false;
    };
    let Ok(mut child) = cmd.stdout(Stdio::piped()).spawn() else {
        return false;
    };
    let header = format!("{}\n{secs}\n", b.id());
    let sent = child.stdin.take().is_some_and(|mut s| {
        s.write_all(header.as_bytes()).is_ok() && s.write_all(value.as_bytes()).is_ok()
    }); // stdin closes here: the server reads to EOF
    if sent
        && child
            .stdout
            .take()
            .is_some_and(|o| wait_ready(o, READY_WAIT))
    {
        return true; // it keeps serving on its own
    }
    let _ = child.kill();
    let _ = child.wait();
    false
}

/// True once `out` yields exactly `ready\n` within `within`.
fn wait_ready(mut out: impl Read + AsRawFd, within: Duration) -> bool {
    let until = Instant::now() + within;
    let mut got = Vec::new();
    while got.len() < READY.len() {
        let left = until.saturating_duration_since(Instant::now());
        if !matches!(
            wl_wire::poll_fd(out.as_raw_fd(), libc::POLLIN, left),
            Ok(true)
        ) {
            return false;
        }
        let mut b = [0u8; 8];
        match out.read(&mut b) {
            Ok(0) | Err(_) => return false,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    got == READY
}

/// `backend\nSECS\nVALUE` from the parent, read into wiped memory.
fn read_job(r: &mut dyn Read) -> Result<(Backend, u64, ZeroString), String> {
    let bad = || "bad clipboard job".to_string();
    let mut buf = Zeroizing::new(vec![0u8; HEADER_MAX + MAX_VALUE + 1]);
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(bad()),
        }
    }
    let mut parts = buf[..n].splitn(3, |c| *c == b'\n');
    let (Some(b), Some(secs), Some(value)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(bad());
    };
    let b = std::str::from_utf8(b).ok().and_then(Backend::from_id);
    let secs = std::str::from_utf8(secs).ok().and_then(|s| s.parse().ok());
    let (Some(b), Some(secs)) = (b, secs) else {
        return Err(bad());
    };
    if value.len() > MAX_VALUE {
        return Err("value too large for the clipboard".into());
    }
    let text = std::str::from_utf8(value).map_err(|_| bad())?;
    let mut s = String::with_capacity(text.len()); // exact: no reallocation copies
    s.push_str(text);
    Ok((b, secs, ZeroString::from_string(s)))
}

/// Print `ready`, then point stdout at /dev/null so the parent sees EOF.
fn say_ready() {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(READY).and_then(|_| out.flush());
    if let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") {
        // SAFETY: dup2 onto fd 1, which this process owns.
        unsafe { libc::dup2(null.as_raw_fd(), 1) };
    }
}

/// `kepr __clipboard-serve` (internal): serve the job read on stdin.
pub fn cmd_clipboard_serve() -> Response {
    // SAFETY: prctl with constant arguments: no core dumps or same-uid
    // ptrace of the process holding the value.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let (b, secs, value) = match read_job(&mut std::io::stdin().lock()) {
        Ok(j) => j,
        Err(e) => return Response::fail(e),
    };
    let r = match b {
        Backend::Wayland => match wayland::serve(&value, secs, say_ready) {
            Err(wayland::WlError::NoDataControl) => std::process::exit(UNSUPPORTED),
            r => r.map_err(|e| e.to_string()),
        },
        Backend::X11 => x11::serve(&value, secs, say_ready), // T12.48
    };
    match r {
        Ok(()) => Response::Pong,
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_job() {
        let (b, secs, v) = read_job(&mut &b"wayland\n20\nline one\nline two"[..]).unwrap();
        assert_eq!(
            (b, secs, v.as_str()),
            (Backend::Wayland, 20, "line one\nline two")
        );
        assert!(read_job(&mut &b"wayland\n20"[..]).is_err());
        assert!(read_job(&mut &b"gnome\n20\nv"[..]).is_err());
        let (b, _, v) = read_job(&mut &b"x11\n0\nv"[..]).unwrap();
        assert_eq!((b, v.as_str()), (Backend::X11, "v"));
        assert!(read_job(&mut &b"wayland\nsoon\nv"[..]).is_err());
    }

    #[test]
    fn a_value_over_the_limit_is_refused() {
        let mut job = b"wayland\n5\n".to_vec();
        job.resize(job.len() + MAX_VALUE, b'x');
        assert_eq!(read_job(&mut &job[..]).unwrap().2.len(), MAX_VALUE);
        job.push(b'x');
        let e = read_job(&mut &job[..]).unwrap_err();
        assert!(e.contains("too large") && !e.contains("xxx"), "{e}");
    }

    #[test]
    fn ready_needs_the_word_in_time() {
        use std::os::unix::net::UnixStream;
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"ready\n").unwrap();
        assert!(wait_ready(b, Duration::from_secs(1)));
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"nope!\n").unwrap();
        assert!(!wait_ready(b, Duration::from_secs(1)));
        let (_a, b) = UnixStream::pair().unwrap();
        assert!(!wait_ready(b, Duration::from_millis(50)));
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(!wait_ready(b, Duration::from_secs(1)));
    }
}
