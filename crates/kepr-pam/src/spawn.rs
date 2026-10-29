//! Running the helper as the logging-in user: the user lookup, the
//! stdin that cannot raise SIGPIPE in the host, and the bounded wait.

use std::ffi::{c_char, c_int, CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::logic::{self, Secret};

/// How long a login waits for a helper that answers (`pam-passwd`).
const SYNC_WAIT: Duration = Duration::from_secs(10);

pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub name: CString,
}

pub fn lookup(name: CString) -> Option<User> {
    let mut buf = vec![0 as c_char; 16 * 1024];
    // SAFETY: an all-zero passwd is a valid value of this plain C struct.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwnam_r fills `pw` and `buf` (valid for their sizes) and sets `out`.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir is a NUL-terminated string inside `buf`.
    let home = unsafe { CStr::from_ptr(pw.pw_dir) }
        .to_string_lossy()
        .into_owned();
    Some(User {
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        home,
        name,
    })
}

fn groups(u: &User) -> Vec<libc::gid_t> {
    let mut n: c_int = 64;
    let mut g = vec![0 as libc::gid_t; n as usize];
    // SAFETY: `g` holds `n` entries; getgrouplist updates `n`.
    let rc = unsafe { libc::getgrouplist(u.name.as_ptr(), u.gid, g.as_mut_ptr(), &mut n) };
    if rc < 0 {
        return vec![u.gid];
    }
    g.truncate(n.max(0) as usize);
    g
}

/// A stdin for the helper that cannot raise SIGPIPE in this process (the
/// host's, not ours, if the helper exits before reading): a socket pair,
/// written with MSG_NOSIGNAL. Returns (the helper's end, our end).
fn stdin_pair() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: socketpair fills two descriptors.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both descriptors are new and owned by nobody else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn send_all(fd: &OwnedFd, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        // SAFETY: `data` is valid for its length; MSG_NOSIGNAL turns a closed peer into EPIPE.
        let n = unsafe {
            libc::send(
                fd.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        data = &data[n as usize..];
    }
    Ok(())
}

/// Run `kepr ARGS` as `u` with `input` on stdin. With `capture`, wait (at
/// most `SYNC_WAIT`) and return its stdout; otherwise just reap it (the
/// unlock helper detaches at once).
pub fn run_helper(
    u: &User,
    kepr: &std::path::Path,
    args: &[&str],
    input: &Secret,
    capture: bool,
) -> std::io::Result<Vec<u8>> {
    let gids = groups(u);
    let (uid, gid) = (u.uid, u.gid);
    let (theirs, ours) = stdin_pair()?;
    let mut cmd = Command::new(kepr);
    cmd.args(args)
        .env_clear()
        .envs(logic::helper_env(uid, &u.home))
        .current_dir("/")
        .stdin(Stdio::from(theirs))
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe calls (setgroups, setgid, setuid, a
    // check that root cannot be regained) run between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(gids.len(), gids.as_ptr()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
                || libc::setuid(0) == 0
            {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    drop(cmd); // the helper's end of the socket is closed here
    let _ = send_all(&ours, input.as_bytes());
    drop(ours); // EOF for the helper
    let until = Instant::now() + SYNC_WAIT;
    let mut out = Vec::new();
    if capture {
        // The helper's answer is one short line and it exits right after.
        loop {
            match child.try_wait() {
                Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                _ => break,
            }
        }
        if let Some(mut so) = child.stdout.take() {
            let _ = std::io::Read::read_to_end(&mut std::io::Read::take(&mut so, 1024), &mut out);
        }
    } else {
        let _ = child.wait();
    }
    Ok(out)
}
