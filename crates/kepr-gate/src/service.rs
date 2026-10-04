//! System-mode gate service (T1.19): `kepr-gate --serve SOCKET`.
//!
//! The system daemon's unit forbids network sockets and runs as root, so
//! it can't run session gates itself. This service runs as its own
//! unprivileged user with network access and no access to the credential
//! store. Only the daemon may use it: a connection is accepted only from
//! the allowed uid (root), checked with SO_PEERCRED. Per connection the
//! daemon sends the session channel fd (SCM_RIGHTS), then a framed
//! `ServiceStart`; the service starts `kepr-gate --owner-pid N` wired
//! exactly as the user-mode daemon does (fd 3 = channel, config on stdin)
//! and relays its ready line back. Closing the connection stops the
//! session gate, which is how `kepr panic` reaches it.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use kepr_core::framing::{read_frame, write_frame};
use kepr_core::gate_protocol::ServiceStart;
use zeroize::Zeroizing;

const MAX_START: usize = 64 * 1024;

fn peer_uid(s: &UnixStream) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED fills a ucred of the length we pass.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

/// Parse `--serve PATH [--allow-uid N]`.
pub fn parse_args(args: &[String]) -> Option<(String, u32)> {
    match args {
        [flag, path] if flag == "--serve" => Some((path.clone(), 0)),
        [flag, path, a, uid] if flag == "--serve" && a == "--allow-uid" => {
            Some((path.clone(), uid.parse().ok()?))
        }
        _ => None,
    }
}

pub fn serve(path: &str, allowed_uid: u32) -> Result<(), String> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).map_err(|e| format!("bind {path}: {e}"))?;
    // Anyone may connect; only `allowed_uid` is served (SO_PEERCRED).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
        .map_err(|e| format!("chmod {path}: {e}"))?;
    eprintln!("kepr-gate: serving {path} for uid {allowed_uid}");
    for conn in listener.incoming().flatten() {
        if peer_uid(&conn) != Some(allowed_uid) {
            continue; // dropped: not the daemon
        }
        std::thread::spawn(move || {
            if let Err(e) = session(conn) {
                eprintln!("kepr-gate: session refused: {e}");
            }
        });
    }
    Ok(())
}

fn session(mut conn: UnixStream) -> Result<(), String> {
    let fd = kepr_core::fdpass::recv_fd(&conn)?.ok_or("no channel fd")?;
    // SAFETY: recv_fd handed us this fd; we own it from here.
    let channel = unsafe { OwnedFd::from_raw_fd(fd) };
    let raw = Zeroizing::new(read_frame(&mut conn, MAX_START).map_err(|e| e.to_string())?);
    let start: ServiceStart = serde_json::from_slice(&raw).map_err(|_| "malformed start")?;
    if start.owner_pid <= 0 {
        return Err("invalid owner pid".into());
    }
    let config = Zeroizing::new(serde_json::to_vec(&start.config).map_err(|e| e.to_string())?);
    drop(start.config);

    let chan_fd = channel.as_raw_fd();
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = Command::new(exe);
    cmd.arg("--owner-pid")
        .arg(start.owner_pid.to_string())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // SAFETY: only dup2/fcntl between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(chan_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start session gate: {e}"))?;
    drop(channel);
    let ready = child
        .stdin
        .take()
        .ok_or("no stdin")
        .and_then(|mut i| i.write_all(&config).map_err(|_| "config write failed"))
        .map_err(str::to_string)
        .and_then(|_| {
            let mut line = String::new();
            let out = child.stdout.take().ok_or("no stdout")?;
            BufReader::new(out)
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            Ok(line)
        });
    let ready = match ready {
        Ok(l) if !l.is_empty() => l,
        other => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(other.err().unwrap_or_else(|| "session gate exited".into()));
        }
    };
    write_frame(&mut conn, ready.trim_end().as_bytes()).map_err(|e| e.to_string())?;

    // The daemon closing the connection (panic, session end) stops the gate.
    let watch = conn.try_clone().map_err(|e| e.to_string())?;
    let pid = child.id() as i32;
    std::thread::spawn(move || {
        let mut sink = [0u8; 64];
        let mut w = watch;
        while matches!(w.read(&mut sink), Ok(n) if n > 0) {}
        // SAFETY: kill(2) on our own child; at worst ESRCH after exit.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    });
    let _ = child.wait();
    let _ = conn.shutdown(std::net::Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn args() {
        assert_eq!(parse_args(&v(&["--serve", "/s"])), Some(("/s".into(), 0)));
        assert_eq!(
            parse_args(&v(&["--serve", "/s", "--allow-uid", "1000"])),
            Some(("/s".into(), 1000))
        );
        assert_eq!(parse_args(&v(&["--owner-pid", "5"])), None);
        assert_eq!(parse_args(&v(&["--serve", "/s", "--allow-uid", "x"])), None);
    }

    #[test]
    fn rejects_other_uids_without_reading() {
        let dir = std::env::temp_dir().join(format!("kgs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("g.sock");
        let p = path.to_str().unwrap().to_string();
        let me = unsafe { libc::getuid() };
        std::thread::spawn(move || serve(&p, me.wrapping_add(1)));
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut c = UnixStream::connect(&path).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut b = [0u8; 1];
        // Not the allowed uid: the service drops the connection.
        assert!(matches!(c.read(&mut b), Ok(0) | Err(_)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
