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

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kepr_core::framing::{read_frame, write_frame};
use kepr_core::gate_protocol::ServiceStart;
use kepr_core::gate_startup::{failure_reason, read_ready, write_config};
use zeroize::Zeroizing;

const MAX_START: usize = 64 * 1024;
const READY_TIMEOUT: Duration = Duration::from_secs(5);

fn peer_uid(s: &UnixStream) -> Option<u32> {
    // SAFETY: an all-zero ucred is a valid value of this plain C struct.
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
    conn.set_read_timeout(Some(READY_TIMEOUT))
        .map_err(|e| e.to_string())?;
    conn.set_write_timeout(Some(READY_TIMEOUT))
        .map_err(|e| e.to_string())?;
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

    let watch = conn.try_clone().map_err(|e| e.to_string())?;
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
    let deadline = Instant::now() + READY_TIMEOUT;
    let ready = child
        .stdin
        .take()
        .ok_or_else(|| "session gate has no stdin".to_string())
        .and_then(|input| write_config(input, &config, deadline))
        .and_then(|_| {
            let stdout = child.stdout.take().ok_or("session gate has no stdout")?;
            read_ready(stdout, deadline)
        });
    let ready = match ready {
        Ok(ready) => ready,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let report = kepr_core::gate_protocol::ReadyLine {
                ready: false,
                port: 0,
                placeholders: std::collections::HashMap::new(),
                ca_pem: None,
                db_ports: std::collections::HashMap::new(),
                error: Some(failure_reason(&error).into()),
            };
            let bytes = serde_json::to_vec(&report).map_err(|_| "cannot encode startup failure")?;
            write_frame(&mut conn, &bytes)
                .map_err(|e| format!("cannot relay session gate startup failure: {e}"))?;
            return Ok(());
        }
    };
    let pidfd = match crate::session::pidfd_open(child.id() as i32) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let ready_line = match serde_json::to_vec(&ready) {
        Ok(bytes) => bytes,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("cannot encode session readiness".into());
        }
    };
    if let Err(error) = write_frame(&mut conn, &ready_line) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("cannot relay session readiness: {error}"));
    }

    // The daemon closing the connection (panic, session end) stops the gate.
    if conn.set_read_timeout(None).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err("cannot prepare session lifeline".into());
    }
    // A pidfd names this exact process: after `wait` reaps it, a kill by
    // pid could hit another session's gate that reused the number.
    let monitor = std::thread::Builder::new()
        .name("kepr-gate-lifeline".into())
        .spawn(move || {
            let mut sink = [0u8; 64];
            let mut w = watch;
            while matches!(w.read(&mut sink), Ok(n) if n > 0) {}
            use std::os::fd::AsRawFd;
            // SAFETY: pidfd_send_signal on a pidfd we own; ESRCH once the
            // gate has exited, never another process.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
        });
    let monitor = match monitor {
        Ok(monitor) => monitor,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("cannot start session lifeline monitor".into());
        }
    };
    let _ = child.wait();
    let _ = conn.shutdown(std::net::Shutdown::Both);
    let _ = monitor.join();
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
        // SAFETY: getuid has no preconditions and cannot fail.
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
