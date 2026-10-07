// daemon_gatex/spawn.rs — start a session gate as this daemon's own
// child (user mode): cleared environment, the session channel on fd 3,
// the config on stdin, then wait for its ready line. Moved out of
// daemon_gate.rs (LOC ceiling); system mode hands the session to
// kepr-gate.service instead (daemon_gate_service.rs).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use kepr_core::gate_protocol::{ReadyLine, SessionConfig};

const READY_TIMEOUT: Duration = Duration::from_secs(5);

fn gate_bin() -> std::path::PathBuf {
    std::env::var_os("KEPR_GATE_BIN")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/usr/local/bin/kepr-gate".into())
}

fn spawn_gate(owner_pid: i32, gate_end: &UnixStream) -> Result<Child, String> {
    let fd = gate_end.as_raw_fd();
    let mut cmd = Command::new(gate_bin());
    cmd.arg("--owner-pid")
        .arg(owner_pid.to_string())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // SAFETY: only async-signal-safe calls (dup2, fcntl) between fork
    // and exec; `fd` stays open in the parent until spawn returns.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
        .map_err(|e| format!("cannot start kepr-gate: {e}"))
}

fn read_ready(child: &mut Child) -> Result<ReadyLine, String> {
    let stdout = child.stdout.take().ok_or("kepr-gate has no stdout")?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = tx.send(BufReader::new(stdout).read_line(&mut line).map(|_| line));
    });
    let line = rx
        .recv_timeout(READY_TIMEOUT)
        .map_err(|_| "kepr-gate did not become ready")?
        .map_err(|e| format!("kepr-gate: {e}"))?;
    let ready: ReadyLine =
        serde_json::from_str(&line).map_err(|_| "kepr-gate sent a malformed ready line")?;
    if !ready.ready {
        return Err("kepr-gate reported not ready".into());
    }
    Ok(ready)
}

/// Spawn the gate here (user mode): returns the child and its ready line.
pub(crate) fn start_local(
    peer_pid: i32,
    gate_end: &UnixStream,
    config: SessionConfig,
) -> Result<(Child, ReadyLine), String> {
    let mut child = spawn_gate(peer_pid, gate_end)?;
    let payload = zeroize::Zeroizing::new(serde_json::to_vec(&config).map_err(|e| e.to_string())?);
    drop(config);
    let ready = child
        .stdin
        .take()
        .ok_or_else(|| "kepr-gate has no stdin".to_string())
        .and_then(|mut stdin| {
            stdin
                .write_all(&payload)
                .map_err(|e| format!("kepr-gate: {e}"))
        })
        .and_then(|_| read_ready(&mut child));
    match ready {
        Ok(r) => Ok((child, r)),
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        }
    }
}
