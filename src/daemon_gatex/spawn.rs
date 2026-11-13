// daemon_gatex/spawn.rs — start a session gate as this daemon's own
// child (user mode): cleared environment, the session channel on fd 3,
// the config on stdin, then wait for its ready line. Moved out of
// daemon_gate.rs (LOC ceiling); system mode hands the session to
// kepr-gate.service instead (daemon_gate_service.rs).

use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kepr_core::gate_protocol::{ReadyLine, SessionConfig};
use kepr_core::gate_startup::{read_ready, write_config};

const READY_TIMEOUT: Duration = Duration::from_secs(5);

fn gate_bin() -> std::path::PathBuf {
    std::env::var_os("KEPR_GATE_BIN")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| default_gate_bin(std::env::current_exe().ok().as_deref()))
}

fn default_gate_bin(daemon_exe: Option<&std::path::Path>) -> std::path::PathBuf {
    daemon_exe
        .and_then(|exe| exe.parent())
        .map(|dir| dir.join("kepr-gate"))
        .filter(|path| {
            std::fs::metadata(path)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
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

/// Spawn the gate here (user mode): returns the child and its ready line.
pub(crate) fn start_local(
    peer_pid: i32,
    gate_end: &UnixStream,
    config: SessionConfig,
) -> Result<(Child, ReadyLine), String> {
    let expected_privacy = config.privacy.as_ref().map(|p| p.preset);
    let payload = zeroize::Zeroizing::new(
        serde_json::to_vec(&config).map_err(|_| "cannot encode kepr-gate session config")?,
    );
    drop(config);
    let mut child = spawn_gate(peer_pid, gate_end)?;
    let deadline = Instant::now() + READY_TIMEOUT;
    let ready = child
        .stdin
        .take()
        .ok_or_else(|| "kepr-gate has no stdin".to_string())
        .and_then(|stdin| write_config(stdin, &payload, deadline))
        .and_then(|_| {
            let stdout = child.stdout.take().ok_or("kepr-gate has no stdout")?;
            let ready = read_ready(stdout, deadline)?;
            if ready.privacy != expected_privacy {
                return Err("gate did not confirm the requested privacy policy".into());
            }
            Ok(ready)
        });
    match ready {
        Ok(r) => Ok((child, r)),
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_install_runs_its_own_gate_binary() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = dir.path().join("kepr-daemon");
        let gate = dir.path().join("kepr-gate");
        std::fs::write(&gate, "synthetic-gate-fixture").unwrap();
        std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(default_gate_bin(Some(&daemon)), gate);
    }

    #[test]
    fn a_missing_sibling_keeps_the_system_install_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let expected = std::path::PathBuf::from("/usr/local/bin/kepr-gate");
        assert_eq!(
            default_gate_bin(Some(&dir.path().join("kepr-daemon"))),
            expected
        );
        assert_eq!(default_gate_bin(None), expected);
    }
}
