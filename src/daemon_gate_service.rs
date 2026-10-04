// daemon_gate_service.rs — system-mode side of T1.19: hand a session to
// the kepr-gate service instead of spawning the gate here.
//
// The system unit forbids network sockets and lacks CAP_KILL / setuid, so
// session gates run under `kepr-gate.service` as their own user. The
// daemon connects to the service's socket (root only, checked there with
// SO_PEERCRED), passes its end of the session channel (SCM_RIGHTS) and
// the session config, and reads back the gate's ready line. The returned
// connection is the gate's lifeline: closing it stops the session gate.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use kepr_core::framing::{read_frame, write_frame};
use kepr_core::gate_protocol::{ReadyLine, ServiceStart, SessionConfig};
use zeroize::Zeroizing;

const READY_TIMEOUT: Duration = Duration::from_secs(5);

/// Registry keys for service-run gates (negative, so never a real pid).
static NEXT_KEY: AtomicI32 = AtomicI32::new(-1);

pub fn next_key() -> i32 {
    NEXT_KEY.fetch_sub(1, Ordering::SeqCst)
}

fn socket_path() -> std::path::PathBuf {
    std::env::var_os("KEPR_GATE_SERVICE_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/run/kepr-gate/gate.sock".into())
}

/// Start a session gate in the service. Returns the control connection
/// (the gate's lifeline) and its ready line.
pub fn start(
    owner_pid: i32,
    gate_end: &UnixStream,
    config: SessionConfig,
) -> Result<(UnixStream, ReadyLine), String> {
    let path = socket_path();
    let mut conn = UnixStream::connect(&path).map_err(|e| {
        format!(
            "the kepr-gate service is not running ({}: {e}); start kepr-gate.service",
            path.display()
        )
    })?;
    conn.set_read_timeout(Some(READY_TIMEOUT))
        .map_err(|e| e.to_string())?;
    kepr_core::fdpass::send_fd(&conn, gate_end.as_raw_fd())?;
    let start = ServiceStart { owner_pid, config };
    let payload = Zeroizing::new(serde_json::to_vec(&start).map_err(|e| e.to_string())?);
    drop(start);
    write_frame(&mut conn, &payload).map_err(|e| format!("kepr-gate service: {e}"))?;
    let line = read_frame(&mut conn, 64 * 1024)
        .map_err(|_| "the kepr-gate service did not start the session")?;
    let ready: ReadyLine =
        serde_json::from_slice(&line).map_err(|_| "kepr-gate sent a malformed ready line")?;
    if !ready.ready {
        return Err("kepr-gate reported not ready".into());
    }
    conn.set_read_timeout(None).map_err(|e| e.to_string())?;
    Ok((conn, ready))
}
