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
use kepr_core::gate_startup::MAX_READY_LINE;
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
    let expected_privacy = config.privacy.as_ref().map(|p| p.preset);
    let path = socket_path();
    let mut conn = UnixStream::connect(&path).map_err(|e| {
        format!(
            "the kepr-gate service is not running ({}: {e}); start kepr-gate.service",
            path.display()
        )
    })?;
    conn.set_read_timeout(Some(READY_TIMEOUT))
        .map_err(|e| e.to_string())?;
    conn.set_write_timeout(Some(READY_TIMEOUT))
        .map_err(|e| e.to_string())?;
    kepr_core::fdpass::send_fd(&conn, gate_end.as_raw_fd())?;
    let start = ServiceStart { owner_pid, config };
    let payload = Zeroizing::new(serde_json::to_vec(&start).map_err(|e| e.to_string())?);
    drop(start);
    write_frame(&mut conn, &payload).map_err(|e| format!("kepr-gate service: {e}"))?;
    let line = read_frame(&mut conn, MAX_READY_LINE).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset => {
            "the kepr-gate service closed before reporting readiness".to_string()
        }
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            "the kepr-gate service readiness timed out".to_string()
        }
        std::io::ErrorKind::InvalidData => {
            "the kepr-gate service sent an oversized readiness response".to_string()
        }
        _ => format!("kepr-gate service readiness failed: {e}"),
    })?;
    let ready = kepr_core::gate_startup::parse_ready(&line)?;
    if ready.privacy != expected_privacy {
        return Err("gate did not confirm the requested privacy policy".into());
    }
    conn.set_read_timeout(None).map_err(|e| e.to_string())?;
    Ok((conn, ready))
}
