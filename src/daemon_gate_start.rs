//! Validate and start one daemon-owned credential gate session.

use super::{random_hex, serve_gate_channel, validate_routes, GateOwner};
use crate::daemon_gate_registry::{gates_for, track_gate, Handle, MAX_GATES_PER_UID};
use kepr_core::gate_protocol::{GateLimits, GateRoute, RotationConfig, SessionConfig};
use kepr_core::protocol::Response;
use std::os::unix::net::UnixStream;

#[allow(clippy::too_many_arguments)]
pub(crate) fn start(
    uid: u32,
    peer_pid: i32,
    username: &str,
    routes: &[GateRoute],
    (port, limits, tunnel, record): (Option<u16>, GateLimits, bool, bool),
    harness: Option<String>,
    privacy: Option<kepr_core::privacy::Policy>,
    rotation: Option<RotationConfig>,
) -> Result<Response, String> {
    validate_routes(routes)?;
    limits.validate()?;
    if let Some(policy) = &privacy {
        policy.validate_routes(routes, tunnel)?;
    }
    if gates_for(uid) >= MAX_GATES_PER_UID {
        return Err(format!(
            "{MAX_GATES_PER_UID} agent sessions already running; end one or run `kepr panic`"
        ));
    }
    let config = SessionConfig {
        privacy,
        session_id: random_hex(8)?.as_str().to_string(),
        session_key_hex: random_hex(32)?,
        routes: routes.to_vec(),
        port,
        limits,
        tunnel,
        record,
        rotation,
    };
    let session = config.session_id.clone();
    let rec = crate::daemon_gatex::recording::Recorder::new(uid, &session, record);
    let (daemon_end, gate_end) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    let (child, ready, key, handle) = if crate::user_mode() {
        let (child, ready) = crate::daemon_gatex::spawn::start_local(peer_pid, &gate_end, config)?;
        let pid = child.id() as i32;
        (Some(child), ready, pid, Handle::Pid(pid))
    } else {
        let (conn, ready) = crate::daemon_gate_service::start(peer_pid, &gate_end, config)?;
        (
            None,
            ready,
            crate::daemon_gate_service::next_key(),
            Handle::Conn(conn),
        )
    };
    drop(gate_end);
    let owner = GateOwner {
        uid,
        username: username.to_string(),
        pid: peer_pid,
        creds: kepr_core::gate_protocol::resolvable_creds(routes),
        rec,
        harness: harness.filter(|h| kepr_core::protocol_aws::valid_harness(h)), // T7.10
        deadlines: Default::default(),
        rotatable: kepr_core::gate_protocol::rotatable_creds(routes),
    };
    track_gate(key, uid, Some(handle));
    std::thread::spawn(move || serve_gate_channel(daemon_end, child, key, owner));
    let gate_pid = key.max(0);
    crate::daemon_policy::session_started(uid, &session, routes); // T9.07
    Ok(Response::GateStarted {
        port: ready.port,
        placeholders: ready.placeholders,
        gate_pid,
        extras: Box::new(kepr_core::protocol_types::GateExtras {
            privacy: ready.privacy,
            ca_pem: ready.ca_pem,
            db_ports: ready.db_ports,
            session: Some(session),
        }),
    })
}
