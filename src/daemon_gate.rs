// daemon_gate.rs — Request::StartGate and the private resolve channel
// (agent vault plan §4.3, ticket T1.05).
//
// The daemon spawns kepr-gate itself, with a cleared environment and
// one end of a socket pair on fd 3. Sealed values are released only
// over that socket pair, never on the public socket, so an agent cannot
// start its own gate under a debugger or with LD_PRELOAD and read keys
// out of it. User-mode only for now: the system-mode unit forbids
// network sockets, so a system gate needs its own service (T1.19).

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::store::{cred_path, validate_name};
use crate::{crypto, expiry};
use kepr_core::binding::Inject;
use kepr_core::framing::{read_frame, write_frame};
use kepr_core::gate_protocol::{GateRequest, GateResponse, GateRoute, ReadyLine, SessionConfig};
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Response, MAX_MSG_BYTES};

const MAX_ROUTES: usize = 16;
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const UNAVAILABLE: &str = "credential unavailable";

fn gate_bin() -> std::path::PathBuf {
    std::env::var_os("KEPR_GATE_BIN")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/usr/local/bin/kepr-gate".into())
}

pub fn validate_routes(routes: &[GateRoute]) -> Result<(), String> {
    if routes.is_empty() || routes.len() > MAX_ROUTES {
        return Err(format!("an agent session needs 1-{MAX_ROUTES} routes"));
    }
    let mut slots = HashSet::new();
    for r in routes {
        validate_name(&r.cred)?;
        if r.provider.is_empty() || !r.provider.chars().all(|c| c.is_ascii_lowercase()) {
            return Err("invalid provider name".to_string());
        }
        if !slots.insert(r.slot) {
            return Err("route slots must be unique".to_string());
        }
    }
    Ok(())
}

/// Pure policy: may this meta be released to the gate for host:port?
/// Returns how to inject it, or the precise (audit-only) reason.
pub fn check_resolvable(
    meta: Option<&expiry::CredMeta>,
    now_unix: u64,
    host: &str,
    port: u16,
) -> Result<Inject, String> {
    let meta = meta.ok_or("resolve: not sealed")?;
    if meta.sealed != Some(true) {
        return Err("resolve: not sealed".to_string());
    }
    if meta.expires_at_unix.is_some_and(|exp| now_unix >= exp) {
        return Err("resolve: expired".to_string());
    }
    let host = host.to_ascii_lowercase();
    meta.bindings
        .iter()
        .flatten()
        .find(|b| b.host == host && b.port == port)
        .map(|b| b.inject.clone())
        .ok_or_else(|| "resolve: host not bound".to_string())
}

pub fn resolve_for_gate(
    uid: u32,
    username: &str,
    name: &str,
    host: &str,
    port: u16,
) -> GateResponse {
    if validate_name(name).is_err() {
        return GateResponse::Err {
            error: UNAVAILABLE.into(),
        };
    }
    let upper = name.to_uppercase();
    let fail = |reason: String| {
        audit::log(&AuditEvent {
            op: "resolve",
            name: Some(&upper),
            uid,
            username,
            result: AuditResult::Fail(reason),
        });
        GateResponse::Err {
            error: UNAVAILABLE.into(),
        }
    };
    let meta = match expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, &upper))) {
        Some(Ok(m)) => Some(m),
        Some(Err(e)) => return fail(format!("resolve: meta parse: {e}")),
        None => None,
    };
    let inject = match check_resolvable(meta.as_ref(), expiry::now_unix(), host, port) {
        Ok(i) => i,
        Err(reason) => return fail(reason),
    };
    match crypto::default_backend().decrypt(uid, &upper) {
        Ok(value) => {
            audit::log(&AuditEvent {
                op: "resolve",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Ok,
            });
            GateResponse::ResolveOk { value, inject }
        }
        Err(e) => fail(format!("resolve: {e}")),
    }
}

fn random_hex(n: usize) -> Result<ZeroString, String> {
    let mut buf = zeroize::Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut buf).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(ZeroString::from_string(hex::encode(&*buf)))
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

fn serve_gate_channel(mut chan: UnixStream, mut child: Child, uid: u32, username: String) {
    while let Ok(raw) = read_frame(&mut chan, MAX_MSG_BYTES) {
        let resp = match serde_json::from_slice::<GateRequest>(&raw) {
            Ok(GateRequest::Resolve { name, host, port }) => {
                resolve_for_gate(uid, &username, &name, &host, port)
            }
            Err(_) => GateResponse::Err {
                error: "malformed request".into(),
            },
        };
        let Ok(payload) = serde_json::to_vec(&resp).map(zeroize::Zeroizing::new) else {
            break;
        };
        if write_frame(&mut chan, &payload).is_err() {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn start(
    uid: u32,
    peer_pid: i32,
    username: &str,
    routes: &[GateRoute],
) -> Result<Response, String> {
    if !crate::user_mode() {
        return Err("agent sessions need the user-mode daemon for now".into());
    }
    validate_routes(routes)?;
    let config = SessionConfig {
        session_id: random_hex(8)?.as_str().to_string(),
        session_key_hex: random_hex(32)?,
        routes: routes.to_vec(),
    };
    let (daemon_end, gate_end) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    let mut child = spawn_gate(peer_pid, &gate_end)?;
    drop(gate_end);
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
    let ready = match ready {
        Ok(r) => r,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    let gate_pid = child.id() as i32;
    let user = username.to_string();
    std::thread::spawn(move || serve_gate_channel(daemon_end, child, uid, user));
    Ok(Response::GateStarted {
        port: ready.port,
        placeholders: ready.placeholders,
        gate_pid,
    })
}

pub fn handle_start_gate(
    uid: u32,
    peer_pid: i32,
    username: &str,
    routes: &[GateRoute],
) -> Response {
    let result = start(uid, peer_pid, username, routes);
    audit::log(&AuditEvent {
        op: "start-gate",
        name: None,
        uid,
        username,
        result: match &result {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
    result.unwrap_or_else(Response::fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::binding::Binding;

    fn route(cred: &str, slot: u16) -> GateRoute {
        GateRoute {
            provider: "anthropic".into(),
            cred: cred.into(),
            slot,
        }
    }

    fn sealed(exp: Option<u64>) -> expiry::CredMeta {
        expiry::CredMeta {
            expires_at_unix: exp,
            ..Default::default()
        }
        .with_seal(
            Some(true),
            Some(vec![Binding {
                host: "api.anthropic.com".into(),
                port: 443,
                inject: Inject::Header {
                    name: "x-api-key".into(),
                },
            }]),
        )
        .unwrap()
    }

    #[test]
    fn resolvable_only_when_sealed_bound_and_fresh() {
        let m = sealed(Some(100));
        assert!(check_resolvable(Some(&m), 10, "API.anthropic.com", 443).is_ok());
        assert_eq!(
            check_resolvable(Some(&m), 10, "evil.example.com", 443),
            Err("resolve: host not bound".into())
        );
        assert!(check_resolvable(Some(&m), 10, "api.anthropic.com", 8443).is_err());
        assert_eq!(
            check_resolvable(Some(&m), 100, "api.anthropic.com", 443),
            Err("resolve: expired".into())
        );
        assert!(check_resolvable(
            Some(&expiry::CredMeta::default()),
            0,
            "api.anthropic.com",
            443
        )
        .is_err());
        assert!(check_resolvable(None, 0, "api.anthropic.com", 443).is_err());
    }

    #[test]
    fn route_validation() {
        assert!(validate_routes(&[route("A", 0)]).is_ok());
        assert!(validate_routes(&[]).is_err());
        assert!(validate_routes(&(0..17).map(|i| route("A", i)).collect::<Vec<_>>()).is_err());
        assert!(validate_routes(&[route("A", 0), route("B", 0)]).is_err());
        assert!(validate_routes(&[route("../x", 0)]).is_err());
        let mut bad = route("A", 0);
        bad.provider = "Evil/../".into();
        assert!(validate_routes(&[bad]).is_err());
    }
}
