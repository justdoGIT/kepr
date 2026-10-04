// daemon_gate.rs — Request::StartGate and the private resolve channel
// (agent vault plan §4.3, ticket T1.05).
//
// The daemon spawns kepr-gate itself, with a cleared environment and
// one end of a socket pair on fd 3. Sealed values are released only
// over that socket pair, never on the public socket, so an agent cannot
// start its own gate under a debugger or with LD_PRELOAD and read keys
// out of it. User-mode only for now: the system-mode unit forbids
// network sockets, so a system gate needs its own service (T1.19).

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

const READY_TIMEOUT: Duration = Duration::from_secs(5);
const UNAVAILABLE: &str = "credential unavailable";

fn gate_bin() -> std::path::PathBuf {
    std::env::var_os("KEPR_GATE_BIN")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/usr/local/bin/kepr-gate".into())
}

pub fn validate_routes(routes: &[GateRoute]) -> Result<(), String> {
    kepr_core::gate_protocol::validate_routes(routes)?;
    routes.iter().try_for_each(|r| validate_name(&r.cred))
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
    if meta.requires_fido2 == Some(true) {
        // with_seal rejects this combination; refuse metas written before it did.
        return Err("resolve: fido2 required".to_string());
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

/// Who a gate serves: the uid whose credentials it may resolve, and the
/// agent process (its --owner-pid) that polkit consent is asked for.
pub struct GateOwner {
    pub uid: u32,
    pub username: String,
    pub pid: i32,
}

/// Gates this daemon started: (gate pid, uid). Used by `kepr panic`.
static GATES: std::sync::Mutex<Vec<(i32, u32)>> = std::sync::Mutex::new(Vec::new());

fn track_gate(pid: i32, uid: u32, add: bool) {
    if let Ok(mut g) = GATES.lock() {
        if add {
            g.push((pid, uid));
        } else {
            g.retain(|(p, _)| *p != pid);
        }
    }
}

/// SIGKILL every gate serving `uid`. Returns how many were signalled.
pub fn stop_gates_for(uid: u32) -> usize {
    let Ok(g) = GATES.lock() else { return 0 };
    g.iter()
        .filter(|(_, u)| *u == uid)
        // SAFETY: kill(2) on a pid this daemon spawned and still tracks
        // (removed from the list when its channel thread reaps it).
        .filter(|(p, _)| unsafe { libc::kill(*p, libc::SIGKILL) } == 0)
        .count()
}

/// Bumped on every set, delete and expiry sweep; gates compare it
/// before using a cached value so revoked or rotated keys stop at once.
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub fn bump_generation() {
    GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Release a sealed value to a gate, or `Err(())` after auditing why.
/// The gate only ever sees the generic "credential unavailable".
pub fn resolve_for_gate(
    owner: &GateOwner,
    name: &str,
    host: &str,
    port: u16,
) -> Result<(ZeroString, Inject), ()> {
    let (uid, username) = (owner.uid, owner.username.as_str());
    validate_name(name).map_err(|_| ())?;
    let upper = name.to_uppercase();
    let fail = |reason: String| {
        audit::log(&AuditEvent {
            op: "resolve",
            name: Some(&upper),
            uid,
            username,
            result: AuditResult::Fail(reason),
        });
        Err(())
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
    // T9.01: a sealed credential flagged --requires-consent is released
    // only after polkit approves the agent process (fail-closed).
    let needs_consent = meta.as_ref().and_then(|m| m.requires_consent) == Some(true);
    if needs_consent && !crate::daemon_polkit::consent_granted(owner.pid) {
        return fail("resolve: consent denied".to_string());
    }
    match crypto::default_backend().decrypt(uid, &upper) {
        Ok(value) => {
            audit::log(&AuditEvent {
                op: "resolve",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Ok,
            });
            Ok((value, inject))
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

fn serve_gate_channel(mut chan: UnixStream, mut child: Child, owner: GateOwner) {
    let gate_pid = child.id() as i32;
    while let Ok(raw) = read_frame(&mut chan, MAX_MSG_BYTES) {
        let resp = match serde_json::from_slice::<GateRequest>(&raw) {
            Ok(GateRequest::Resolve {
                id,
                name,
                host,
                port,
            }) => match resolve_for_gate(&owner, &name, &host, port) {
                Ok((value, inject)) => GateResponse::ResolveOk { id, value, inject },
                Err(()) => GateResponse::Err {
                    id,
                    error: UNAVAILABLE.into(),
                },
            },
            Ok(GateRequest::Generation { id }) => GateResponse::Generation {
                id,
                generation: GENERATION.load(std::sync::atomic::Ordering::SeqCst),
            },
            Err(_) => GateResponse::Err {
                id: 0,
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
    // Untrack before reaping so `stop_gates_for` can never signal a
    // pid that has been reaped and reused.
    let _ = child.kill();
    track_gate(gate_pid, owner.uid, false);
    let _ = child.wait();
}

/// `kepr panic` (T3.05): stop the caller's gates (their key caches die
/// with them) and, if the store is passphrase-protected, lock it so the
/// master key leaves memory until `kepr unlock`.
pub fn handle_panic(uid: u32, username: &str) -> Response {
    let gates_stopped = stop_gates_for(uid);
    let may_lock = crate::user_mode() || uid == 0;
    let locked =
        may_lock && crate::protected_master_key_path().exists() && crypto::lock_backend().is_ok();
    audit::log(&AuditEvent {
        op: "panic",
        name: None,
        uid,
        username,
        result: AuditResult::Ok,
    });
    Response::PanicOk {
        gates_stopped,
        locked,
    }
}

fn start(
    uid: u32,
    peer_pid: i32,
    username: &str,
    routes: &[GateRoute],
    port: Option<u16>,
) -> Result<Response, String> {
    if !crate::user_mode() {
        return Err("agent sessions need the user-mode daemon for now".into());
    }
    validate_routes(routes)?;
    let config = SessionConfig {
        session_id: random_hex(8)?.as_str().to_string(),
        session_key_hex: random_hex(32)?,
        routes: routes.to_vec(),
        port,
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
    let owner = GateOwner {
        uid,
        username: username.to_string(),
        pid: peer_pid,
    };
    track_gate(gate_pid, uid, true);
    std::thread::spawn(move || serve_gate_channel(daemon_end, child, owner));
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
    port: Option<u16>,
) -> Response {
    let result = start(uid, peer_pid, username, routes, port);
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
