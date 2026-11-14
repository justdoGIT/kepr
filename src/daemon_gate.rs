// daemon_gate.rs — Request::StartGate and the private resolve channel
// (agent vault plan §4.3, ticket T1.05).
//
// The daemon spawns kepr-gate itself, with a cleared environment and
// one end of a socket pair on fd 3. Sealed values are released only
// over that socket pair, never on the public socket, so an agent cannot
// start its own gate under a debugger or with LD_PRELOAD and read keys
// out of it. The system-mode unit forbids network sockets, so there the
// session is handed to kepr-gate.service instead (daemon_gate_service.rs,
// T1.19); the channel and every resolve check stay here either way.

use std::os::unix::net::UnixStream;
use std::process::Child;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_gate_deadline as deadline;
use crate::daemon_gate_registry::track_gate;
use crate::store::{cred_path, validate_name};
use crate::{crypto, expiry};
use kepr_core::binding::Inject;
use kepr_core::framing::{read_frame, write_frame};
use kepr_core::gate_protocol::{GateLimits, GateRequest, GateResponse, GateRoute};
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Response, MAX_MSG_BYTES};

#[path = "daemon_gate_start.rs"]
mod startup;
pub(crate) use startup::start;

const UNAVAILABLE: &str = "credential unavailable";

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
    /// The credentials this session's routes name; anything else a gate
    /// asks for is refused, so a compromised gate stays confined.
    pub creds: std::collections::HashSet<String>,
    /// T7.09: stores what the gate records (`kepr agent run --record`).
    pub rec: crate::daemon_gatex::recording::Recorder,
    /// T7.10: the harness the session claims to run, for just-in-time
    /// grants (`daemon_aws::grant`). `None` = no grant can match.
    pub harness: Option<String>,
    /// When values this gate was given stop being allowed: its
    /// generation moves then (daemon_gate_deadline.rs).
    pub deadlines: crate::daemon_gate_deadline::Deadlines,
    /// T13.03: credentials this session exists to rotate (`rotate:`
    /// routes); only these may be committed by the gate.
    pub rotatable: std::collections::HashSet<String>,
}

/// Bumped on every set, delete and expiry sweep; gates compare it
/// before using a cached value so revoked or rotated keys stop at once.
/// Each session's reply adds its own passed deadlines (`deadline`).
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub fn bump_generation() {
    GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

pub(crate) fn generation() -> u64 {
    GENERATION.load(std::sync::atomic::Ordering::SeqCst)
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
    if !owner.creds.contains(&name.to_uppercase()) {
        return Err(());
    }
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
    if crate::daemon_policy::canary_refuse(uid, username, &upper, meta.as_ref()) {
        return Err(()); // T9.08: never released; asking trips it
    }
    let inject = match check_resolvable(meta.as_ref(), expiry::now_unix(), host, port) {
        Ok(i) => i,
        Err(reason) => return fail(reason),
    };
    // T7.10: a just-in-time credential needs an open grant for this
    // session's harness.
    let jit = meta
        .as_ref()
        .map(|m| crate::daemon_aws::grant::check(m, owner.harness.as_deref(), expiry::now_unix()));
    if let Some(Err(reason)) = jit {
        return fail(reason);
    }
    if let Some(Err(e)) = meta
        .as_ref()
        .map(|m| crate::daemon_syncx::quorum_gate(uid, &upper, m))
    {
        return fail(format!("resolve: {e}")); // T7.12: M-of-N approvals
    }
    // T9.01: a sealed credential flagged --requires-consent is released
    // only after polkit approves the agent process (fail-closed).
    let needs_consent = meta.as_ref().and_then(|m| m.requires_consent) == Some(true);
    let consent = |m: &expiry::CredMeta| crate::daemon_policy::consent(uid, owner.pid, &upper, m); // T9.04
    if needs_consent && !meta.as_ref().is_some_and(consent) {
        return fail("resolve: consent denied".to_string());
    }
    // A window ending must reach a gate that cached the value.
    let (h, now) = (owner.harness.as_deref(), expiry::now_unix());
    let until = meta
        .as_ref()
        .and_then(|m| deadline::until(uid, &upper, m, h, now));
    if until.is_some_and(|t| owner.deadlines.note(t).is_err()) {
        return fail("resolve: too many open windows in this session".to_string());
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

fn serve_gate_channel(mut chan: UnixStream, child: Option<Child>, key: i32, mut owner: GateOwner) {
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
                generation: generation() + owner.deadlines.passed(expiry::now_unix()),
            },
            Ok(GateRequest::Record { id, record }) => owner.rec.handle(id, record),
            Ok(GateRequest::Decision { id, record }) => {
                crate::daemon_gatex::decisions::handle_decision(
                    owner.uid,
                    owner.rec.session(),
                    id,
                    record,
                )
            }
            Ok(GateRequest::Result { id, record }) => {
                crate::daemon_gatex::decisions::handle_result(
                    owner.uid,
                    owner.rec.session(),
                    id,
                    record,
                )
            }
            Ok(GateRequest::Journal { id, entries }) => crate::daemon_gatex::logs::handle_journal(
                owner.uid,
                owner.rec.session(),
                id,
                entries,
            ),
            Ok(GateRequest::Canary { id, fingerprints }) => {
                crate::daemon_policy::canary_gate_check(
                    owner.uid,
                    &owner.username,
                    id,
                    &fingerprints,
                )
            }
            Ok(GateRequest::DayUsage {
                id,
                name,
                requests,
                tokens,
            }) => crate::daemon_policy::day_usage(
                &owner.creds,
                owner.uid,
                id,
                &name,
                (requests, tokens),
            ),
            Ok(GateRequest::RotateCommit { id, name, value }) => {
                crate::daemon_gatex::rotate::commit(&owner, id, &name, &value)
            }
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
    // pid that has been reaped and reused. A service-run gate's lifeline
    // connection is dropped with its registry entry.
    track_gate(key, owner.uid, None);
    if let Some(mut child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
}

pub fn handle_start_gate(
    uid: u32,
    peer_pid: i32,
    username: &str,
    routes: &[GateRoute],
    port_limits: (Option<u16>, GateLimits, bool, bool),
    harness: Option<String>,
    privacy: Option<kepr_core::privacy::Policy>,
) -> Response {
    let result = start(
        uid,
        peer_pid,
        username,
        routes,
        port_limits,
        harness,
        privacy,
        None,
    );
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

pub fn handle_rotate_provider(
    uid: u32,
    peer_pid: i32,
    username: &str,
    target: &str,
    provider: &str,
    bootstrap: &str,
) -> Response {
    crate::daemon_gatex::provider_rotate::handle(
        uid, peer_pid, username, target, provider, bootstrap,
    )
}

#[cfg(test)]
#[path = "daemon_gate_tests.rs"]
mod tests;
