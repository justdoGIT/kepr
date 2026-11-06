//! Private daemon ↔ kepr-gate protocol (agent vault plan §4.3).
//!
//! These messages travel only over the socket pair the daemon creates
//! when it spawns a gate (`Request::StartGate`). The daemon never
//! accepts them on its public socket, so no other process can ask for a
//! sealed value.

use crate::binding::Inject;
pub use crate::gate_limits::GateLimits;
use crate::generate::ZeroString;
use serde::{Deserialize, Serialize};

/// Gate → daemon. Every request carries an `id` that the reply echoes,
/// so a reply that arrives after the gate gave up waiting (a slow
/// consent prompt) is recognised as stale instead of being taken as the
/// answer to the next request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum GateRequest {
    Resolve {
        id: u64,
        name: String,
        host: String,
        port: u16,
    },
    /// Current store generation: changes whenever any credential is set,
    /// deleted or expires, so gates can drop cached values.
    Generation { id: u64 },
    /// T7.09: recorded chunks for the daemon to store, encrypted.
    Record {
        id: u64,
        record: crate::gate_record::GateRecord,
    },
    /// T11.22: request journal entries for `kepr agent logs` (at most
    /// `gate_journal::MAX_BATCH`); answered with `Recorded`.
    Journal {
        id: u64,
        entries: Vec<crate::gate_journal::JournalEntry>,
    },
    /// T9.06: add to today's usage of credential `name` (shared by every
    /// session of the user); answered with `UsageToday`.
    DayUsage {
        id: u64,
        name: String,
        requests: u64,
        tokens: u64,
    },
    /// T9.08: canary fingerprints of key-shaped strings in a request;
    /// answered with `CanaryChecked` (the daemon raises the alarm).
    Canary { id: u64, fingerprints: Vec<String> },
    /// T13.03: a rotator inside a `rotate:` session stores the new value of
    /// the credential it rotated (the daemon keeps the seal and bindings),
    /// answered with `Rotated`. Refused for any other session.
    RotateCommit {
        id: u64,
        name: String,
        value: ZeroString,
    },
}

/// Daemon → gate.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GateResponse {
    ResolveOk {
        id: u64,
        value: ZeroString,
        inject: Inject,
    },
    Generation {
        id: u64,
        generation: u64,
    },
    Recorded {
        id: u64,
    },
    /// T13.03: the new value is stored; gates re-fetch.
    Rotated {
        id: u64,
    },
    /// T9.06: the credential's totals today, this report included.
    UsageToday {
        id: u64,
        requests: u64,
        tokens: u64,
    },
    /// T9.08: whether one of them is a planted canary.
    CanaryChecked {
        id: u64,
        tripped: bool,
    },
    Err {
        id: u64,
        error: String,
    },
}

impl GateResponse {
    pub fn id(&self) -> u64 {
        match self {
            Self::ResolveOk { id, .. }
            | Self::Generation { id, .. }
            | Self::Recorded { id }
            | Self::Rotated { id }
            | Self::UsageToday { id, .. }
            | Self::CanaryChecked { id, .. }
            | Self::Err { id, .. } => *id,
        }
    }
}

/// One provider route of an agent session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRoute {
    /// Key into kepr-gate's provider table, e.g. `anthropic`.
    pub provider: String,
    /// Credential NAME in the vault.
    pub cred: String,
    pub slot: u16,
    /// P7.1 database routes (`provider` = `db:<CRED>`): where the gate
    /// logs in. `None` for HTTP provider routes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<DbTarget>,
}

pub use crate::gate_target::{
    DbTarget, Ephemeral, RoleGrant, TargetKind, EPHEMERAL_DEFAULT_TTL, EPHEMERAL_TTL,
};

/// Route key for a database credential.
pub fn db_route_key(cred: &str) -> String {
    format!("db:{cred}")
}

/// Route key for a Kubernetes API server login (T13.04).
pub fn kube_route_key(cred: &str) -> String {
    format!("kube:{cred}")
}

/// Route key for a raw TCP tunnel named `name` (T7.03).
pub fn tunnel_route_key(name: &str) -> String {
    format!("tcp:{name}")
}

/// T2.02 (batch: aws): route key for a sealed AWS key (SigV4 re-signing).
pub fn aws_route_key(cred: &str) -> String {
    format!("aws:{cred}")
}

/// Route key for a provider-side rotation of `cred` (T13.03): the session
/// exists to rotate that sealed key, and only such a session may send
/// `RotateCommit`. An agent's own session never has one.
pub fn rotate_route_key(cred: &str) -> String {
    format!("rotate:{cred}")
}

impl GateRoute {
    pub fn is_tunnel(&self) -> bool {
        self.target
            .as_ref()
            .is_some_and(|t| t.kind == TargetKind::Tcp)
    }
}

/// The credentials a session may rotate (T13.03): its `rotate:` routes.
pub fn rotatable_creds(routes: &[GateRoute]) -> std::collections::HashSet<String> {
    routes
        .iter()
        .filter(|r| r.provider == rotate_route_key(&r.cred))
        .map(|r| r.cred.to_uppercase())
        .collect()
}

/// The credential NAMEs a session's gate may ask the daemon for: every
/// route's credential except a tunnel's (its "cred" is only its name),
/// plus the admin logins of role grants (T7.18).
pub fn resolvable_creds(routes: &[GateRoute]) -> std::collections::HashSet<String> {
    let admins = routes
        .iter()
        .filter_map(|r| r.target.as_ref()?.grant.as_ref())
        .map(|g| g.admin.to_uppercase());
    routes
        .iter()
        .filter(|r| !r.is_tunnel())
        .map(|r| r.cred.to_uppercase())
        .chain(admins)
        .collect()
}

/// What the daemon writes to a freshly spawned gate's stdin.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionConfig {
    /// 16 hex chars.
    pub session_id: String,
    /// 64 hex chars (32 bytes).
    pub session_key_hex: ZeroString,
    pub routes: Vec<GateRoute>,
    /// Fixed loopback port; `None` = any free port.
    #[serde(default)]
    pub port: Option<u16>,
    /// P9.5 spend and rate guard for this session.
    #[serde(default)]
    pub limits: GateLimits,
    /// P2.1 egress proxy: tunnel CONNECTs to hosts no route is bound to
    /// (off under `--isolate-net`, where only bound hosts are reachable).
    #[serde(default)]
    pub tunnel: bool,
    /// T7.09: send what the agent sends and receives to the daemon.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub record: bool,
}

/// System-mode daemon → kepr-gate service (T1.19), sent after the
/// session channel fd (SCM_RIGHTS) on the service's root-only socket.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceStart {
    /// The agent process; the session gate exits when it does.
    pub owner_pid: i32,
    pub config: SessionConfig,
}

/// The single line a gate prints to stdout once it is listening.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadyLine {
    pub ready: bool,
    pub port: u16,
    /// Provider name → placeholder (one per route; providers are unique).
    pub placeholders: std::collections::HashMap<String, String>,
    /// P2.1: the session CA (PEM) the egress proxy signs bound hosts with.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ca_pem: Option<String>,
    /// P7.1: route key (`db:<CRED>`) → local port of its database proxy.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub db_ports: std::collections::HashMap<String, u16>,
    /// Safe, standardized reason a gate could not become ready.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

/// Rules every StartGate request must meet, checked by the daemon before
/// it spawns a gate and again by the gate: bounded routes, known providers
/// or explicit HTTPS destinations,
/// unique providers and unique slots. Credential names are checked by
/// the daemon (`store::validate_name`).
pub fn validate_routes(routes: &[GateRoute]) -> Result<(), String> {
    if routes.is_empty() || routes.len() > crate::http_route::MAX_ROUTES {
        return Err(format!("an agent session needs 1-{} routes", crate::http_route::MAX_ROUTES));
    }
    for (i, r) in routes.iter().enumerate() {
        let db_ok = r.target.as_ref().is_some_and(|t| {
            let key = match t.kind {
                TargetKind::Tcp => tunnel_route_key(&r.cred),
                TargetKind::Kube => kube_route_key(&r.cred),
                _ => db_route_key(&r.cred),
            };
            r.provider == key && t.port != 0 && crate::binding::validate_host(&t.host).is_ok()
        });
        let aws_ok = r.target.is_none() && r.provider == aws_route_key(&r.cred);
        let rotate_ok = r.target.is_none() && r.provider == rotate_route_key(&r.cred);
        let http_ok = r.target.is_none() && crate::http_route::parse(&r.provider)
            .is_some_and(|(_, credential)| credential == r.cred);
        if !db_ok
            && !aws_ok
            && !rotate_ok
            && !http_ok
            && (r.target.is_some() || crate::providers::lookup(&r.provider).is_none())
        {
            return Err(format!("unknown provider {}", r.provider));
        }
        if let Some((t, e)) = r
            .target
            .as_ref()
            .and_then(|t| Some((t, t.ephemeral.as_ref()?)))
        {
            e.validate(t.kind, t)?;
        }
        if let Some((t, g)) = r.target.as_ref().and_then(|t| Some((t, t.grant.as_ref()?))) {
            g.validate(&r.cred, t.kind)?;
            // The agent would hold the admin login itself.
            if routes.iter().any(|o| o.cred.eq_ignore_ascii_case(&g.admin)) {
                return Err(format!(
                    "--grant: {} grants roles, so it can't also be a route of the session",
                    g.admin
                ));
            }
        }
        if routes[..i]
            .iter()
            .any(|o| o.provider == r.provider || o.slot == r.slot)
        {
            return Err("route providers and slots must be unique".into());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "gate_protocol_tests.rs"]
mod tests;
