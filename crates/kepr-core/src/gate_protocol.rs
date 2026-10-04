//! Private daemon ↔ kepr-gate protocol (agent vault plan §4.3).
//!
//! These messages travel only over the socket pair the daemon creates
//! when it spawns a gate (`Request::StartGate`). The daemon never
//! accepts them on its public socket, so no other process can ask for a
//! sealed value.

use crate::binding::Inject;
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
    Err {
        id: u64,
        error: String,
    },
}

impl GateResponse {
    pub fn id(&self) -> u64 {
        match self {
            Self::ResolveOk { id, .. } | Self::Generation { id, .. } | Self::Err { id, .. } => *id,
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
}

/// The single line a gate prints to stdout once it is listening.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadyLine {
    pub ready: bool,
    pub port: u16,
    /// Provider name → placeholder (one per route; providers are unique).
    pub placeholders: std::collections::HashMap<String, String>,
}

/// Rules every StartGate request must meet, checked by the daemon before
/// it spawns a gate and again by the gate: 1-16 routes, known providers,
/// unique providers and unique slots. Credential names are checked by
/// the daemon (`store::validate_name`).
pub fn validate_routes(routes: &[GateRoute]) -> Result<(), String> {
    if routes.is_empty() || routes.len() > 16 {
        return Err("an agent session needs 1-16 routes".into());
    }
    for (i, r) in routes.iter().enumerate() {
        if crate::providers::lookup(&r.provider).is_none() {
            return Err(format!("unknown provider {}", r.provider));
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
mod tests {
    use super::*;

    #[test]
    fn gate_messages_round_trip() {
        let r = GateRequest::Resolve {
            id: 7,
            name: "A".into(),
            host: "api.x.ai".into(),
            port: 443,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains(r#""cmd":"resolve""#));
        let _: GateRequest = serde_json::from_str(&j).unwrap();
        let ok = GateResponse::ResolveOk {
            id: 7,
            value: ZeroString::from_string("v".into()),
            inject: Inject::Bearer,
        };
        let j = serde_json::to_string(&ok).unwrap();
        let back: GateResponse = serde_json::from_str(&j).unwrap();
        assert_eq!(back.id(), 7);
    }

    #[test]
    fn route_rules() {
        let r = |p: &str, slot: u16| GateRoute {
            provider: p.into(),
            cred: "K".into(),
            slot,
        };
        assert!(validate_routes(&[r("anthropic", 0), r("xai", 1)]).is_ok());
        assert!(validate_routes(&[]).is_err());
        assert!(validate_routes(&[r("nope", 0)]).is_err());
        assert!(validate_routes(&[r("xai", 0), r("xai", 1)]).is_err());
        assert!(validate_routes(&[r("xai", 0), r("openai", 0)]).is_err());
        assert!(validate_routes(&(0..17).map(|i| r("xai", i)).collect::<Vec<_>>()).is_err());
    }

    #[test]
    fn resolve_is_not_a_public_request() {
        let j = r#"{"cmd":"resolve","name":"A","host":"api.x.ai","port":443}"#;
        assert!(serde_json::from_str::<crate::protocol::Request>(j).is_err());
    }
}
