//! Private daemon ↔ kepr-gate protocol (agent vault plan §4.3).
//!
//! These messages travel only over the socket pair the daemon creates
//! when it spawns a gate (`Request::StartGate`). The daemon never
//! accepts them on its public socket, so no other process can ask for a
//! sealed value.

use crate::binding::Inject;
use crate::generate::ZeroString;
use serde::{Deserialize, Serialize};

/// Gate → daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum GateRequest {
    Resolve {
        name: String,
        host: String,
        port: u16,
    },
}

/// Daemon → gate.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GateResponse {
    ResolveOk { value: ZeroString, inject: Inject },
    Err { error: String },
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
    /// Credential NAME → placeholder.
    pub placeholders: std::collections::HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_messages_round_trip() {
        let r = GateRequest::Resolve {
            name: "A".into(),
            host: "api.x.ai".into(),
            port: 443,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains(r#""cmd":"resolve""#));
        let _: GateRequest = serde_json::from_str(&j).unwrap();
        let ok = GateResponse::ResolveOk {
            value: ZeroString::from_string("v".into()),
            inject: Inject::Bearer,
        };
        let j = serde_json::to_string(&ok).unwrap();
        let _: GateResponse = serde_json::from_str(&j).unwrap();
    }

    #[test]
    fn resolve_is_not_a_public_request() {
        let j = r#"{"cmd":"resolve","name":"A","host":"api.x.ai","port":443}"#;
        assert!(serde_json::from_str::<crate::protocol::Request>(j).is_err());
    }
}
