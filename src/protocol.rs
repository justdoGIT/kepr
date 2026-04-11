// protocol.rs — shared request/response types
//
// Everything that crosses the Unix socket lives here.
// Both credman (client) and credman-daemon import this module.
// Keep it minimal — only wire types, no logic.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Socket path ───────────────────────────────────────────────────────────────

pub const SOCKET_PATH:    &str = "/run/credman/credman.sock";
#[allow(dead_code)]
pub const SOCKET_DIR:     &str = "/run/credman";
pub const MAX_MSG_BYTES:  usize = 65_536;   // 64 KB max message
pub const TIMEOUT_SECS:   u64   = 10;

// ── Request ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum Request {
    Set {
        name:     String,
        #[serde(skip_serializing_if = "Option::is_none")]
        value:    Option<String>,       // None = generate
        #[serde(skip_serializing_if = "Option::is_none")]
        generate: Option<String>,       // "hex"|"base62"|"pass"|"uuid"
    },
    Get    { name: String },
    List,
    Delete { name: String },
    Check,
    Ping,
}

// ── Response ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok:             bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name:           Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_name:      Option<String>,

    // value is present only for Get responses
    // daemon sends it over socket (socket is root:credman-group protected)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value:          Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:          Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials:    Option<Vec<CredInfo>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub count:          Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub results:        Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pong:           Option<bool>,
}

impl Response {
    #[allow(dead_code)]
    pub fn ok() -> Self {
        Self { ok: true, ..Self::empty() }
    }

    pub fn fail(msg: &str) -> Self {
        Self { ok: false, error: Some(msg.to_string()), ..Self::empty() }
    }

    pub fn empty() -> Self {
        Self {
            ok: false, name: None, cred_name: None,
            value: None, error: None, credentials: None,
            count: None, results: None, pong: None,
        }
    }
}

// ── Credential info (for list) ────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredInfo {
    pub name:       String,     // ENV_VAR_NAME
    pub cred_name:  String,     // credman-<uid>-env-var-name
    pub size:       u64,
    pub modified:   String,     // YYYY-MM-DD HH:MM
}
