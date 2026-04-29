// protocol.rs — shared request/response types for the CLI↔daemon Unix socket.
//
// Both kepr (client) and kepr-daemon import this module. Keep it
// minimal — only wire types + helpers that preserve wire invariants.
//
// Wire format (framed): <u32 BE length> <JSON payload>
//
// Request and Response are both tagged enums, so adding a new operation
// requires exactly one new variant — no god-struct with all-Option fields.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Socket path / limits ──────────────────────────────────────────────────────

pub const SOCKET_PATH: &str = "/run/kepr/kepr.sock";
#[allow(dead_code)]
pub const SOCKET_DIR: &str = "/run/kepr";
pub const MAX_MSG_BYTES: usize = 65_536; // 64 KB max framed message
pub const TIMEOUT_SECS: u64 = 10;

// ── Request ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum Request {
    Set {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<String>, // None = generate
        #[serde(skip_serializing_if = "Option::is_none")]
        generate: Option<String>, // "hex"|"base62"|"pass"|"uuid"
    },
    Get {
        name: String,
    },
    List,
    Delete {
        name: String,
    },
    Check,
    Ping,
}

// ── Response ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    SetOk {
        name: String,
        cred_name: String,
    },
    GetOk {
        name: String,
        value: String,
    },
    DeleteOk {
        name: String,
    },
    ListOk {
        credentials: Vec<CredInfo>,
        count: usize,
    },
    CheckOk {
        results: HashMap<String, String>,
        count: usize,
        all_ok: bool,
    },
    Pong,
    Err {
        error: String,
    },
}

impl Response {
    /// Transport-level success (request was understood and not rejected).
    /// A CheckOk with `all_ok=false` is still transport-ok.
    #[allow(dead_code)]
    pub fn is_transport_ok(&self) -> bool {
        !matches!(self, Response::Err { .. })
    }

    /// Semantic success — used for the CLI's exit code.
    /// False for any Err and for CheckOk with a failing credential.
    pub fn is_success(&self) -> bool {
        match self {
            Response::Err { .. } => false,
            Response::CheckOk { all_ok, .. } => *all_ok,
            _ => true,
        }
    }

    #[allow(dead_code)]
    pub fn err_msg(&self) -> Option<&str> {
        if let Response::Err { error } = self {
            Some(error)
        } else {
            None
        }
    }

    /// Convenience constructor used throughout the codebase.
    pub fn fail(msg: impl Into<String>) -> Self {
        Response::Err { error: msg.into() }
    }
}

// ── Credential info (for ListOk) ──────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredInfo {
    pub name: String,      // ENV_VAR_NAME
    pub cred_name: String, // kepr-<uid>-env-var-name
    pub size: u64,
    pub modified: String, // YYYY-MM-DD HH:MM
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn as_value<T: Serialize>(v: &T) -> Value {
        serde_json::to_value(v).expect("serialize")
    }

    fn roundtrip_request(req: &Request) -> Value {
        let bytes = serde_json::to_vec(req).expect("to_vec");
        let back: Request = serde_json::from_slice(&bytes).expect("from_slice");
        as_value(&back)
    }

    #[test]
    fn request_wire_tag_is_lowercase_cmd() {
        assert_eq!(as_value(&Request::Ping)["cmd"], json!("ping"));
        assert_eq!(as_value(&Request::List)["cmd"], json!("list"));
        assert_eq!(as_value(&Request::Check)["cmd"], json!("check"));
        assert_eq!(
            as_value(&Request::Get { name: "X".into() })["cmd"],
            json!("get")
        );
        assert_eq!(
            as_value(&Request::Delete { name: "X".into() })["cmd"],
            json!("delete")
        );
        assert_eq!(
            as_value(&Request::Set {
                name: "X".into(),
                value: None,
                generate: None
            })["cmd"],
            json!("set"),
        );
    }

    #[test]
    fn request_roundtrip_preserves_all_variants() {
        let cases = [
            Request::Ping,
            Request::List,
            Request::Check,
            Request::Get {
                name: "OPENAI".into(),
            },
            Request::Delete { name: "FOO".into() },
            Request::Set {
                name: "K".into(),
                value: Some("v".into()),
                generate: None,
            },
            Request::Set {
                name: "K".into(),
                value: None,
                generate: Some("hex".into()),
            },
            Request::Set {
                name: "K".into(),
                value: None,
                generate: None,
            },
        ];
        for req in cases {
            assert_eq!(as_value(&req), roundtrip_request(&req));
        }
    }

    #[test]
    fn set_optional_fields_omitted_when_none() {
        let req = Request::Set {
            name: "X".into(),
            value: None,
            generate: None,
        };
        let v = as_value(&req);
        assert!(v.get("value").is_none(), "value should be absent: {v}");
        assert!(
            v.get("generate").is_none(),
            "generate should be absent: {v}"
        );
    }

    #[test]
    fn response_err_wire_shape() {
        let r = Response::fail("boom");
        let v = as_value(&r);
        assert_eq!(v["kind"], json!("err"));
        assert_eq!(v["error"], json!("boom"));
        assert!(!r.is_transport_ok());
        assert!(!r.is_success());
        assert_eq!(r.err_msg(), Some("boom"));
    }

    #[test]
    fn response_variant_tags() {
        assert_eq!(as_value(&Response::Pong)["kind"], json!("pong"));
        assert_eq!(
            as_value(&Response::SetOk {
                name: "X".into(),
                cred_name: "y".into()
            })["kind"],
            json!("set_ok"),
        );
        assert_eq!(
            as_value(&Response::GetOk {
                name: "X".into(),
                value: "v".into()
            })["kind"],
            json!("get_ok"),
        );
        assert_eq!(
            as_value(&Response::DeleteOk { name: "X".into() })["kind"],
            json!("delete_ok"),
        );
    }

    #[test]
    fn response_list_roundtrip() {
        let r = Response::ListOk {
            credentials: vec![CredInfo {
                name: "X".into(),
                cred_name: "kepr-1000-x".into(),
                size: 42,
                modified: "2024-01-01 00:00".into(),
            }],
            count: 1,
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: Response = serde_json::from_slice(&bytes).unwrap();
        match back {
            Response::ListOk { credentials, count } => {
                assert_eq!(count, 1);
                assert_eq!(credentials[0].name, "X");
                assert_eq!(credentials[0].size, 42);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn response_check_all_ok_drives_is_success() {
        let mut results = HashMap::new();
        results.insert("A".into(), "ok".into());
        results.insert("B".into(), "failed".into());
        let r = Response::CheckOk {
            results,
            count: 2,
            all_ok: false,
        };
        // transport-ok (the daemon answered), but semantic-fail (a cred is broken)
        assert!(r.is_transport_ok());
        assert!(!r.is_success());
    }

    #[test]
    fn response_get_roundtrip() {
        let r = Response::GetOk {
            name: "X".into(),
            value: "secret".into(),
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: Response = serde_json::from_slice(&bytes).unwrap();
        match back {
            Response::GetOk { name, value } => {
                assert_eq!(name, "X");
                assert_eq!(value, "secret");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
