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
        // The daemon dispatches on `cmd`. Regressing the tag or casing
        // would silently break every client.
        assert_eq!(as_value(&Request::Ping)["cmd"],   json!("ping"));
        assert_eq!(as_value(&Request::List)["cmd"],   json!("list"));
        assert_eq!(as_value(&Request::Check)["cmd"],  json!("check"));
        assert_eq!(
            as_value(&Request::Get { name: "X".into() })["cmd"],
            json!("get"),
        );
        assert_eq!(
            as_value(&Request::Delete { name: "X".into() })["cmd"],
            json!("delete"),
        );
        assert_eq!(
            as_value(&Request::Set {
                name: "X".into(), value: None, generate: None,
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
            Request::Get    { name: "OPENAI".into() },
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
            let original = as_value(&req);
            let back     = roundtrip_request(&req);
            assert_eq!(original, back, "roundtrip changed variant: {original}");
        }
    }

    #[test]
    fn set_optional_fields_omitted_when_none() {
        // `skip_serializing_if` keeps the wire compact and avoids leaking `null`s.
        let req = Request::Set {
            name: "X".into(), value: None, generate: None,
        };
        let v = as_value(&req);
        assert!(v.get("value").is_none(),    "value should be absent: {v}");
        assert!(v.get("generate").is_none(), "generate should be absent: {v}");
    }

    #[test]
    fn response_fail_shape() {
        let r = Response::fail("boom");
        assert!(!r.ok);
        assert_eq!(r.error.as_deref(), Some("boom"));
        // Every other field is None — the CLI checks these.
        assert!(r.name.is_none());
        assert!(r.cred_name.is_none());
        assert!(r.value.is_none());
        assert!(r.credentials.is_none());
        assert!(r.count.is_none());
        assert!(r.results.is_none());
        assert!(r.pong.is_none());
    }

    #[test]
    fn response_ok_serializes_without_nulls() {
        // A bare `ok: true` response must not serialize any `null` keys —
        // JSON-mode consumers parse this output.
        let v = as_value(&Response::ok());
        let obj = v.as_object().expect("response is a JSON object");
        assert_eq!(obj.len(), 1, "unexpected extra keys: {v}");
        assert_eq!(obj.get("ok"), Some(&json!(true)));
    }

    #[test]
    fn response_roundtrip() {
        let resp = Response {
            ok: true,
            name: Some("X".into()),
            value: Some("secret".into()),
            ..Response::empty()
        };
        let bytes = serde_json::to_vec(&resp).expect("to_vec");
        let back: Response = serde_json::from_slice(&bytes).expect("from_slice");
        assert!(back.ok);
        assert_eq!(back.name.as_deref(),  Some("X"));
        assert_eq!(back.value.as_deref(), Some("secret"));
        assert!(back.error.is_none());
    }

    #[test]
    fn response_list_and_check_shapes_roundtrip() {
        // Exercises the collection fields `credentials` and `results` so a
        // stray `skip_serializing_if` regression on either would be caught.
        let list_resp = Response {
            ok: true,
            count: Some(1),
            credentials: Some(vec![CredInfo {
                name:      "X".into(),
                cred_name: "credman-1000-x".into(),
                size:      42,
                modified:  "2024-01-01 00:00".into(),
            }]),
            ..Response::empty()
        };
        let bytes = serde_json::to_vec(&list_resp).expect("to_vec");
        let back: Response = serde_json::from_slice(&bytes).expect("from_slice");
        let creds = back.credentials.expect("credentials must roundtrip");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].name, "X");
        assert_eq!(creds[0].size, 42);
        assert_eq!(back.count, Some(1));

        let mut results = HashMap::new();
        results.insert("A".to_string(), "ok".to_string());
        results.insert("B".to_string(), "failed".to_string());
        let check_resp = Response {
            ok: false,
            results: Some(results),
            count: Some(2),
            ..Response::empty()
        };
        let bytes = serde_json::to_vec(&check_resp).expect("to_vec");
        let back: Response = serde_json::from_slice(&bytes).expect("from_slice");
        let r = back.results.expect("results must roundtrip");
        assert_eq!(r.get("A").map(String::as_str), Some("ok"));
        assert_eq!(r.get("B").map(String::as_str), Some("failed"));
    }
}
