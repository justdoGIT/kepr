// protocol.rs — shared request/response types for the CLI↔daemon Unix socket.
//
// Both kepr (client) and kepr-daemon import this module. Keep it
// minimal — only wire types + helpers that preserve wire invariants.
//
// Wire format (framed): <u32 BE length> <JSON payload>
//
// Request and Response are both tagged enums, so adding a new operation
// requires exactly one new variant — no god-struct with all-Option fields.

use crate::generate::ZeroString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Runtime paths are user-scoped by default. Set `KEPR_SYSTEM_MODE=1` for the
// optional root-managed deployment that uses the historical /run/kepr path.
pub fn socket_path() -> std::path::PathBuf {
    if std::env::var_os("KEPR_SYSTEM_MODE").is_some() {
        return std::path::PathBuf::from("/run/kepr/kepr.sock");
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join(".local/state/kepr/runtime")
        });
    runtime.join("kepr").join("kepr.sock")
}

pub fn socket_dir() -> std::path::PathBuf {
    socket_path()
        .parent()
        .expect("kepr socket always has a parent")
        .to_path_buf()
}

#[allow(dead_code)]
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
        // ZeroString rather than String so the secret value transits
        // through the client process and serde's intermediate buffer
        // in a wrapper that zeroises on drop. Symmetric with
        // `Response::GetOk.value`. Wire format unchanged (still a
        // JSON string when present).
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<ZeroString>, // None = generate
        #[serde(skip_serializing_if = "Option::is_none")]
        generate: Option<String>, // "hex"|"base62"|"pass"|"uuid"
        /// Phase 2 α: optional time-to-live in seconds. When set, the
        /// daemon writes a sidecar metadata file recording the absolute
        /// unix timestamp at which this credential expires. After that
        /// instant, `handle_get` returns `credential unavailable`
        /// regardless of whether the on-disk ciphertext is still
        /// readable. A future PR adds a sweeper thread that GCs the
        /// expired files; this PR limits scope to the access-time
        /// check, so expired files take up disk until manually deleted
        /// or until the sweeper lands.
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_secs: Option<u64>,
        /// Phase 2 ε: gate `get` behind a polkit consent prompt.
        /// When `Some(true)`, the daemon writes a `requires_consent`
        /// flag into the sidecar metadata; subsequent `Get` calls
        /// pkcheck the calling process before decrypting. Pre-Phase-
        /// 2-ε daemons ignore the field (skip_serializing_if).
        #[serde(skip_serializing_if = "Option::is_none")]
        requires_consent: Option<bool>,
        /// Phase 2 η: gate `get` behind a FIDO2 hardware-key
        /// assertion. When `Some(true)`, the daemon writes a
        /// `requires_fido2` flag into the sidecar metadata;
        /// subsequent `Get` calls receive a `Fido2Needed` challenge
        /// and must be retried with a valid FIDO2 assertion.
        #[serde(skip_serializing_if = "Option::is_none")]
        requires_fido2: Option<bool>,
    },
    Get {
        name: String,
        /// Phase 2 η: FIDO2 assertion payload for the second
        /// round-trip of a FIDO2-gated Get. Absent on the first
        /// call (daemon returns `Fido2Needed`), present on the
        /// retry. Old daemons ignore the field (skip_serializing_if);
        /// old clients never send it. Hex-encoded bytes fields
        /// match the wire shape of the `Fido2Assertion` client-side
        /// struct so the JSON round-trip is transparent.
        #[serde(skip_serializing_if = "Option::is_none")]
        fido2_assertion: Option<Fido2Assertion>,
    },
    List,
    Delete {
        name: String,
    },
    Check,
    /// Phase 2 δ.3 — verify the daemon's hash-chained audit log at
    /// `/var/lib/kepr/audit.log`. The daemon walks the file and
    /// returns `Response::AuditOk { entries, last_hash }` on
    /// success or `Response::Err` with a line-number-tagged tamper
    /// reason. The chain file itself is root-only readable, so
    /// this is the only path a kepr-group member has to inspect it.
    AuditVerify,
    /// Phase 2 η: register a FIDO2 credential with the daemon.
    /// The client sends the credential ID and public key (in COSE
    /// format, hex-encoded). The daemon stores the mapping and
    /// returns the credential ID on success. The `label` is a
    /// human-readable name for `kepr fido2 list`.
    Fido2Register {
        label: String,
        credential_id: String,   // hex
        public_key_cose: String, // hex — COSE_Key CBOR bytes
    },
    /// Phase 2 η: list registered FIDO2 credentials.
    Fido2List,
    Lock {
        password: ZeroString,
    },
    Unlock {
        password: ZeroString,
    },
    Status,
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
        // ZeroString rather than String so the deserialised secret on
        // the client side is wiped from memory when the Response is
        // dropped, instead of leaking through serde's allocation pool
        // until the GC happens to overwrite the heap region. Wire
        // format unchanged (still a JSON string); old daemons / new
        // clients and vice versa interoperate.
        value: ZeroString,
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
    /// Phase 2 δ.3 — successful audit-chain verification. `entries`
    /// is the count of validated chain entries; `last_hash` is the
    /// hex-encoded head, intended for external attestation against
    /// a checkpoint store (Phase 3 Sigstore Rekor anchor).
    AuditOk {
        entries: usize,
        last_hash: String,
    },
    /// Phase 2 η: a FIDO2 assertion is required to decrypt this
    /// credential. The client should obtain an assertion from the
    /// FIDO2 authenticator identified by `credential_ids` over
    /// `challenge`, then retry `Get` with `fido2_assertion` set.
    Fido2Needed {
        name: String,
        /// 32 random bytes, hex-encoded. The client must include
        /// this challenge verbatim in the `clientDataJSON` passed
        /// to the authenticator.
        challenge: String,
        /// The credential IDs registered for this user whose
        /// associated public keys the daemon can verify. The
        /// client picks one that the user's authenticator holds.
        credential_ids: Vec<String>, // hex
    },
    /// Phase 2 η: successful FIDO2 registration. The daemon echoes
    /// the credential ID it stored.
    Fido2RegisterOk {
        credential_id: String,
    },
    /// Phase 2 η: list of registered FIDO2 credentials.
    Fido2ListOk {
        credentials: Vec<Fido2CredInfo>,
    },
    Pong,
    LockedOk,
    UnlockedOk,
    StatusOk {
        locked: bool,
        password_protected: bool,
    },
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
    /// Phase 2 α: human-readable absolute expiry timestamp
    /// (`YYYY-MM-DD HH:MM`) for creds that were set with `--ttl`.
    /// `None` for credentials with no TTL — same wire shape as the
    /// pre-Phase-2 daemon (the field is `skip_serializing_if =
    /// "Option::is_none"`, so old clients never see the field and
    /// new clients tolerate the missing-field path).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<String>,
    /// Phase 2 ε: true iff `kepr get` for this credential requires
    /// a polkit consent prompt before the daemon decrypts. Surfaces
    /// in `kepr list` so the user can spot consent-flagged creds at
    /// a glance. Same backward-compat shape as `expires_at`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_consent: Option<bool>,
    /// Phase 2 η: true iff `kepr get` for this credential requires a
    /// FIDO2 hardware-key assertion before the daemon decrypts.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_fido2: Option<bool>,
}

// ── FIDO2 types (Phase 2 η) ─────────────────────────────────────────────────

/// A FIDO2 assertion produced by the client's authenticator. Sent as
/// the second round-trip payload on `Request::Get` when the daemon
/// returned `Fido2Needed`. All byte fields are hex-encoded.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Fido2Assertion {
    /// The credential ID (from the authenticator). Hex-encoded.
    pub credential_id: String,
    /// The clientDataJSON that was hashed and signed. Hex-encoded
    /// raw bytes — the daemon reconstructs the SHA-256 hash and
    /// verifies it against the authenticator data.
    pub client_data_json: String, // hex
    /// The authenticatorData bytes returned by the authenticator.
    /// Contains the RP ID hash, flags, and signature counter.
    pub authenticator_data: String, // hex
    /// The assertion signature over (authenticator_data ||
    /// sha256(client_data_json)). Hex-encoded raw bytes.
    pub signature: String, // hex
}

/// A registered FIDO2 credential, returned by `Fido2ListOk`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Fido2CredInfo {
    /// Human-readable label assigned at registration time.
    pub label: String,
    /// The FIDO2 credential ID, hex-encoded.
    pub credential_id: String,
    /// The user ID (kepr uid) this credential is registered for.
    pub uid: u32,
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
            as_value(&Request::Get {
                name: "X".into(),
                fido2_assertion: None,
            })["cmd"],
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
                generate: None,
                ttl_secs: None,
                requires_consent: None,
                requires_fido2: None,
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
                fido2_assertion: None,
            },
            Request::Delete { name: "FOO".into() },
            Request::Set {
                name: "K".into(),
                value: Some("v".into()),
                generate: None,
                ttl_secs: None,
                requires_consent: None,
                requires_fido2: None,
            },
            Request::Set {
                name: "K".into(),
                value: None,
                generate: Some("hex".into()),
                ttl_secs: None,
                requires_consent: None,
                requires_fido2: None,
            },
            Request::Set {
                name: "K".into(),
                value: None,
                generate: None,
                ttl_secs: None,
                requires_consent: None,
                requires_fido2: None,
            },
            // Phase 2 α: TTL-bearing variant must round-trip cleanly.
            Request::Set {
                name: "EPHEMERAL".into(),
                value: Some("v".into()),
                generate: None,
                ttl_secs: Some(60),
                requires_consent: None,
                requires_fido2: None,
            },
            // Phase 2 ε: consent-bearing variant must round-trip cleanly.
            Request::Set {
                name: "GUARDED".into(),
                value: Some("v".into()),
                generate: None,
                ttl_secs: None,
                requires_consent: Some(true),
                requires_fido2: None,
            },
            // Phase 2 η: FIDO2-bearing variant must round-trip cleanly.
            Request::Set {
                name: "FIDO2_GUARDED".into(),
                value: Some("v".into()),
                generate: None,
                ttl_secs: None,
                requires_consent: None,
                requires_fido2: Some(true),
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
            ttl_secs: None,
            requires_consent: None,
            requires_fido2: None,
        };
        let v = as_value(&req);
        assert!(v.get("value").is_none(), "value should be absent: {v}");
        // Phase 2 α: ttl_secs uses skip_serializing_if so old daemons
        // never see the field. Pin the wire shape.
        assert!(
            v.get("ttl_secs").is_none(),
            "ttl_secs should be absent when None: {v}"
        );
        assert!(
            v.get("generate").is_none(),
            "generate should be absent: {v}"
        );
        // Phase 2 η: requires_fido2 uses skip_serializing_if.
        assert!(
            v.get("requires_fido2").is_none(),
            "requires_fido2 should be absent when None: {v}"
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
                expires_at: None,
                requires_consent: None,
                requires_fido2: None,
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
                // Compare via as_str so we go through the same Deref path
                // any consumer that displays the value would: confirms
                // the deserialised ZeroString carries the original
                // plaintext, even though Debug/PartialEq of the
                // ZeroString itself never expose the bytes.
                assert_eq!(value.as_str(), "secret");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn response_get_value_zeroizes_on_drop() {
        // Pin the property the wire-side ZeroString switch is supposed
        // to deliver: dropping the deserialised Response must run
        // ZeroString's Drop, which zeroizes the underlying bytes. We
        // can't directly observe the freed memory after drop without
        // tooling, but we can at least exercise the path and confirm
        // the bytes round-trip cleanly while alive.
        let bytes = serde_json::to_vec(&Response::GetOk {
            name: "Y".into(),
            value: "alive".into(),
        })
        .unwrap();
        let back: Response = serde_json::from_slice(&bytes).unwrap();
        match back {
            Response::GetOk { value, .. } => {
                assert_eq!(value.as_str(), "alive");
                drop(value); // explicit Drop-and-zeroize
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
