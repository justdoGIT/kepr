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
        generate: Option<String>, // "hex"|"base62"|"pass"|"uuid"|"words"
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
        /// Agent vault P1: write-only credential. The daemon refuses
        /// `Get` and releases the value only to a daemon-spawned
        /// kepr-gate, for a host in `bindings`. Requires `bindings`.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        sealed: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        bindings: Option<Vec<crate::binding::Binding>>,
    },
    /// Agent vault P1: start a kepr-gate for the calling process
    /// (the agent harness, after exec). User-mode daemon only.
    StartGate {
        routes: Vec<crate::gate_protocol::GateRoute>,
        /// Fixed loopback port (for harnesses whose config file holds
        /// a fixed base URL). `None` = any free port.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        port: Option<u16>,
        /// P9.5 per-session request / token / rate caps.
        #[serde(
            skip_serializing_if = "crate::gate_protocol::GateLimits::is_none",
            default
        )]
        limits: crate::gate_protocol::GateLimits,
        /// P2.1: let the egress proxy tunnel hosts no route is bound to.
        #[serde(default)]
        tunnel: bool,
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
    /// `kepr panic`: stop the caller's gates; lock if passphrase-protected.
    Panic,
    /// P2.4 SSH agent: create a new sign-only Ed25519 key in the vault.
    SshGenerate {
        name: String,
        comment: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        requires_consent: Option<bool>,
    },
    /// Import an unencrypted OpenSSH Ed25519 private key (sign-only after).
    SshImport {
        name: String,
        private_key: ZeroString,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        requires_consent: Option<bool>,
    },
    SshList,
    /// Sign `data_b64` with the named key; the private key never leaves
    /// the daemon.
    SshSign {
        name: String,
        data_b64: String,
    },
    /// P5.3: list saved previous values of a credential (no values).
    History {
        name: String,
    },
    /// P5.3: make history version `version` (1 = newest) current again.
    Restore {
        name: String,
        version: u32,
    },
    /// P9.6: per-credential usage from the audit log (last `days`, or all).
    Usage {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        days: Option<u32>,
    },
    /// P6.4: weak / reused / old credentials (flags only, no values).
    Health {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        max_age_days: Option<u32>,
    },
    /// P6.4: is `name`'s SHA-1 among these breach-list suffixes (the
    /// public range for the prefix `Health` returned)?
    BreachCheck {
        name: String,
        suffixes: Vec<String>,
    },
    /// P9.8 leak response: stop the caller's agent gates, delete the
    /// credential and its history, record an incident.
    Leaked {
        name: String,
    },
    /// P6.3: split the master key into k-of-n recovery shares. Needs the
    /// store passphrase; owner / root only.
    RecoveryKitCreate {
        password: ZeroString,
        threshold: u8,
        shares: u8,
    },
    /// P6.3: rebuild a lost master key from shares, under a new passphrase.
    RecoveryRestore {
        shares: Vec<ZeroString>,
        new_password: ZeroString,
    },
    /// P6.1: this user's share public key (`create`: make one if missing).
    ShareKey {
        #[serde(default)]
        create: bool,
    },
    /// P6.2: encrypt `name` to the public key `to` (expires after ttl).
    ShareSend {
        name: String,
        to: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        ttl_secs: Option<u64>,
    },
    /// P6.2: decrypt and store a share (single use), optionally renamed.
    ShareReceive {
        envelope: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        name: Option<String>,
    },
    /// P7.2: rotate a sealed database login: `begin` adds a random
    /// pending password, `commit` makes it current, `abort` drops it.
    DbRotate {
        name: String,
        phase: String,
    },
    /// P5.1: store a typed record; `fields` is a JSON object of strings.
    RecordSet {
        name: String,
        record_type: String,
        fields: ZeroString,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        requires_consent: Option<bool>,
        /// P7.1: seal a `database` record for the gate's database proxy;
        /// the daemon binds it to the record's own host:port.
        #[serde(default)]
        seal: bool,
    },
    // ── P2–P11 ticket batches: one `#[serde(untagged)]` variant per batch,
    // wrapping that batch's own `#[serde(tag = "cmd")]` enum in
    // `protocol_<batch>.rs`. Untagged variants must stay last.
    // batch: vault
    // batch: seal
    // batch: store
    #[serde(untagged)]
    Store(crate::protocol_store::StoreRequest),
    // batch: records
    // batch: share
    #[serde(untagged)]
    Sharing(crate::protocol_sharing::SharingRequest),
    // batch: sync
    // batch: policy
    // batch: gate
    // batch: aws
    // batch: eco
    #[serde(untagged)]
    Eco(crate::protocol_eco::EcoRequest),
    // batch: platform
    // batch: session
    // end of batches
}

pub use crate::protocol_response::Response;
pub use crate::protocol_types::{
    CredInfo, Fido2Assertion, Fido2CredInfo, HistoryEntry, KeyHealth, KeyUsage, SshKeyInfo,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::collections::HashMap;

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
                sealed: None,
                bindings: None,
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
                sealed: None,
                bindings: None,
            },
            Request::Set {
                name: "K".into(),
                value: None,
                generate: Some("hex".into()),
                ttl_secs: None,
                requires_consent: None,
                requires_fido2: None,
                sealed: None,
                bindings: None,
            },
            Request::Set {
                name: "K".into(),
                value: None,
                generate: None,
                ttl_secs: None,
                requires_consent: None,
                requires_fido2: None,
                sealed: None,
                bindings: None,
            },
            // Phase 2 α: TTL-bearing variant must round-trip cleanly.
            Request::Set {
                name: "EPHEMERAL".into(),
                value: Some("v".into()),
                generate: None,
                ttl_secs: Some(60),
                requires_consent: None,
                requires_fido2: None,
                sealed: None,
                bindings: None,
            },
            // Phase 2 ε: consent-bearing variant must round-trip cleanly.
            Request::Set {
                name: "GUARDED".into(),
                value: Some("v".into()),
                generate: None,
                ttl_secs: None,
                requires_consent: Some(true),
                requires_fido2: None,
                sealed: None,
                bindings: None,
            },
            // Phase 2 η: FIDO2-bearing variant must round-trip cleanly.
            Request::Set {
                name: "FIDO2_GUARDED".into(),
                value: Some("v".into()),
                generate: None,
                ttl_secs: None,
                requires_consent: None,
                requires_fido2: Some(true),
                sealed: None,
                bindings: None,
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
            sealed: None,
            bindings: None,
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
                cred_name: "y".into(),
                password_protected: false,
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
                ..Default::default()
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
