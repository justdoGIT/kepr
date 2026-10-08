// protocol_types.rs — record types carried inside protocol.rs's Request
// and Response variants (credential listings, FIDO2 payloads, SSH key
// info). Split out of protocol.rs (LOC limit); re-exported from there.

use serde::{Deserialize, Serialize};

/// One SSH key, as `kepr ssh list` and the agent see it (no secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyInfo {
    pub name: String,
    /// Public key blob, base64.
    pub public_b64: String,
    pub comment: String,
}

/// One saved previous value (P5.3), as `kepr history` shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// 1 = the most recently replaced value.
    pub version: u32,
    /// `YYYY-MM-DD HH:MM` UTC, when it was replaced.
    pub saved_at: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sealed: Option<bool>,
}

/// One credential's usage (P9.6), as `kepr usage` shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUsage {
    pub name: String,
    /// Successful get / gate resolve / SSH sign in the window.
    pub uses: u64,
    /// Refused attempts in the window.
    pub refused: u64,
    /// Last successful use, any time (`YYYY-MM-DD HH:MM` UTC).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_used: Option<String>,
}

/// One credential's health (P6.4), as `kepr health` shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHealth {
    pub name: String,
    /// Human-readable findings; empty = healthy.
    pub issues: Vec<String>,
    /// Days since the value last changed.
    pub age_days: u64,
    /// First 5 hex digits of the value's SHA-1, for the breach-list
    /// range lookup. Absent for sealed credentials.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hibp_prefix: Option<String>,
    /// T11.23: findings the owner chose to ignore (moved out of `issues`).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ignored: Vec<String>,
    /// T11.23: the finding kinds ignored for this credential, so a client
    /// can apply them to findings it adds itself (breaches).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ignore: Vec<String>,
}

/// Optional parts of `GateStarted` (P2.1 egress CA, P7.1 database ports).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GateExtras {
    /// Session CA (PEM) for the egress proxy; tools must trust it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ca_pem: Option<String>,
    /// `db:<CRED>` → local port of the gate's database proxy.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub db_ports: std::collections::HashMap<String, u16>,
    /// The gate session's id (`kepr agent replay` / `kepr agent logs`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session: Option<String>,
}

// ── Credential info (for ListOk) ──────────────────────────────────────────────

/// `Default` lets literals name only the fields they set (`..Default::default()`),
/// so a batch adding an optional field doesn't touch every literal.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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
    /// Agent vault P1: true iff the credential is write-only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sealed: Option<bool>,
    /// Hosts a sealed credential is bound to (no secret material).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bound_hosts: Option<Vec<String>>,
    /// P5.1: typed record (`login`, `card`, …); absent for a plain value.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub record_type: Option<String>,
    // ── P2–P11 ticket batches: new optional fields under the batch's marker.
    // batch: vault
    // batch: seal
    // batch: store
    /// T5.01: tags and folder (no secret material).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub folder: Option<String>,
    /// T11.5: this entry is an alias of that credential.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alias_of: Option<String>,
    // batch: records
    // batch: share
    /// T6.07: revealed by break-glass; rotate it (cleared by the next set).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub must_rotate: Option<bool>,
    // batch: sync
    // batch: policy
    // batch: gate
    /// T7.01: protocol of a sealed database login (`postgres`, `redis`,
    /// …), so `kepr agent run` opens the right proxy for it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub db_kind: Option<String>,
    // batch: aws
    /// T2.02: a sealed AWS key the gate re-signs SigV4 requests with, so
    /// `kepr agent run` gives the session an AWS placeholder pair.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aws_sigv4: Option<bool>,
    // batch: eco
    // batch: platform
    // batch: session
    /// T11.14: revealing the value needs the store passphrase again.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requires_reauth: Option<bool>,
    // end of batches
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
