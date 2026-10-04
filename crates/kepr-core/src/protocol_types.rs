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
    /// Agent vault P1: true iff the credential is write-only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sealed: Option<bool>,
    /// Hosts a sealed credential is bound to (no secret material).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bound_hosts: Option<Vec<String>>,
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
