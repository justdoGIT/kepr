// protocol_sharing_types.rs — record types carried by the `share` batch's
// requests and replies (protocol_sharing.rs re-exports them). No secret
// material in any of them: public keys, labels, times.

use serde::{Deserialize, Serialize};

/// One share this user sent (no value, no key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentShare {
    pub id: String,
    pub name: String,
    /// `link` or `envelope`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub relay: Option<String>,
    pub sent_unix: u64,
    pub expires_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub opened_unix: Option<u64>,
    #[serde(default)]
    pub self_destruct: bool,
    /// The self-destruct ran (or found the record already replaced).
    #[serde(default)]
    pub settled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcIdentity {
    pub issuer: String,
    pub subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub label: String,
    /// The device's share public key (not secret).
    pub public: String,
    pub added: String,
    /// T6.13: `subject @ issuer` when the enrolment was IdP-checked.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDevice {
    pub label: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub oidc_issuer: Option<String>,
}

/// T11.15: a pinned share contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub name: String,
    /// The contact's share public key (not secret).
    pub public: String,
    /// Short SHA-256 of `public`, to compare by voice or on paper.
    pub fingerprint: String,
    pub added: String,
}

/// T6.06: one emergency contact as its owner sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyInfo {
    /// The contact's name (or `key:<fingerprint>`).
    pub contact: String,
    pub fingerprint: String,
    pub delay_secs: u64,
    /// `None`: every shareable credential at release time.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub names: Option<Vec<String>>,
    /// `waiting` (no request), `requested`, or `released`.
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub requested_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub release_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub released_at: Option<String>,
}
