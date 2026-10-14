// protocol_sharing.rs — wire types of the `share` ticket batch (P6
// sharing + T11.15): devices, one-time links, contacts, emergency
// access, break-glass and escrow. Carried by `Request::Sharing` /
// `Response::Sharing` (untagged, after every tagged variant), so the
// command names here must not collide with any other `cmd` / `kind`.

use crate::generate::ZeroString;
pub use crate::protocol_sharing_types::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum SharingRequest {
    /// T6.03: a single-use enrolment token (15 min) for a new device.
    /// T6.13: `oidc_issuer` makes the enrolment also need an IdP login.
    DeviceAdd {
        label: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        oidc_issuer: Option<String>,
    },
    /// T6.03: pin the device in `request` (an `EnrolRequest` as JSON).
    DeviceEnroll {
        request: String,
        /// T6.13: the IdP identity the CLI verified in the request's
        /// ID token (issuer + subject).
        #[serde(skip_serializing_if = "Option::is_none", default)]
        oidc: Option<OidcIdentity>,
    },
    DeviceList,
    /// Forget a device (by id or label): it gets no further sync bundles.
    DeviceRemove {
        device: String,
    },
    /// T6.04: a one-time link for `name`: an encrypted blob plus its key.
    ShareLinkCreate {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        ttl_secs: Option<u64>,
        /// T6.05: delete the record (and its history) once the link is
        /// opened or expires.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        self_destruct: Option<bool>,
        /// Where the CLI puts the blob (kept in the sent-share ledger).
        #[serde(skip_serializing_if = "Option::is_none", default)]
        relay: Option<String>,
        /// T11.15: the received copy deletes itself this long after its
        /// first `get`.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        view_window_secs: Option<u64>,
    },
    /// T6.04: open a link's blob with the key from its #fragment and
    /// store the value (as `name`, or the sender's name).
    ShareLinkOpen {
        blob: String,
        key: ZeroString,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        name: Option<String>,
    },
    /// T6.05: the caller's sent shares (the ledger).
    ShareSentList,
    /// T6.05: the caller saw its link's blob gone from the relay (410):
    /// mark it opened, and self-destruct the record if it asked for it.
    ShareLinkOpened {
        id: String,
    },
    /// T11.15: pin `key` (a share public key) under the contact `name`.
    ShareContactAdd {
        name: String,
        key: String,
    },
    ShareContactList,
    ShareContactRemove {
        name: String,
    },
    /// T11.15: the caller's sent shares, from the ledger and the audit chain.
    ShareReport,
    /// T6.06: let `contact` (a pinned contact or a key) request access;
    /// `names` (None = every shareable credential) is released to them
    /// `delay_secs` after a request the owner doesn't deny.
    EmergencyAdd {
        contact: String,
        delay_secs: u64,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        names: Option<Vec<String>>,
    },
    EmergencyList,
    EmergencyRemove {
        contact: String,
    },
    /// T6.06 (owner): cancel a pending request (and unfetched releases).
    EmergencyDeny {
        contact: String,
    },
    /// T6.06 (contact): a request to `owner` (key or pinned contact),
    /// authenticated with the caller's share key.
    EmergencyProve {
        owner: String,
    },
    /// T6.06: hand a request (`kepr-emreq1-…`) to this daemon.
    EmergencyRequest {
        proof: String,
    },
    /// T6.06: released envelopes for the caller's share key (and, for an
    /// owner, the ones released from their grants, to pass on).
    EmergencyRelease,
    /// T6.07: reveal sealed `name` once, given k recovery-kit shares of
    /// this store's key. Replies `Response::GetOk`; marks `must_rotate`.
    BreakGlass {
        name: String,
        shares: Vec<ZeroString>,
    },
    /// T6.14: wrap the master key to an administrator's share key
    /// (`escrow.bin`). Needs the store passphrase, like the recovery kit.
    EscrowEnable {
        admin_key: String,
        password: ZeroString,
    },
    /// Needs the store passphrase too: only the owner turns it off.
    EscrowDisable {
        password: ZeroString,
    },
    EscrowStatus,
    /// T6.14 (admin's machine): open an escrow file with the caller's
    /// share key; replies `Response::RecoveryKitOk` (a 2-of-2 kit for
    /// `kepr recovery-kit restore` next to the old credential files).
    EscrowOpen {
        escrow: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SharingResponse {
    DeviceToken {
        /// `KD1-…`: single use, valid until `expires_at`.
        token: ZeroString,
        label: String,
        expires_at: String,
    },
    DeviceListing {
        devices: Vec<DeviceInfo>,
        pending: Vec<PendingDevice>,
    },
    /// A request that needs no other reply than a line for the user.
    SharingDone {
        message: String,
    },
    /// T6.04: the key goes only into the link's #fragment, never to a relay.
    ShareLink {
        id: String,
        key: ZeroString,
        blob: String,
        expires_at: String,
        ttl_secs: u64,
    },
    /// T6.04, CLI output only (`--json`): the finished link.
    ShareLinkReady {
        link: ZeroString,
        expires_at: String,
    },
    /// T6.05: the sent-share ledger, newest last (also T11.15's report).
    ShareSent {
        shares: Vec<SentShare>,
    },
    /// T11.15: the caller's pinned contacts.
    ShareContacts {
        contacts: Vec<ContactInfo>,
    },
    /// T6.06: the caller's emergency contacts and their state.
    EmergencyListing {
        grants: Vec<EmergencyInfo>,
    },
    EmergencyProof {
        proof: String,
    },
    /// T6.06: share envelopes (each opens only with its contact's key).
    EmergencyEnvelopes {
        envelopes: Vec<String>,
    },
    /// T6.14: is the master key escrowed, and to whom?
    EscrowState {
        enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        admin: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        admin_fingerprint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        since: Option<String>,
    },
}

impl From<SharingResponse> for crate::protocol::Response {
    fn from(r: SharingResponse) -> Self {
        crate::protocol::Response::Sharing(r)
    }
}

// ── T6.03 enrolment request (new device → first device) ──────────────────────

/// What a new device hands the first one (as a file or relay blob): its
/// share public key, authenticated with an HMAC keyed by the token hash,
/// so only a holder of the single-use token could have made it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolRequest {
    pub v: u8,
    /// The new device's own name for itself (informational).
    pub host: String,
    /// Its share public key (`kepr-pk2-…`).
    pub public: String,
    /// T6.13: an OIDC ID token from the device-code login.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id_token: Option<String>,
    /// base64url HMAC-SHA256 under `token_hash(token)`.
    pub mac: String,
}

pub const DEVICE_TOKEN_PREFIX: &str = "KD1-";

/// The canonical form of a typed token, or `None` if it isn't one.
pub fn normalize_token(text: &str) -> Option<String> {
    let t = text.trim();
    let hex = t
        .get(..DEVICE_TOKEN_PREFIX.len())
        .filter(|p| p.eq_ignore_ascii_case(DEVICE_TOKEN_PREFIX))
        .map(|_| &t[DEVICE_TOKEN_PREFIX.len()..])?
        .replace('-', "")
        .to_ascii_lowercase();
    (hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| format!("{DEVICE_TOKEN_PREFIX}{hex}"))
}

/// SHA-256 of the canonical token: all the first device ever stores.
pub fn token_hash(token: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(token.as_bytes()).into()
}

fn enrol_mac(hash: &[u8; 32], r: &EnrolRequest) -> hmac::Hmac<sha2::Sha256> {
    use hmac::{KeyInit, Mac};
    let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(hash).expect("any key length");
    m.update(b"kepr-device-enrol-v1");
    for part in [&r.host, &r.public, r.id_token.as_deref().unwrap_or("")] {
        m.update(&(part.len() as u32).to_be_bytes());
        m.update(part.as_bytes());
    }
    m
}

impl EnrolRequest {
    pub fn new(token: &str, host: &str, public: &str, id_token: Option<String>) -> Self {
        use base64::Engine;
        use hmac::Mac;
        let mut r = Self {
            v: 1,
            host: host.to_string(),
            public: public.to_string(),
            id_token,
            mac: String::new(),
        };
        let tag = enrol_mac(&token_hash(token), &r).finalize().into_bytes();
        r.mac = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag);
        r
    }

    /// Constant-time check of `mac` against a stored token hash.
    pub fn verify(&self, hash: &[u8; 32]) -> bool {
        use base64::Engine;
        use hmac::Mac;
        let Ok(tag) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&self.mac) else {
            return false;
        };
        enrol_mac(hash, self).verify_slice(&tag).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    #[test]
    fn requests_and_responses_survive_json_through_the_outer_enums() {
        let reqs = [
            SharingRequest::DeviceAdd {
                label: "laptop".into(),
                oidc_issuer: None,
            },
            SharingRequest::DeviceEnroll {
                request: "{}".into(),
                oidc: Some(OidcIdentity {
                    issuer: "https://idp".into(),
                    subject: "u1".into(),
                }),
            },
            SharingRequest::DeviceList,
            SharingRequest::DeviceRemove { device: "x".into() },
            SharingRequest::ShareLinkCreate {
                name: "A".into(),
                ttl_secs: Some(60),
                self_destruct: Some(true),
                relay: None,
                view_window_secs: Some(300),
            },
            SharingRequest::ShareSentList,
            SharingRequest::ShareContactAdd {
                name: "bob".into(),
                key: "kepr-pk2-x".into(),
            },
            SharingRequest::ShareContactList,
            SharingRequest::ShareContactRemove { name: "bob".into() },
            SharingRequest::ShareReport,
            SharingRequest::EmergencyAdd {
                contact: "bob".into(),
                delay_secs: 3600,
                names: Some(vec!["A".into()]),
            },
            SharingRequest::EmergencyList,
            SharingRequest::EmergencyRemove {
                contact: "bob".into(),
            },
            SharingRequest::EmergencyDeny {
                contact: "bob".into(),
            },
            SharingRequest::EmergencyProve {
                owner: "alice".into(),
            },
            SharingRequest::EmergencyRequest {
                proof: "kepr-emreq1-x".into(),
            },
            SharingRequest::EmergencyRelease,
            SharingRequest::BreakGlass {
                name: "A".into(),
                shares: vec!["kepr1-x".into()],
            },
            SharingRequest::EscrowEnable {
                admin_key: "kepr-pk2-x".into(),
                password: "pw".into(),
            },
            SharingRequest::EscrowDisable {
                password: "pw".into(),
            },
            SharingRequest::EscrowStatus,
            SharingRequest::EscrowOpen {
                escrow: "{}".into(),
            },
            SharingRequest::ShareLinkOpened { id: "i".into() },
            SharingRequest::ShareLinkOpen {
                blob: "kepr-link1-x".into(),
                key: "k".into(),
                name: None,
            },
        ];
        for r in reqs {
            let json = serde_json::to_string(&Request::Sharing(r)).unwrap();
            let back: Request = serde_json::from_str(&json).unwrap();
            assert!(matches!(back, Request::Sharing(_)), "{json}");
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
        }
        let resps = [
            SharingResponse::DeviceToken {
                token: "KD1-x".into(),
                label: "l".into(),
                expires_at: "t".into(),
            },
            SharingResponse::DeviceListing {
                devices: vec![],
                pending: vec![],
            },
            SharingResponse::SharingDone {
                message: "ok".into(),
            },
            SharingResponse::ShareLink {
                id: "i".into(),
                key: "k".into(),
                blob: "b".into(),
                expires_at: "t".into(),
                ttl_secs: 60,
            },
            SharingResponse::ShareSent {
                shares: vec![SentShare {
                    id: "i".into(),
                    name: "A".into(),
                    kind: "link".into(),
                    to: None,
                    relay: Some("http://r".into()),
                    sent_unix: 1,
                    expires_unix: 2,
                    opened_unix: None,
                    self_destruct: true,
                    settled: false,
                }],
            },
            SharingResponse::ShareContacts {
                contacts: vec![ContactInfo {
                    name: "bob".into(),
                    public: "kepr-pk2-x".into(),
                    fingerprint: "ab".into(),
                    added: "t".into(),
                }],
            },
            SharingResponse::EmergencyListing {
                grants: vec![EmergencyInfo {
                    contact: "bob".into(),
                    fingerprint: "ab".into(),
                    delay_secs: 3600,
                    names: None,
                    state: "requested".into(),
                    requested_at: Some("t".into()),
                    release_at: Some("t".into()),
                    released_at: None,
                }],
            },
            SharingResponse::EmergencyProof {
                proof: "kepr-emreq1-x".into(),
            },
            SharingResponse::EmergencyEnvelopes {
                envelopes: vec!["kepr-share2-x".into()],
            },
            SharingResponse::EscrowState {
                enabled: true,
                admin: Some("it-admin".into()),
                admin_fingerprint: Some("ab".into()),
                since: Some("t".into()),
            },
        ];
        for r in resps {
            let json = serde_json::to_string(&Response::Sharing(r)).unwrap();
            let back: Response = serde_json::from_str(&json).unwrap();
            assert!(matches!(back, Response::Sharing(_)), "{json}");
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
        }
        // The tagged variants still win for their own tags.
        let ping: Request = serde_json::from_str(r#"{"cmd":"ping"}"#).unwrap();
        assert!(matches!(ping, Request::Ping));
    }

    #[test]
    fn enrol_request_mac_binds_token_and_fields() {
        let token = "KD1-00112233445566778899aabbccddeeff";
        let r = EnrolRequest::new(token, "laptop", "kepr-pk2-AAAA", None);
        assert!(r.verify(&token_hash(token)));
        assert!(!r.verify(&token_hash("KD1-ffffffffffffffffffffffffffffffff")));
        for f in [
            |r: &mut EnrolRequest| r.public.push('B'),
            |r: &mut EnrolRequest| r.host.push('x'),
            |r: &mut EnrolRequest| r.id_token = Some("t".into()),
            |r: &mut EnrolRequest| r.mac = "AAAA".into(),
        ] {
            let mut m = r.clone();
            f(&mut m);
            assert!(!m.verify(&token_hash(token)));
        }
    }

    #[test]
    fn tokens_normalize() {
        let t = "KD1-00112233445566778899aabbccddeeff";
        assert_eq!(normalize_token(t).as_deref(), Some(t));
        assert_eq!(
            normalize_token(" kd1-0011-2233-4455-6677-8899-AABB-CCDD-EEFF ").as_deref(),
            Some(t)
        );
        assert_eq!(normalize_token("KD1-0011"), None);
        assert_eq!(
            normalize_token("KD1-zz112233445566778899aabbccddeeff"),
            None
        );
        assert_eq!(normalize_token("x"), None);
    }
}
