// daemon_sharing/devices.rs — T6.03 devices and single-use enrolment
// tokens (T6.13 adds the optional IdP check).
//
//   kepr device add LABEL        → KD1-… token, 15 min, single use. Only
//                                  SHA-256(token), the label and the expiry
//                                  are kept.
//   (new machine) kepr device enroll TOKEN -o FILE
//                                → its share public key + HMAC under the
//                                  token hash (kepr_core EnrolRequest)
//   kepr device enroll --from FILE
//                                → this daemon checks the HMAC against the
//                                  stored hashes, burns the token and pins
//                                  the key under the label.
//
// Devices are what multi-device sync (T6.10) encrypts to:
// `sync_recipients` is the list it should read.

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{
    token_hash, DeviceInfo, EnrolRequest, OidcIdentity, PendingDevice, SharingResponse,
    DEVICE_TOKEN_PREFIX,
};
use sha2::{Digest, Sha256};

use super::{audit_r, load, save, state_path, LOCK};
use crate::daemon_sharing::kem::Recipient;
use crate::expiry::{format_expires_at, now_unix};

pub const TOKEN_TTL: u64 = 15 * 60;
const MAX_DEVICES: usize = 32;
const MAX_PENDING: usize = 8;

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub(crate) struct Devices {
    #[serde(default)]
    devices: Vec<Device>,
    #[serde(default)]
    tokens: Vec<Token>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Device {
    id: String,
    label: String,
    public: String,
    added: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<OidcIdentity>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Token {
    hash: String,
    label: String,
    expires: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oidc_issuer: Option<String>,
}

/// A device / contact label: short, printable, no control characters.
pub(crate) fn valid_label(label: &str) -> Result<(), String> {
    let ok = !label.is_empty()
        && label.chars().count() <= 64
        && !label.chars().any(|c| c.is_control())
        && label.trim() == label;
    ok.then_some(())
        .ok_or_else(|| "a label is 1-64 printable characters".into())
}

fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

impl Devices {
    fn prune(&mut self, now: u64) {
        self.tokens.retain(|t| t.expires > now);
    }

    pub(crate) fn add_token(
        &mut self,
        label: &str,
        oidc_issuer: Option<String>,
        now: u64,
    ) -> Result<String, String> {
        valid_label(label)?;
        self.prune(now);
        if self.tokens.len() >= MAX_PENDING {
            return Err("too many enrolments in progress; wait for them to expire".into());
        }
        if self.devices.len() >= MAX_DEVICES {
            return Err(format!("at most {MAX_DEVICES} devices"));
        }
        let mut raw = zeroize::Zeroizing::new([0u8; 16]);
        getrandom::fill(raw.as_mut()).map_err(|e| format!("CSPRNG failure: {e}"))?;
        let token = format!("{DEVICE_TOKEN_PREFIX}{}", hex::encode(raw.as_ref()));
        self.tokens.push(Token {
            hash: hex::encode(token_hash(&token)),
            label: label.to_string(),
            expires: now + TOKEN_TTL,
            oidc_issuer,
        });
        Ok(token)
    }

    /// Pin the device in `req` if its HMAC matches a live token. The
    /// token is burnt on success (single use) and on expiry.
    pub(crate) fn enroll(
        &mut self,
        req: &EnrolRequest,
        oidc: Option<&OidcIdentity>,
        now: u64,
    ) -> Result<DeviceInfo, String> {
        let public = Recipient::parse(&req.public)?.text();
        let pos = self
            .tokens
            .iter()
            .position(|t| {
                let mut h = [0u8; 32];
                hex::decode_to_slice(&t.hash, &mut h).is_ok() && req.verify(&h)
            })
            .ok_or("the request doesn't match any enrolment token (wrong or already used)")?;
        if self.tokens[pos].expires <= now {
            self.tokens.remove(pos);
            return Err(
                "this enrolment token has expired; make a new one (kepr device add)".into(),
            );
        }
        let token = self.tokens[pos].clone();
        // The ID token rides inside the HMAC'd request, so it came from
        // the token holder; the CLI verified its signature (no network
        // here) and names the identity.
        let identity = match (&token.oidc_issuer, oidc) {
            (Some(iss), Some(id)) if same_issuer(iss, &id.issuer) && req.id_token.is_some() => {
                Some(id.clone())
            }
            (Some(iss), _) => {
                return Err(format!(
                    "this enrolment needs an IdP login: kepr device enroll --from FILE --oidc {iss} --client-id ID"
                ))
            }
            (None, id) => id.cloned(),
        };
        if let Some(d) = self.devices.iter().find(|d| d.public == public) {
            return Err(format!("this device is already enrolled as {}", d.label));
        }
        if self.devices.len() >= MAX_DEVICES {
            return Err(format!("at most {MAX_DEVICES} devices"));
        }
        self.tokens.remove(pos);
        let id = hex::encode(&Sha256::digest(public.as_bytes())[..4]);
        let d = Device {
            id,
            label: token.label,
            public,
            added: now,
            identity,
        };
        self.devices.push(d.clone());
        Ok(info(&d))
    }

    pub(crate) fn remove(&mut self, key: &str) -> Result<String, String> {
        let pos = self
            .devices
            .iter()
            .position(|d| d.id == key || d.label == key)
            .ok_or_else(|| format!("no device {key} (see kepr device ls)"))?;
        Ok(self.devices.remove(pos).label)
    }

    /// The share keys sync bundles are encrypted to (T6.10).
    pub(crate) fn recipients(&self) -> Vec<String> {
        self.devices.iter().map(|d| d.public.clone()).collect()
    }

    fn listing(&self, now: u64) -> SharingResponse {
        SharingResponse::DeviceListing {
            devices: self.devices.iter().map(info).collect(),
            pending: self
                .tokens
                .iter()
                .filter(|t| t.expires > now)
                .map(|t| PendingDevice {
                    label: t.label.clone(),
                    expires_at: format_expires_at(t.expires),
                    oidc_issuer: t.oidc_issuer.clone(),
                })
                .collect(),
        }
    }
}

fn info(d: &Device) -> DeviceInfo {
    DeviceInfo {
        id: d.id.clone(),
        label: d.label.clone(),
        public: d.public.clone(),
        added: format_expires_at(d.added),
        identity: d
            .identity
            .as_ref()
            .map(|i| format!("{} @ {}", i.subject, i.issuer)),
    }
}

/// Every enrolled device's share key, for multi-device sync (T6.10).
pub fn sync_recipients(uid: u32) -> Vec<String> {
    load::<Devices>(&state_path("devices", uid)).recipients()
}

/// Load, change and save this uid's device file under the state lock.
fn with_devices<T>(
    uid: u32,
    f: impl FnOnce(&mut Devices) -> Result<T, String>,
) -> Result<T, String> {
    let _g = LOCK.lock().map_err(|_| "device state lock poisoned")?;
    let path = state_path("devices", uid);
    let mut d: Devices = load(&path);
    let out = f(&mut d);
    // Save even on failure: an expired token is dropped as it's reported.
    save(&path, &d)?;
    out
}

pub fn handle_add(uid: u32, username: &str, label: &str, oidc_issuer: Option<String>) -> Response {
    let now = now_unix();
    let r = with_devices(uid, |d| d.add_token(label, oidc_issuer, now));
    audit_r("device-add", uid, username, None, &r);
    match r {
        Ok(token) => SharingResponse::DeviceToken {
            token: token.into(),
            label: label.to_string(),
            expires_at: format_expires_at(now + TOKEN_TTL),
        }
        .into(),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_enroll(
    uid: u32,
    username: &str,
    request: &str,
    oidc: Option<&OidcIdentity>,
) -> Response {
    let r = serde_json::from_str::<EnrolRequest>(request)
        .map_err(|_| "not a device enrolment request".to_string())
        .and_then(|req| with_devices(uid, |d| d.enroll(&req, oidc, now_unix())));
    audit_r("device-enroll", uid, username, None, &r);
    match r {
        Ok(dev) => SharingResponse::DeviceListing {
            devices: vec![dev],
            pending: vec![],
        }
        .into(),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_list(uid: u32) -> Response {
    let now = now_unix();
    let d: Devices = load(&state_path("devices", uid));
    d.listing(now).into()
}

pub fn handle_remove(uid: u32, username: &str, device: &str) -> Response {
    let r = with_devices(uid, |d| d.remove(device));
    audit_r("device-remove", uid, username, None, &r);
    match r {
        Ok(label) => super::done(format!(
            "device {label} removed; it gets no further sync bundles"
        )),
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_sharing::kem::ShareSecret;
    use kepr_core::protocol_sharing::normalize_token;

    fn public() -> String {
        ShareSecret::generate().unwrap().recipient().text()
    }

    #[test]
    fn a_token_enrols_exactly_once() {
        let mut d = Devices::default();
        let token = d.add_token("laptop", None, 1000).unwrap();
        assert!(normalize_token(&token).is_some());
        let req = EnrolRequest::new(&token, "host", &public(), None);
        let dev = d.enroll(&req, None, 1001).unwrap();
        assert_eq!(dev.label, "laptop");
        assert_eq!(d.recipients(), vec![req.public.clone()]);
        // Same request (or a new one with the same token) fails now.
        assert!(d.enroll(&req, None, 1002).is_err());
        let again = EnrolRequest::new(&token, "host", &public(), None);
        assert!(d.enroll(&again, None, 1002).is_err());
        assert_eq!(d.devices.len(), 1);
    }

    #[test]
    fn an_expired_token_is_refused_and_dropped() {
        let mut d = Devices::default();
        let token = d.add_token("laptop", None, 1000).unwrap();
        let req = EnrolRequest::new(&token, "host", &public(), None);
        let err = d.enroll(&req, None, 1000 + TOKEN_TTL).unwrap_err();
        assert!(err.contains("expired"), "{err}");
        assert!(d.tokens.is_empty() && d.devices.is_empty());
    }

    #[test]
    fn an_hmac_mismatch_is_refused_and_keeps_the_token() {
        let mut d = Devices::default();
        let token = d.add_token("laptop", None, 1000).unwrap();
        let mut req = EnrolRequest::new(&token, "host", &public(), None);
        req.public = public(); // swapped key: the MAC no longer matches
        assert!(d.enroll(&req, None, 1001).is_err());
        let forged =
            EnrolRequest::new("KD1-00000000000000000000000000000000", "h", &public(), None);
        assert!(d.enroll(&forged, None, 1001).is_err());
        assert_eq!(d.tokens.len(), 1);
        assert!(d.devices.is_empty());
    }

    #[test]
    fn rm_drops_the_device_from_sync_recipients() {
        let mut d = Devices::default();
        for label in ["a", "b"] {
            let t = d.add_token(label, None, 1).unwrap();
            d.enroll(&EnrolRequest::new(&t, "h", &public(), None), None, 2)
                .unwrap();
        }
        assert_eq!(d.recipients().len(), 2);
        let b_key = d.devices[1].public.clone();
        let a_id = d.devices[0].id.clone();
        assert_eq!(d.remove(&a_id).unwrap(), "a");
        assert_eq!(d.recipients(), vec![b_key]);
        assert!(d.remove("a").is_err());
    }

    #[test]
    fn an_oidc_token_needs_an_identity_from_its_issuer() {
        let mut d = Devices::default();
        let t = d
            .add_token("laptop", Some("https://idp.example".into()), 1)
            .unwrap();
        let req = EnrolRequest::new(&t, "h", &public(), Some("a.b.c".into()));
        let other = OidcIdentity {
            issuer: "https://evil.example".into(),
            subject: "ana".into(),
        };
        assert!(d.enroll(&req, None, 2).unwrap_err().contains("--oidc"));
        assert!(d.enroll(&req, Some(&other), 2).is_err());
        let ok = OidcIdentity {
            issuer: "https://idp.example/".into(),
            subject: "ana@example.com".into(),
        };
        // A request made without an IdP login can't borrow an identity.
        let bare = EnrolRequest::new(&t, "h", &public(), None);
        assert!(d.enroll(&bare, Some(&ok), 2).is_err());
        // The failed attempts didn't burn the token.
        let dev = d.enroll(&req, Some(&ok), 2).unwrap();
        assert_eq!(
            dev.identity.as_deref(),
            Some("ana@example.com @ https://idp.example/")
        );
    }

    #[test]
    fn labels_and_caps() {
        let mut d = Devices::default();
        assert!(d.add_token("", None, 1).is_err());
        assert!(d.add_token("bad\nlabel", None, 1).is_err());
        for _ in 0..MAX_PENDING {
            d.add_token("x", None, 1).unwrap();
        }
        assert!(d.add_token("x", None, 1).is_err());
        // Expired tokens make room again.
        assert!(d.add_token("x", None, 1 + TOKEN_TTL).is_ok());
    }
}
