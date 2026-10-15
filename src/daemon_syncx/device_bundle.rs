// daemon_syncx/device_bundle.rs — T6.10 sync bundles: encrypted to every
// enrolled device (T6.03) and authenticated as coming from this one.
//
//   kepr_bundle1\n
//   {"kind":"sync","from":"kepr-pk2-…","at":U,"nonce":"…",
//    "keys":[{"to":"<hex x25519>","wrap":"kepr-share2-…","mac":"…"},…]}\n
//   AES-256-GCM(content key, nonce, AAD = "kepr-sync-v1" ‖ from ‖ at, body)
//
// The content key is new for every bundle and wrapped to each device with
// the share envelope (kem.rs), so a device dropped from the list gets no
// wrap in the next bundle and can't open anything pushed after that
// re-key. Share keys are KEM keys, not signing keys: each wrap carries a
// MAC under HKDF(X25519(sender, recipient)) over the header fields and
// the ciphertext's hash, as in emergency_proof.rs. Only the sender and
// that recipient can compute it, so a bundle opens only when it comes
// from a pinned device, unchanged.

use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use kepr_core::generate::ZeroString;
use kepr_core::protocol_syncx::BUNDLE_MAGIC;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::bundle::ItemMeta;
use crate::daemon_eco::cipher::{self, NONCE_LEN};
use crate::daemon_sharing::kem::{self, Recipient, ShareSecret};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const KIND: &str = "sync";
const MAX_HEADER: usize = 256 * 1024;
const FORGED: &str = "damaged or forged sync bundle";

/// What a device publishes: every credential it syncs, with when and
/// where it last changed (`value: None` is a delete, kept 30 days).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyncBody {
    pub entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub at: u64,
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<ZeroString>,
    #[serde(default)]
    pub meta: ItemMeta,
}

/// An opened bundle: its body, the sending device's X25519 key (hex) and
/// when it was built (the header `at`, under the MAC and the AAD).
#[derive(Debug)]
pub struct Opened {
    pub body: SyncBody,
    pub from: String,
    pub at: u64,
}

#[derive(Serialize, Deserialize)]
struct Header {
    kind: String,
    from: String,
    at: u64,
    nonce: String,
    keys: Vec<Wrap>,
}

#[derive(Serialize, Deserialize)]
struct Wrap {
    to: String,
    wrap: String,
    mac: String,
}

/// A device's short id (the one `kepr device ls` shows).
pub fn device_id(public_text: &str) -> String {
    hex::encode(&Sha256::digest(public_text.as_bytes())[..4])
}

fn mac_key(
    mine: &StaticSecret,
    peer: &[u8; 32],
    from: &[u8; 32],
    to: &[u8; 32],
) -> Option<Zeroizing<[u8; 32]>> {
    let ss = mine.diffie_hellman(&PublicKey::from(*peer));
    if !ss.was_contributory() {
        return None;
    }
    let info = [&b"kepr-sync-v1"[..], from, to].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ss.as_bytes())
        .expand(&info, key.as_mut())
        .ok()?;
    Some(key)
}

fn tag(key: &[u8; 32], h: &Header, w: &Wrap, ct: &[u8]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    m.update(b"kepr-sync-bundle-v1");
    for part in [&h.from, &h.nonce, &w.to, &w.wrap] {
        m.update(&(part.len() as u32).to_be_bytes());
        m.update(part.as_bytes());
    }
    m.update(&h.at.to_be_bytes());
    m.update(&Sha256::digest(ct));
    m
}

fn aad(from: &str, at: u64) -> Vec<u8> {
    [&b"kepr-sync-v1"[..], from.as_bytes(), &at.to_be_bytes()].concat()
}

/// Encrypt `body` from `me` to each of `to`, at time `at`.
pub fn seal(
    me: &ShareSecret,
    to: &[Recipient],
    body: &SyncBody,
    at: u64,
) -> Result<Vec<u8>, String> {
    if to.is_empty() {
        return Err("no devices enrolled: add one with `kepr device add` first".into());
    }
    let from = me.recipient();
    let from_x = *from.x25519();
    let mut content = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(content.as_mut()).map_err(|e| format!("CSPRNG failure: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let mut h = Header {
        kind: KIND.into(),
        from: from.text(),
        at,
        nonce: B64.encode(nonce),
        keys: Vec::new(),
    };
    let plain = Zeroizing::new(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    let ct = cipher::seal(content.as_ref(), &nonce, &aad(&h.from, at), &plain)
        .map_err(|_| "bundle encryption failed".to_string())?;
    for r in to {
        let mut w = Wrap {
            to: hex::encode(r.x25519()),
            wrap: kem::seal(r, content.as_ref())?,
            mac: String::new(),
        };
        let key =
            mac_key(&me.x, r.x25519(), &from_x, r.x25519()).ok_or("a device key is not usable")?;
        w.mac = B64.encode(tag(&key, &h, &w, &ct).finalize().into_bytes());
        h.keys.push(w);
    }
    let mut out = BUNDLE_MAGIC.to_vec();
    out.extend(serde_json::to_vec(&h).map_err(|e| e.to_string())?);
    out.push(b'\n');
    out.extend(ct);
    Ok(out)
}

fn split(bytes: &[u8]) -> Result<(Header, &[u8]), String> {
    let rest = bytes
        .strip_prefix(BUNDLE_MAGIC)
        .ok_or("not a kepr bundle")?;
    let line = rest
        .iter()
        .take(MAX_HEADER)
        .position(|b| *b == b'\n')
        .ok_or("not a sync bundle")?;
    let h: Header = serde_json::from_slice(&rest[..line]).map_err(|_| "not a sync bundle")?;
    if h.kind != KIND {
        return Err("not a sync bundle".into());
    }
    Ok((h, &rest[line + 1..]))
}

/// Open a bundle sent to `me` by one of the `trusted` devices.
pub fn open(me: &ShareSecret, trusted: &[Recipient], bytes: &[u8]) -> Result<Opened, String> {
    let (h, ct) = split(bytes)?;
    let from = Recipient::parse(&h.from).map_err(|_| FORGED)?;
    let from_x = *from.x25519();
    if !trusted.iter().any(|t| *t.x25519() == from_x) {
        return Err("from an unknown device (not enrolled here)".into());
    }
    let my_x = PublicKey::from(&me.x).to_bytes();
    let w = h
        .keys
        .iter()
        .find(|w| w.to == hex::encode(my_x))
        .ok_or("not encrypted to this device")?;
    let key = mac_key(&me.x, &from_x, &from_x, &my_x).ok_or(FORGED)?;
    let mac = B64.decode(&w.mac).map_err(|_| FORGED)?;
    tag(&key, &h, w, ct)
        .verify_slice(&mac)
        .map_err(|_| FORGED)?;
    let content = kem::open(me, &w.wrap).map_err(|_| FORGED)?;
    let nonce: [u8; NONCE_LEN] = B64
        .decode(&h.nonce)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or(FORGED)?;
    let plain = cipher::open(&content, &nonce, &aad(&h.from, h.at), ct).map_err(|_| FORGED)?;
    let body = serde_json::from_slice(&plain).map_err(|_| "malformed sync bundle")?;
    Ok(Opened {
        body,
        from: hex::encode(from_x),
        at: h.at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ShareSecret {
        ShareSecret::generate().unwrap()
    }

    fn body() -> SyncBody {
        SyncBody {
            entries: vec![Entry {
                name: "API".into(),
                at: 5,
                origin: "aa".into(),
                value: Some("v".into()),
                meta: ItemMeta::default(),
            }],
        }
    }

    #[test]
    fn opens_for_each_recipient_from_a_trusted_sender() {
        let (a, b, c) = (key(), key(), key());
        let bytes = seal(&a, &[b.recipient(), c.recipient()], &body(), 9).unwrap();
        for me in [&b, &c] {
            let got = open(me, &[a.recipient()], &bytes).unwrap();
            assert_eq!(got.body.entries[0].value.as_ref().unwrap().as_str(), "v");
            assert_eq!((got.from, got.at), (hex::encode(a.recipient().x25519()), 9));
        }
        assert!(!String::from_utf8_lossy(&bytes).contains("\"API\""));
    }

    #[test]
    fn unknown_senders_strangers_and_tampering_are_refused() {
        let (a, b, c, mallory) = (key(), key(), key(), key());
        let bytes = seal(&a, &[b.recipient()], &body(), 9).unwrap();
        assert!(open(&b, &[c.recipient()], &bytes)
            .unwrap_err()
            .contains("unknown device"));
        assert_eq!(
            open(&c, &[a.recipient()], &bytes).unwrap_err(),
            "not encrypted to this device"
        );
        let mut ct = bytes.clone();
        *ct.last_mut().unwrap() ^= 1;
        assert_eq!(open(&b, &[a.recipient()], &ct).unwrap_err(), FORGED);
        // Mallory names A as the sender: the MAC needs A's or B's secret.
        let forged = seal(&mallory, &[b.recipient()], &body(), 9).unwrap();
        let (h, ct) = split(&forged).unwrap();
        let h = Header {
            from: a.recipient().text(),
            ..h
        };
        let mut f = BUNDLE_MAGIC.to_vec();
        f.extend(serde_json::to_vec(&h).unwrap());
        f.push(b'\n');
        f.extend(ct);
        assert_eq!(open(&b, &[a.recipient()], &f).unwrap_err(), FORGED);
    }

    #[test]
    fn a_removed_device_cannot_open_the_next_bundle() {
        let (a, b, c) = (key(), key(), key());
        let before = seal(&a, &[b.recipient(), c.recipient()], &body(), 1).unwrap();
        assert!(open(&c, &[a.recipient()], &before).is_ok());
        // `kepr device rm c`: the next bundle is wrapped to b only.
        let after = seal(&a, &[b.recipient()], &body(), 2).unwrap();
        assert_eq!(
            open(&c, &[a.recipient()], &after).unwrap_err(),
            "not encrypted to this device"
        );
        assert!(open(&b, &[a.recipient()], &after).is_ok());
        assert!(seal(&a, &[], &body(), 3)
            .unwrap_err()
            .contains("no devices"));
    }
}
