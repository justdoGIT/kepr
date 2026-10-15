// daemon_sharing/emergency_proof.rs — T6.06 emergency access requests.
//
// A request is made by the contact's daemon and checked by the owner's:
//
//   kepr-emreq1-<b64url(JSON { v, from, to, at, nonce, mac })>
//   from / to  the contact's and the owner's share public keys
//   mac        HMAC-SHA256 over (from, to, nonce, at) under
//              HKDF-SHA256(X25519(contact_sk, owner_pk),
//                          info = "kepr-emergency-v1" ‖ from_x ‖ to_x)
//
// Share keys are KEM keys, not signing keys, so the request is
// authenticated with the static X25519 secret both sides can compute
// (only the contact and the owner hold one of the two private keys).
// A key whose exchange isn't contributory (a low-order point) never
// verifies. Freshness and replay are the caller's checks (`at`).

use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::kem::{Recipient, ShareSecret};

pub const PREFIX: &str = "kepr-emreq1-";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const MAX_LEN: usize = 16 * 1024;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Proof {
    pub v: u8,
    pub from: String,
    pub to: String,
    pub at: u64,
    pub nonce: String,
    pub mac: String,
}

fn mac_key(
    mine: &StaticSecret,
    peer: &[u8; 32],
    from_x: &[u8; 32],
    to_x: &[u8; 32],
) -> Option<Zeroizing<[u8; 32]>> {
    let ss = mine.diffie_hellman(&PublicKey::from(*peer));
    if !ss.was_contributory() {
        return None;
    }
    let info = [&b"kepr-emergency-v1"[..], from_x, to_x].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ss.as_bytes())
        .expand(&info, key.as_mut())
        .ok()?;
    Some(key)
}

fn tag(key: &[u8; 32], p: &Proof) -> Hmac<Sha256> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
    m.update(b"kepr-emergency-request-v1");
    for part in [&p.from, &p.to, &p.nonce] {
        m.update(&(part.len() as u32).to_be_bytes());
        m.update(part.as_bytes());
    }
    m.update(&p.at.to_be_bytes());
    m
}

/// Contact side: a request to `owner` made at `now`, under our key.
pub fn make(me: &ShareSecret, owner: &Recipient, now: u64) -> Result<String, String> {
    let from = me.recipient();
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let mut p = Proof {
        v: 1,
        from: from.text(),
        to: owner.text(),
        at: now,
        nonce: hex::encode(nonce),
        mac: String::new(),
    };
    let key = mac_key(&me.x, owner.x25519(), from.x25519(), owner.x25519())
        .ok_or("that is not a usable share key")?;
    p.mac = B64.encode(tag(&key, &p).finalize().into_bytes());
    let json = serde_json::to_vec(&p).map_err(|e| e.to_string())?;
    Ok(format!("{PREFIX}{}", B64.encode(json)))
}

pub fn parse(text: &str) -> Result<Proof, String> {
    let bad = || "not a kepr emergency request (kepr-emreq1-…)".to_string();
    let t = text.trim();
    if t.len() > MAX_LEN {
        return Err(bad());
    }
    let raw = t
        .strip_prefix(PREFIX)
        .and_then(|b| B64.decode(b).ok())
        .ok_or_else(bad)?;
    let p: Proof = serde_json::from_slice(&raw).map_err(|_| bad())?;
    (p.v == 1).then_some(p).ok_or_else(bad)
}

/// Owner side: was `p` made by `contact`'s key, for our key?
pub fn verify(p: &Proof, owner: &ShareSecret, contact: &Recipient) -> bool {
    let (Ok(from), Ok(to)) = (Recipient::parse(&p.from), Recipient::parse(&p.to)) else {
        return false;
    };
    let owner_x = PublicKey::from(&owner.x).to_bytes();
    if from.x25519() != contact.x25519() || *to.x25519() != owner_x {
        return false;
    }
    let Some(key) = mac_key(&owner.x, contact.x25519(), contact.x25519(), &owner_x) else {
        return false;
    };
    let Ok(t) = B64.decode(&p.mac) else {
        return false;
    };
    tag(&key, p).verify_slice(&t).is_ok()
}

/// The X25519 half of a public key's text, for matching.
pub fn x_of(public: &str) -> Option<[u8; 32]> {
    Recipient::parse(public).ok().map(|r| *r.x25519())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_verifies_only_for_its_contact_and_owner() {
        let (owner, contact, other) = (
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
        );
        let text = make(&contact, &owner.recipient(), 1_000).unwrap();
        let p = parse(&text).unwrap();
        assert_eq!(p.at, 1_000);
        assert!(verify(&p, &owner, &contact.recipient()));
        // Not from this contact, or not for this owner.
        assert!(!verify(&p, &owner, &other.recipient()));
        assert!(!verify(&p, &other, &contact.recipient()));
        // Made by someone else who claims to be the contact.
        let mut forged = parse(&make(&other, &owner.recipient(), 1_000).unwrap()).unwrap();
        forged.from = contact.recipient().text();
        assert!(!verify(&forged, &owner, &contact.recipient()));
        // Any field changed breaks the MAC.
        for f in [
            |p: &mut Proof| p.at += 1,
            |p: &mut Proof| p.nonce.push('0'),
            |p: &mut Proof| p.mac = "AAAA".into(),
        ] {
            let mut m = p.clone();
            f(&mut m);
            assert!(!verify(&m, &owner, &contact.recipient()));
        }
    }

    #[test]
    fn a_low_order_key_never_verifies() {
        let owner = ShareSecret::generate().unwrap();
        let zero = Recipient::V1([0u8; 32]);
        assert!(make(&owner, &zero, 1).is_err());
        let p = Proof {
            v: 1,
            from: zero.text(),
            to: owner.recipient().text(),
            at: 1,
            nonce: "00".into(),
            mac: String::new(),
        };
        // Whatever the MAC, an all-zero shared secret is refused.
        assert!(!verify(&p, &owner, &zero));
    }

    #[test]
    fn junk_is_not_a_request() {
        for t in ["", "kepr-emreq1-", "kepr-emreq1-!!", "kepr-share2-AAAA"] {
            assert!(parse(t).is_err(), "{t}");
        }
        assert!(parse(&format!("{PREFIX}{}", "A".repeat(MAX_LEN))).is_err());
    }
}
