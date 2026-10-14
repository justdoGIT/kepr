// daemon_syncx/quorum_device.rs — T7.12 approvals from enrolled devices.
//
//   request   kepr-quorum1-<base64url {"owner":"kepr-pk2-…","id","name",
//             "action","expires_at"}>          printed by the owner's daemon
//   approval  kepr-approval1-<base64url {"id","from":"kepr-pk2-…","mac"}>
//
// The human at another enrolled device (T6.03) runs `kepr quorum sign
// REQUEST`, approves that machine's polkit prompt, and carries the
// approval back. The MAC is under HKDF(X25519(approver, owner)): only that
// device's share secret (or the owner's) can make it, and the owner takes
// it only from a device enrolled with it, never from its own key.

use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::daemon_sharing::kem::{Recipient, ShareSecret};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
pub const REQUEST: &str = "kepr-quorum1-";
const APPROVAL: &str = "kepr-approval1-";
const MAX_TEXT: usize = 8 * 1024;

/// What is being approved, as the devices see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ask {
    pub owner: String,
    pub id: String,
    pub name: String,
    pub action: String,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct Approval {
    id: String,
    from: String,
    mac: String,
}

fn decode<T: serde::de::DeserializeOwned>(
    text: &str,
    prefix: &str,
    what: &str,
) -> Result<T, String> {
    let t = text.trim();
    t.strip_prefix(prefix)
        .filter(|b| b.len() <= MAX_TEXT)
        .and_then(|b| B64.decode(b).ok())
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .ok_or_else(|| format!("not a kepr {what} ({prefix}…)"))
}

impl Ask {
    pub fn text(&self) -> String {
        format!(
            "{REQUEST}{}",
            B64.encode(serde_json::to_vec(self).unwrap_or_default())
        )
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let a: Ask = decode(text, REQUEST, "approval request")?;
        crate::store::validate_name(&a.name)?;
        Recipient::parse(&a.owner)?;
        Ok(a)
    }
}

fn key(
    mine: &StaticSecret,
    peer: &[u8; 32],
    from: &[u8; 32],
    to: &[u8; 32],
) -> Option<Zeroizing<[u8; 32]>> {
    let ss = mine.diffie_hellman(&PublicKey::from(*peer));
    if !ss.was_contributory() {
        return None;
    }
    let info = [&b"kepr-quorum-v1"[..], from, to].concat();
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ss.as_bytes())
        .expand(&info, k.as_mut())
        .ok()?;
    Some(k)
}

fn mac(key: &[u8; 32], ask: &Ask) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    m.update(b"kepr-quorum-approval-v1");
    for part in [&ask.owner, &ask.id, &ask.name, &ask.action] {
        m.update(&(part.len() as u32).to_be_bytes());
        m.update(part.as_bytes());
    }
    m.update(&ask.expires_at.to_be_bytes());
    m
}

/// On the approving device: its approval of `ask` (the caller checked
/// that the owner is enrolled here and that the human said yes).
pub fn sign(me: &ShareSecret, ask: &Ask) -> Result<String, String> {
    let owner = Recipient::parse(&ask.owner)?;
    let from = me.recipient();
    let k = key(&me.x, owner.x25519(), from.x25519(), owner.x25519())
        .ok_or("the owner's key is not usable")?;
    let a = Approval {
        id: ask.id.clone(),
        from: from.text(),
        mac: B64.encode(mac(&k, ask).finalize().into_bytes()),
    };
    Ok(format!(
        "{APPROVAL}{}",
        B64.encode(serde_json::to_vec(&a).map_err(|e| e.to_string())?)
    ))
}

/// The approver identity of an enrolled device: its X25519 key, the one
/// thing the MAC proves. Never the `from` text, which the MAC doesn't
/// cover: the same key as a V1 text, or as a V2 text with another ML-KEM
/// key, would otherwise count as one more approver.
pub fn approver_id(x25519: &[u8; 32]) -> String {
    format!("device:{}", hex::encode(x25519))
}

/// On the owner: check an approval of `ask` (ours) against the enrolled
/// `devices`. Returns the approver identity (`approver_id`).
pub fn verify(
    me: &ShareSecret,
    devices: &[Recipient],
    ask: &Ask,
    text: &str,
) -> Result<String, String> {
    let a: Approval = decode(text, APPROVAL, "approval")?;
    if a.id != ask.id {
        return Err("that approval is for another request".into());
    }
    let from = Recipient::parse(&a.from)?;
    let my_x = PublicKey::from(&me.x).to_bytes();
    if *from.x25519() == my_x {
        return Err("an approval must come from another device".into());
    }
    if !devices.iter().any(|d| d.x25519() == from.x25519()) {
        return Err("that approval is from a device not enrolled here (kepr device ls)".into());
    }
    let k = key(&me.x, from.x25519(), from.x25519(), &my_x).ok_or("approval does not verify")?;
    let got = B64.decode(&a.mac).map_err(|_| "approval does not verify")?;
    mac(&k, ask)
        .verify_slice(&got)
        .map_err(|_| "approval does not verify")?;
    Ok(approver_id(from.x25519()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ShareSecret {
        ShareSecret::generate().unwrap()
    }

    fn ask(owner: &ShareSecret) -> Ask {
        Ask {
            owner: owner.recipient().text(),
            id: "0a1b2c3d".into(),
            name: "API".into(),
            action: "use for 1h".into(),
            expires_at: 99,
        }
    }

    #[test]
    fn an_enrolled_device_approves_and_nothing_else_does() {
        let (a, b, c) = (key(), key(), key());
        let req = ask(&a);
        assert_eq!(Ask::parse(&req.text()).unwrap(), req);
        let approval = sign(&b, &req).unwrap();
        let id = verify(&a, &[b.recipient()], &req, &approval).unwrap();
        assert_eq!(id, approver_id(b.recipient().x25519()));
        // Not enrolled, our own key, another request, a changed field.
        let e = verify(&a, &[c.recipient()], &req, &approval).unwrap_err();
        assert!(e.contains("not enrolled"), "{e}");
        let mine = sign(&a, &req).unwrap();
        assert!(verify(&a, &[a.recipient()], &req, &mine)
            .unwrap_err()
            .contains("another device"));
        let other = Ask {
            id: "ffffffff".into(),
            ..req.clone()
        };
        assert!(verify(&a, &[b.recipient()], &other, &approval)
            .unwrap_err()
            .contains("another request"));
        let longer = Ask {
            action: "use for 24h".into(),
            ..req.clone()
        };
        assert_eq!(
            verify(&a, &[b.recipient()], &longer, &approval).unwrap_err(),
            "approval does not verify"
        );
        // C can't make an approval that passes as B's.
        let forged = sign(&c, &req).unwrap();
        let raw: Approval = decode(&forged, APPROVAL, "approval").unwrap();
        let swapped = Approval {
            from: b.recipient().text(),
            ..raw
        };
        let swapped = format!(
            "{APPROVAL}{}",
            B64.encode(serde_json::to_vec(&swapped).unwrap())
        );
        assert_eq!(
            verify(&a, &[b.recipient()], &req, &swapped).unwrap_err(),
            "approval does not verify"
        );
        assert!(Ask::parse("kepr-quorum1-!!").is_err());
    }

    /// Security review (T7.12): the approver is the key the MAC proves,
    /// whatever text the approval names it by (V1, or V2 with another
    /// ML-KEM key), so one device can't count twice.
    #[test]
    fn the_approver_is_the_key_not_its_text() {
        let (a, b, c) = (key(), key(), key());
        let req = ask(&a);
        let devices = [b.recipient()];
        let approval = sign(&b, &req).unwrap();
        let want = verify(&a, &devices, &req, &approval).unwrap();
        let raw: Approval = decode(&approval, APPROVAL, "approval").unwrap();
        let x = *b.recipient().x25519();
        let Recipient::V2 { ek, .. } = c.recipient() else {
            panic!("a v2 key");
        };
        for alias in [Recipient::V1(x), Recipient::V2 { x, ek }] {
            assert_ne!(alias.text(), raw.from);
            let renamed = Approval {
                id: raw.id.clone(),
                from: alias.text(),
                mac: raw.mac.clone(),
            };
            let text = format!(
                "{APPROVAL}{}",
                B64.encode(serde_json::to_vec(&renamed).unwrap())
            );
            assert_eq!(verify(&a, &devices, &req, &text).unwrap(), want);
        }
    }
}
