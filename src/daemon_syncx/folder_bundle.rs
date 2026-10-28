// daemon_syncx/folder_bundle.rs — T6.02 the shared-folder bundle format.
//
//   kepr_bundle1\n
//   {"kind":"folder","v":1,"id":…,"folder":"team/api","from":"kepr-pk2-…",
//    "signer":"<ed25519 pub>","at":U,"sealed":false,
//    "keys":[{"to":"<hex x25519>","wrap":"kepr-share2-…","bind":"…"},…],
//    "items":[{"name":"API_KEY","nonce":…,"ct":…},…]}\n
//   <ed25519 signature over "kepr-folder-manifest-v1\0" ‖ the line above>\n
//
// One random folder key per export seals each credential (AES-256-GCM,
// AAD = folder id ‖ 0 ‖ name) and is wrapped to each recipient with the
// share envelope (kem.rs, v2 for v2 keys). Names and the folder path are
// visible; values are not.
//
// The manifest is signed with the exporter's Ed25519 folder key. It lives
// inside the share-key record, which `get` refuses like an SSH key: it is
// derived from the share secret (HKDF, its own label), so it needs no
// second stored secret. Share keys can't sign, so each wrap also carries
// `bind`, a MAC under HKDF(X25519(exporter, recipient)) over the folder
// id, the signer key and the wrap: only the holder of `from`'s secret (or
// the recipient) can make it. An importer accepts a bundle only when
// `from` is a pinned contact, `bind` checks out for it and the signature
// verifies, so a changed byte anywhere is refused.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use kepr_core::generate::ZeroString;
use kepr_core::protocol_syncx::BUNDLE_MAGIC;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::bundle::ItemMeta;
use crate::daemon_eco::cipher::{self, NONCE_LEN};
use crate::daemon_sharing::kem::{self, Recipient, ShareSecret};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const KIND: &str = "folder";
const DOMAIN: &[u8] = b"kepr-folder-manifest-v1\0";
pub const FORGED: &str = "damaged or forged folder bundle";
pub const BAD_SIGNATURE: &str =
    "the folder bundle's signature does not verify (changed after it was made?)";

/// What one credential carries inside its sealed item.
#[derive(Debug, Serialize, Deserialize)]
pub struct Payload {
    pub value: ZeroString,
    #[serde(default)]
    pub meta: ItemMeta,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    kind: String,
    v: u32,
    id: String,
    folder: String,
    from: String,
    signer: String,
    at: u64,
    sealed: bool,
    keys: Vec<Wrap>,
    items: Vec<Sealed>,
}

#[derive(Serialize, Deserialize)]
struct Wrap {
    to: String,
    wrap: String,
    bind: String,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    name: String,
    nonce: String,
    ct: String,
}

/// An opened bundle: who sent it (the pinned contact's name), when (the
/// signed manifest's `at`) and what.
#[derive(Debug)]
pub struct Opened {
    pub id: String,
    pub folder: String,
    pub contact: String,
    pub at: u64,
    pub sealed: bool,
    pub items: Vec<(String, Payload)>,
}

/// The folder's id: the same for every export of one folder by one key.
pub fn folder_id(from: &str, folder: &str) -> String {
    let d = cipher::sha256(&[
        b"kepr-folder-id-v1\0",
        from.as_bytes(),
        b"\0",
        folder.as_bytes(),
    ]);
    hex::encode(&d[..16])
}

/// The exporter's Ed25519 folder key, derived from the share secret.
fn signing_key(me: &ShareSecret) -> SigningKey {
    let secret = Zeroizing::new(me.x.to_bytes());
    let seed = cipher::hkdf_sha256(None, secret.as_ref(), &[b"kepr-folder-signing-v1"]);
    SigningKey::from_bytes(&seed)
}

fn bind_key(
    mine: &StaticSecret,
    peer: &[u8; 32],
    from: &[u8; 32],
    to: &[u8; 32],
) -> Option<Zeroizing<[u8; 32]>> {
    let ss = mine.diffie_hellman(&PublicKey::from(*peer));
    if !ss.was_contributory() {
        return None;
    }
    let info = [&b"kepr-folder-v1"[..], from, to].concat();
    Some(cipher::hkdf_sha256(None, ss.as_bytes(), &[&info]))
}

/// The bytes a wrap's bind MAC covers.
fn bound(id: &str, signer: &str, w: &Wrap) -> Vec<u8> {
    let mut m = b"kepr-folder-signer-v1".to_vec();
    for part in [id, signer, &w.to, &w.wrap] {
        m.extend_from_slice(&(part.len() as u32).to_be_bytes());
        m.extend_from_slice(part.as_bytes());
    }
    m
}

fn aad(id: &str, name: &str) -> Vec<u8> {
    [id.as_bytes(), b"\0", name.as_bytes()].concat()
}

/// Seal `items` of `folder` from `me` to each of `to`.
pub fn seal(
    me: &ShareSecret,
    to: &[Recipient],
    (folder, sealed, at): (&str, bool, u64),
    items: &[(String, Payload)],
) -> Result<Vec<u8>, String> {
    if to.is_empty() {
        return Err("name at least one recipient (--to KEY or a pinned contact)".into());
    }
    let from = me.recipient();
    let from_x = *from.x25519();
    let signer = signing_key(me);
    let mut m = Manifest {
        kind: KIND.into(),
        v: 1,
        id: folder_id(&from.text(), folder),
        folder: folder.to_string(),
        from: from.text(),
        signer: B64.encode(signer.verifying_key().to_bytes()),
        at,
        sealed,
        keys: Vec::new(),
        items: Vec::new(),
    };
    let mut key = Zeroizing::new([0u8; 32]);
    cipher::fill_random(key.as_mut()).map_err(|_| "CSPRNG failure")?;
    for (name, p) in items {
        let mut nonce = [0u8; NONCE_LEN];
        cipher::fill_random(&mut nonce).map_err(|_| "CSPRNG failure")?;
        let plain = Zeroizing::new(serde_json::to_vec(p).map_err(|e| e.to_string())?);
        let ct = cipher::seal(key.as_ref(), &nonce, &aad(&m.id, name), &plain)
            .map_err(|_| "folder encryption failed".to_string())?;
        m.items.push(Sealed {
            name: name.clone(),
            nonce: B64.encode(nonce),
            ct: B64.encode(ct),
        });
    }
    for r in to {
        let mut w = Wrap {
            to: hex::encode(r.x25519()),
            wrap: kem::seal(r, key.as_ref())?,
            bind: String::new(),
        };
        let k = bind_key(&me.x, r.x25519(), &from_x, r.x25519())
            .ok_or("a recipient key is not usable")?;
        w.bind = B64.encode(cipher::hmac_sha256(
            k.as_ref(),
            &[&bound(&m.id, &m.signer, &w)],
        ));
        m.keys.push(w);
    }
    let line = serde_json::to_vec(&m).map_err(|e| e.to_string())?;
    let sig = signer.sign(&[DOMAIN, &line].concat());
    let mut out = BUNDLE_MAGIC.to_vec();
    out.extend(&line);
    out.push(b'\n');
    out.extend(B64.encode(sig.to_bytes()).as_bytes());
    out.push(b'\n');
    Ok(out)
}

fn split(bytes: &[u8]) -> Result<(Manifest, &[u8], &[u8]), String> {
    let rest = bytes
        .strip_prefix(BUNDLE_MAGIC)
        .ok_or("not a kepr bundle")?;
    let nl = rest
        .iter()
        .position(|b| *b == b'\n')
        .ok_or("not a folder bundle")?;
    let (line, sig) = (&rest[..nl], rest[nl + 1..].trim_ascii());
    let m: Manifest = serde_json::from_slice(line).map_err(|_| "not a folder bundle")?;
    if m.kind != KIND || m.v != 1 {
        return Err("not a folder bundle (or one from a newer kepr)".into());
    }
    Ok((m, line, sig))
}

/// Open a bundle for `me`. `pinned(public)` names the contact pinned to
/// a public key, if any.
pub fn open(
    me: &ShareSecret,
    bytes: &[u8],
    pinned: impl Fn(&str) -> Option<String>,
) -> Result<Opened, String> {
    let (m, line, sig) = split(bytes)?;
    let vk: [u8; 32] = B64
        .decode(&m.signer)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or(FORGED)?;
    let vk = VerifyingKey::from_bytes(&vk).map_err(|_| FORGED)?;
    let sig = B64
        .decode(sig)
        .ok()
        .and_then(|s| Signature::from_slice(&s).ok())
        .ok_or(BAD_SIGNATURE)?;
    vk.verify_strict(&[DOMAIN, line].concat(), &sig)
        .map_err(|_| BAD_SIGNATURE)?;
    let from = Recipient::parse(&m.from).map_err(|_| FORGED)?;
    let contact = pinned(&from.text()).ok_or_else(|| {
        format!(
            "from a key you haven't pinned ({}): check it with the sender, then \
             kepr share contact add NAME KEY",
            crate::daemon_sharing::contacts::fingerprint(&from.text())
        )
    })?;
    if m.id != folder_id(&from.text(), &m.folder) {
        return Err(FORGED.into());
    }
    let my_x = PublicKey::from(&me.x).to_bytes();
    let w = m
        .keys
        .iter()
        .find(|w| w.to == hex::encode(my_x))
        .ok_or("not encrypted to your share key")?;
    let k = bind_key(&me.x, from.x25519(), from.x25519(), &my_x).ok_or(FORGED)?;
    let mac = B64.decode(&w.bind).map_err(|_| FORGED)?;
    if !cipher::hmac_sha256_verify(k.as_ref(), &[&bound(&m.id, &m.signer, w)], &mac) {
        return Err(format!("{FORGED}: not signed by {contact}'s key"));
    }
    let key = kem::open(me, &w.wrap).map_err(|_| FORGED)?;
    let mut items = Vec::with_capacity(m.items.len());
    for s in &m.items {
        let nonce: [u8; NONCE_LEN] = B64
            .decode(&s.nonce)
            .ok()
            .and_then(|n| n.try_into().ok())
            .ok_or(FORGED)?;
        let ct = B64.decode(&s.ct).map_err(|_| FORGED)?;
        let plain = cipher::open(&key, &nonce, &aad(&m.id, &s.name), &ct).map_err(|_| FORGED)?;
        let p: Payload = serde_json::from_slice(&plain).map_err(|_| FORGED)?;
        items.push((s.name.clone(), p));
    }
    Ok(Opened {
        id: m.id,
        folder: m.folder,
        contact,
        at: m.at,
        sealed: m.sealed,
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ShareSecret {
        ShareSecret::generate().unwrap()
    }

    fn items() -> Vec<(String, Payload)> {
        let p = |v: &str| Payload {
            value: v.into(),
            meta: ItemMeta::default(),
        };
        vec![("API".into(), p("one")), ("DB".into(), p("two"))]
    }

    fn pin(who: &ShareSecret) -> impl Fn(&str) -> Option<String> {
        let public = who.recipient().text();
        move |k: &str| (k == public).then(|| "alice".to_string())
    }

    #[test]
    fn two_recipients_open_it_and_a_third_key_cannot() {
        let (a, b, c, d) = (key(), key(), key(), key());
        let bytes = seal(
            &a,
            &[b.recipient(), c.recipient()],
            ("team/api", true, 5),
            &items(),
        )
        .unwrap();
        for me in [&b, &c] {
            let o = open(me, &bytes, pin(&a)).unwrap();
            assert_eq!(
                (o.folder.as_str(), o.contact.as_str(), o.sealed),
                ("team/api", "alice", true)
            );
            assert_eq!(o.items[1].0, "DB");
            assert_eq!(o.items[1].1.value.as_str(), "two");
            assert_eq!(o.id, folder_id(&a.recipient().text(), "team/api"));
            assert_eq!(o.at, 5);
        }
        assert_eq!(
            open(&d, &bytes, pin(&a)).unwrap_err(),
            "not encrypted to your share key"
        );
        // Quoted: random base64 can hold the bare letters, never a quote.
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("\"one\"") && !text.contains("\"two\""));
        assert!(split(&bytes).is_ok());
    }

    #[test]
    fn a_changed_byte_fails_the_signature() {
        let (a, b) = (key(), key());
        let bytes = seal(&a, &[b.recipient()], ("team", false, 5), &items()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for (from, to) in [
            ("\"sealed\":false", "\"sealed\":true "),
            ("\"name\":\"DB\"", "\"name\":\"DC\""),
        ] {
            let bad = text.replacen(from, to, 1);
            assert_ne!(bad, text);
            assert_eq!(
                open(&b, bad.as_bytes(), pin(&a)).unwrap_err(),
                BAD_SIGNATURE
            );
        }
    }

    #[test]
    fn only_a_pinned_sender_with_its_own_key_is_accepted() {
        let (a, b, mallory) = (key(), key(), key());
        let bytes = seal(&a, &[b.recipient()], ("team", false, 5), &items()).unwrap();
        let e = open(&b, &bytes, |_: &str| None).unwrap_err();
        assert!(e.contains("haven't pinned"), "{e}");
        // Mallory re-signs a manifest that names Alice as the sender: her
        // own signer key verifies, but the bind needs Alice's secret.
        let forged = seal(&mallory, &[b.recipient()], ("team", false, 5), &items()).unwrap();
        let (mut m, _, _) = split(&forged).unwrap();
        m.from = a.recipient().text();
        m.id = folder_id(&m.from, &m.folder);
        let line = serde_json::to_vec(&m).unwrap();
        let sig = signing_key(&mallory).sign(&[DOMAIN, &line].concat());
        let mut f = BUNDLE_MAGIC.to_vec();
        f.extend(&line);
        f.push(b'\n');
        f.extend(B64.encode(sig.to_bytes()).as_bytes());
        let e = open(&b, &f, pin(&a)).unwrap_err();
        assert!(e.contains("not signed by alice"), "{e}");
        assert!(seal(&a, &[], ("team", false, 5), &items()).is_err());
    }

    fn fixed(x: u8, seed: u8) -> ShareSecret {
        ShareSecret {
            x: StaticSecret::from([x; 32]),
            mlkem_seed: Some(Zeroizing::new([seed; 64])),
        }
    }

    // Made by the code before it moved onto the cipher seam (T12.42).
    #[test]
    fn a_bundle_from_the_old_code_still_opens() {
        let (a, b) = (fixed(5, 6), fixed(7, 8));
        let bytes = include_bytes!("testdata/folder_bundle.bin");
        let o = open(&b, bytes, pin(&a)).unwrap();
        assert_eq!((o.folder.as_str(), o.sealed, o.at), ("team/api", true, 5));
        assert_eq!(o.items[1].1.value.as_str(), "two");
        assert_eq!(
            folder_id("kepr-pk2-abc", "team/api"),
            "350aaffaea949a4e308255551d25043c"
        );
        assert_eq!(
            hex::encode(signing_key(&a).verifying_key().to_bytes()),
            "312ef4d282b1ea216e0cb3fc3dc6a163ac3af47110a5c5d10b558856a877a6be"
        );
    }
}
