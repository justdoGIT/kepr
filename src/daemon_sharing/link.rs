// daemon_sharing/link.rs — one-time share links (T6.04).
//
//   ShareLinkCreate  NAME's value (same policy as `share send`) in a
//                    single-use payload, AES-256-GCM under a fresh random
//                    key: blob = `kepr-link1-<b64(nonce ‖ ct)>`. The CLI
//                    puts the blob on a relay (or in a file) and the key
//                    only in the link's #fragment.
//   ShareLinkOpen    blob + key → the payload, stored like a received
//                    share (expiry, single use by id, no overwrite).
//
// The relay sees the blob and its id, never the key.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::SharingResponse;
use zeroize::Zeroizing;

use super::audit_r;
use crate::daemon_share::{new_payload, received, store_payload, Payload1};
use crate::expiry;

pub const BLOB_PREFIX: &str = "kepr-link1-";
const AAD: &[u8] = b"kepr-link-v1";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const NOT_OPENED: &str = "this link can't be opened (wrong key, or the blob was altered)";

/// Encrypt `payload` under a new random key: (key, blob).
pub fn seal(payload: &[u8]) -> Result<(Zeroizing<[u8; 32]>, String), String> {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 12];
    getrandom::fill(key.as_mut()).map_err(|e| format!("CSPRNG failure: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| "bad key")?;
    let ct = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: payload,
                aad: AAD,
            },
        )
        .map_err(|_| "encryption failed")?;
    Ok((
        key,
        format!("{BLOB_PREFIX}{}", B64.encode([&nonce[..], &ct].concat())),
    ))
}

pub fn open(key: &[u8], blob: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let raw = blob
        .trim()
        .strip_prefix(BLOB_PREFIX)
        .and_then(|b| B64.decode(b).ok())
        .filter(|r| r.len() > 12 + 16)
        .ok_or("not a kepr link blob")?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| NOT_OPENED)?;
    let nonce: [u8; 12] = raw[..12].try_into().map_err(|_| NOT_OPENED)?;
    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &raw[12..],
                aad: AAD,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| NOT_OPENED.into())
}

/// The link key as it travels in the fragment.
pub fn key_text(key: &[u8; 32]) -> String {
    B64.encode(key)
}

pub fn handle_create(
    (uid, peer_pid): (u32, i32),
    username: &str,
    name: &str,
    ttl: Option<u64>,
) -> Response {
    let upper = name.to_uppercase();
    let r = (|| {
        let p = new_payload((uid, peer_pid), name, ttl)?;
        let json = Zeroizing::new(serde_json::to_vec(&p).map_err(|e| e.to_string())?);
        let (key, blob) = seal(&json)?;
        let now = expiry::now_unix();
        Ok(SharingResponse::ShareLink {
            id: p.id,
            key: key_text(&key).into(),
            blob,
            expires_at: expiry::format_expires_at(p.expires),
            ttl_secs: p.expires.saturating_sub(now).max(1),
        })
    })();
    audit_r("share-link", uid, username, Some(&upper), &r);
    match r {
        Ok(link) => link.into(),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_open(
    uid: u32,
    username: &str,
    blob: &str,
    key: &str,
    rename: Option<&str>,
) -> Response {
    let r = (|| {
        let key = Zeroizing::new(B64.decode(key.trim()).map_err(|_| NOT_OPENED)?);
        let plain = open(&key, blob)?;
        let p: Payload1 = serde_json::from_slice(&plain).map_err(|_| "malformed share")?;
        store_payload(uid, username, p, rename)
    })();
    received("share-link-open", uid, username, r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;
    use kepr_core::protocol_sharing::SharingResponse as S;

    fn link(uid: u32, name: &str) -> (String, String) {
        match handle_create((uid, 0), "t", name, Some(60)) {
            Response::Sharing(S::ShareLink { key, blob, id, .. }) => {
                assert_eq!(id.len(), 32);
                (key.as_str().to_string(), blob)
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn seal_and_open() {
        let (key, blob) = seal(b"payload").unwrap();
        assert_eq!(open(key.as_ref(), &blob).unwrap().as_slice(), b"payload");
        assert!(open(&[0u8; 32], &blob).is_err());
        let mut raw = B64.decode(&blob[BLOB_PREFIX.len()..]).unwrap();
        raw[20] ^= 1;
        let altered = format!("{BLOB_PREFIX}{}", B64.encode(raw));
        assert!(open(key.as_ref(), &altered).is_err());
        assert!(open(key.as_ref(), "kepr-share2-AAAA").is_err());
    }

    #[test]
    fn a_link_opens_once_into_the_store() {
        let (a, b) = (testkit::uid(), testkit::uid());
        testkit::set(a, "LINK_SRC", "s3cret");
        let (key, blob) = link(a, "LINK_SRC");
        assert!(!blob.contains("s3cret"));
        let r = handle_open(b, "t", &blob, &key, Some("GOT"));
        assert!(r.is_success(), "{r:?}");
        assert_eq!(testkit::value(b, "GOT").as_deref(), Some("s3cret"));
        // Single use: the same link can't be stored again.
        let again = handle_open(b, "t", &blob, &key, Some("GOT2"));
        assert!(matches!(again, Response::Err { error } if error.contains("already")));
        // A wrong key opens nothing.
        let r = handle_open(b, "t", &blob, &key_text(&[1u8; 32]), Some("GOT3"));
        assert!(!r.is_success());
    }

    #[test]
    fn an_expired_link_is_refused() {
        let uid = testkit::uid();
        let p = Payload1 {
            id: "ab".repeat(16),
            name: "OLD_LINK".into(),
            value: "v".into(),
            expires: expiry::now_unix() - 1,
            record_type: None,
        };
        let (key, blob) = seal(&serde_json::to_vec(&p).unwrap()).unwrap();
        let r = handle_open(uid, "t", &blob, &key_text(&key), None);
        assert!(matches!(r, Response::Err { error } if error.contains("expired")));
        assert!(testkit::value(uid, "OLD_LINK").is_none());
    }

    #[test]
    fn sealed_values_never_go_into_a_link() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "LINK_SEALED", "v");
        let r = handle_create((uid, 0), "t", "LINK_SEALED", None);
        assert!(matches!(r, Response::Err { error } if error.contains("can't be shared")));
    }
}
