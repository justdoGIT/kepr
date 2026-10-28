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
// T6.05: each link is a row in the sent-share ledger (sent.rs); with
// `self_destruct` the record is marked to be deleted once it is opened.
//
// The relay sees the blob and its id, never the key.

use base64::Engine;
use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{SentShare, SharingResponse};
use zeroize::Zeroizing;

use super::{audit_r, sent};
use crate::daemon_eco::cipher;
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
    cipher::fill_random(key.as_mut()).map_err(|_| "CSPRNG failure")?;
    cipher::fill_random(&mut nonce).map_err(|_| "CSPRNG failure")?;
    let ct = cipher::seal(key.as_ref(), &nonce, AAD, payload).map_err(|_| "encryption failed")?;
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
    let nonce: [u8; 12] = raw[..12].try_into().map_err(|_| NOT_OPENED)?;
    cipher::open(key, &nonce, AAD, &raw[12..]).map_err(|_| NOT_OPENED.into())
}

/// The link key as it travels in the fragment.
pub fn key_text(key: &[u8; 32]) -> String {
    B64.encode(key)
}

/// `share send --once` flags.
#[derive(Default)]
pub struct Options {
    pub ttl: Option<u64>,
    pub self_destruct: bool,
    pub relay: Option<String>,
    /// T11.15: the received copy deletes itself this long after its first get.
    pub view_window: Option<u64>,
}

pub fn handle_create(
    (uid, peer_pid): (u32, i32),
    username: &str,
    name: &str,
    opts: Options,
) -> Response {
    let Options {
        ttl,
        self_destruct,
        relay,
        view_window,
    } = opts;
    let upper = name.to_uppercase();
    let r = (|| {
        crate::daemon_sharing::view::check(view_window)?;
        if relay
            .as_ref()
            .is_some_and(|r| r.len() > 256 || r.chars().any(char::is_control))
        {
            return Err("not a relay URL".to_string());
        }
        // One lock over read + mark: a value set in between is never
        // the one that self-destructs.
        let _lock = crate::daemon_credlock::lock(uid, &upper);
        let mut p = new_payload((uid, peer_pid), name, ttl)?;
        p.view_window = view_window;
        let json = Zeroizing::new(serde_json::to_vec(&p).map_err(|e| e.to_string())?);
        let (key, blob) = seal(&json)?;
        let now = expiry::now_unix();
        let row = SentShare {
            id: p.id.clone(),
            name: upper.clone(),
            kind: "link".into(),
            to: None,
            relay,
            sent_unix: now,
            expires_unix: p.expires,
            opened_unix: None,
            self_destruct,
            settled: false,
        };
        sent::record(uid, row, now)?;
        if self_destruct {
            sent::mark(uid, &upper, &p.id)?;
        }
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
        let opts = Options {
            ttl: Some(60),
            ..Default::default()
        };
        match handle_create((uid, 0), "t", name, opts) {
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
            view_window: None,
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
        let opts = Options {
            self_destruct: true,
            ..Default::default()
        };
        let r = handle_create((uid, 0), "t", "LINK_SEALED", opts);
        assert!(matches!(r, Response::Err { error } if error.contains("can't be shared")));
    }

    #[test]
    fn a_link_carries_its_view_window_to_the_receiver() {
        let (a, b) = (testkit::uid(), testkit::uid());
        testkit::set(a, "LINK_VW", "v");
        let opts = |w| Options {
            view_window: Some(w),
            ..Default::default()
        };
        assert!(!handle_create((a, 0), "t", "LINK_VW", opts(0)).is_success());
        let Response::Sharing(S::ShareLink { key, blob, .. }) =
            handle_create((a, 0), "t", "LINK_VW", opts(300))
        else {
            panic!("no link");
        };
        assert!(handle_open(b, "t", &blob, key.as_str(), None).is_success());
        assert_eq!(testkit::meta(b, "LINK_VW").view_window_secs, Some(300));
        assert_eq!(testkit::meta(b, "LINK_VW").expires_at_unix, None);
    }

    #[test]
    fn a_blob_written_by_the_old_code_still_opens() {
        let key = B64
            .decode("6C1vTd2T4EjQS2He0QK44K3Po6SGuDsdEbjD-g4HA_g")
            .unwrap();
        let blob = "kepr-link1-pkIBg73Cw3mHwoF0ILF_yPHiTJdrBWQnFc-BaepiBeatJrlxmAbD";
        assert_eq!(&**open(&key, blob).unwrap(), b"pinned link");
    }
}
