// daemon_syncx/folder_state.rs — T6.02 what a daemon remembers about
// shared folders, one small JSON file per uid (`folders-<uid>.json`):
//
//   folders  per folder id, per name: a fingerprint of what the last
//            import wrote (HMAC under a key derived from the share key,
//            so the file says nothing about values)
//   seen     per folder id: the newest manifest `at` imported. A signed
//            bundle can't be changed, but an old one can be put back on
//            the shared path; one older than this is refused, so it can't
//            roll a rotated value back
//   sent     per folder id of our own: the last `at` exported. Each export
//            takes a later one, so two bundles of a folder never share an
//            `at` and "older" is exact
//
// Read-modify-write under LOCK (one import or export step at a time).

use std::collections::BTreeMap;
use std::sync::Mutex;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::folder_bundle::{Opened, Payload};
use crate::daemon_sharing::kem::ShareSecret;
use crate::daemon_sharing::{load, save, state_path};

pub static LOCK: Mutex<()> = Mutex::new(());

#[derive(Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub folders: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub seen: BTreeMap<String, u64>,
    #[serde(default)]
    pub sent: BTreeMap<String, u64>,
}

impl State {
    pub fn load(uid: u32) -> Self {
        load(&state_path("folders", uid))
    }

    pub fn save(&self, uid: u32) -> Result<(), String> {
        save(&state_path("folders", uid), self)
    }

    /// Refuse a bundle older than one of the same folder imported before.
    pub fn check_fresh(&self, b: &Opened) -> Result<(), String> {
        match self.seen.get(&b.id) {
            Some(seen) if b.at < *seen => Err(format!(
                "this bundle of {} from {} is older than one already imported \
                 (made {}); ask {} for a new one",
                b.folder,
                b.contact,
                crate::expiry::format_expires_at(*seen),
                b.contact
            )),
            _ => Ok(()),
        }
    }

    /// Remember that a bundle made at `at` of folder `id` was imported.
    pub fn saw(&mut self, id: &str, at: u64) {
        let seen = self.seen.entry(id.to_string()).or_insert(0);
        *seen = (*seen).max(at);
    }
}

/// The manifest time of a new export of folder `id`: now, but later than
/// the last export of it.
pub fn next_at(uid: u32, id: &str, now: u64) -> Result<u64, String> {
    let _g = LOCK.lock().map_err(|_| "folder state lock poisoned")?;
    let mut st = State::load(uid);
    let at = st.sent.get(id).map_or(now, |last| now.max(last + 1));
    st.sent.insert(id.to_string(), at);
    st.save(uid)?;
    Ok(at)
}

pub fn fp_key(me: &ShareSecret) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let secret = Zeroizing::new(me.x.to_bytes());
    Hkdf::<Sha256>::new(None, secret.as_ref())
        .expand(b"kepr-folder-fingerprint-v1", key.as_mut())
        .expect("32 bytes is a valid HKDF length");
    key
}

pub fn fingerprint(key: &[u8; 32], name: &str, p: &Payload, sealed: bool) -> String {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    let meta = serde_json::to_vec(&p.meta).unwrap_or_default();
    for part in [
        name.as_bytes(),
        p.value.as_bytes(),
        &meta,
        &[u8::from(sealed)],
    ] {
        m.update(&(part.len() as u64).to_be_bytes());
        m.update(part);
    }
    hex::encode(&m.finalize().into_bytes()[..16])
}
