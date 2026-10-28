// daemon_desktop/doc.rs — how a Secret Service item is kept: one JSON
// document in one encrypted credential, `SSI_<26-char id>`, filed under
// the folder `secret-service`. Decrypted only inside the daemon, to match
// attributes or to answer a secret request; the whole document (secret
// included) is wiped when dropped.

use std::collections::BTreeMap;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_desktop::{self as pd, SsItemInfo};
use serde::{Deserialize, Serialize};

use crate::expiry;
use crate::store::{cred_exists, cred_path};
use crate::{crypto, daemon_cache};

pub const PREFIX: &str = "SSI_";
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Serialize, Deserialize)]
pub struct ItemDoc {
    pub v: u8,
    pub collection: String,
    pub label: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    pub content_type: String,
    /// Base64 of the secret.
    pub secret: ZeroString,
    pub created: u64,
    pub modified: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    Locked,
    NotFound,
    Invalid(String),
    Other(String),
}

impl Failure {
    pub fn text(&self) -> String {
        match self {
            Failure::Locked => pd::ERR_LOCKED.into(),
            Failure::NotFound => pd::ERR_NO_ITEM.into(),
            Failure::Invalid(e) | Failure::Other(e) => e.clone(),
        }
    }

    pub fn response(&self) -> Response {
        Response::fail(self.text())
    }
}

pub fn cred_name(id: &str) -> String {
    format!("{PREFIX}{id}")
}

/// 128 random bits as 26 base32 characters.
pub fn new_id() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let (mut out, mut acc, mut bits) = (String::with_capacity(26), 0u32, 0u32);
    for byte in b {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    Ok(out)
}

pub fn locked() -> bool {
    crypto::backend_is_locked()
}

/// The ids of the caller's items.
pub fn ids(uid: u32) -> Vec<String> {
    daemon_cache::list_for_uid(uid)
        .into_iter()
        .filter_map(|(name, _)| name.strip_prefix(PREFIX).map(String::from))
        .filter(|id| pd::valid_item_id(id))
        .collect()
}

/// Read and parse the document in credential `name`.
pub fn read(uid: u32, name: &str) -> Result<ZeroString, Failure> {
    if locked() {
        return Err(Failure::Locked);
    }
    if !cred_exists(uid, name) {
        return Err(Failure::NotFound);
    }
    crypto::default_backend().decrypt(uid, name).map_err(|e| {
        if locked() {
            Failure::Locked
        } else {
            Failure::Other(e)
        }
    })
}

pub fn load(uid: u32, id: &str) -> Result<ItemDoc, Failure> {
    if !pd::valid_item_id(id) {
        return Err(Failure::Invalid("not an item id".into()));
    }
    let text = read(uid, &cred_name(id))?;
    serde_json::from_str(text.as_str()).map_err(|_| Failure::Other("the item is damaged".into()))
}

/// Write `json` to credential `name` and make sure its sidecar marks it
/// as a Secret Service item in the shared folder (other sidecar fields,
/// tags a user added for instance, stay).
pub fn write(uid: u32, name: &str, json: &ZeroString) -> Result<(), Failure> {
    let _lock = crate::daemon_credlock::lock(uid, name);
    let existed = cred_exists(uid, name);
    crypto::default_backend()
        .encrypt(uid, name, json.as_bytes())
        .map_err(|e| {
            if locked() {
                Failure::Locked
            } else {
                Failure::Other(e)
            }
        })?;
    let meta_path = expiry::meta_path_for(&cred_path(uid, name));
    let mut meta = expiry::read_meta(&meta_path)
        .and_then(Result::ok)
        .unwrap_or_default();
    if meta.desktop_item != Some(true) || meta.folder.is_none() {
        meta.desktop_item = Some(true);
        meta.folder.get_or_insert_with(|| pd::FOLDER.to_string());
        if let Err(e) = expiry::write_meta(&meta_path, &meta) {
            if !existed {
                let _ = crypto::default_backend().delete(uid, name);
            }
            return Err(Failure::Other(format!("meta write failed: {e}")));
        }
    }
    daemon_cache::invalidate(uid);
    Ok(())
}

pub fn save(uid: u32, id: &str, doc: &ItemDoc) -> Result<(), Failure> {
    let json = ZeroString::from_string(
        serde_json::to_string(doc).map_err(|_| Failure::Other("cannot encode the item".into()))?,
    );
    write(uid, &cred_name(id), &json)
}

pub fn remove(uid: u32, name: &str) -> Result<(), Failure> {
    let _lock = crate::daemon_credlock::lock(uid, name);
    if !cred_exists(uid, name) {
        return Err(Failure::NotFound);
    }
    crypto::default_backend()
        .delete(uid, name)
        .map_err(Failure::Other)?;
    expiry::delete_meta(&expiry::meta_path_for(&cred_path(uid, name)));
    daemon_cache::invalidate(uid);
    Ok(())
}

pub fn info(id: &str, d: &ItemDoc) -> SsItemInfo {
    SsItemInfo {
        id: id.to_string(),
        collection: d.collection.clone(),
        label: d.label.clone(),
        attributes: d.attributes.clone(),
        content_type: d.content_type.clone(),
        created: d.created,
        modified: d.modified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_26_base32_characters_and_random() {
        let a = new_id().unwrap();
        assert!(pd::valid_item_id(&a), "{a}");
        assert_ne!(a, new_id().unwrap());
    }

    #[test]
    fn failures_speak_the_protocol_s_words() {
        assert_eq!(Failure::Locked.text(), pd::ERR_LOCKED);
        assert_eq!(Failure::NotFound.text(), pd::ERR_NO_ITEM);
        assert_eq!(Failure::Invalid("x".into()).text(), "x");
        assert_eq!(cred_name("ID"), "SSI_ID");
    }
}
