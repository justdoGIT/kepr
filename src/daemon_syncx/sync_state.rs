// daemon_syncx/sync_state.rs — T6.10 what this device knows about each
// synced credential: when it last changed and on which device (`at`,
// `origin`: last writer wins, ties broken by device id), and a
// fingerprint of its value and meta. A delete is a tombstone (no
// fingerprint) kept 30 days. Fingerprints are HMACs under a key derived
// from the user's share key, so the state file says nothing about values.
//
// Local changes are found by comparing fingerprints at each sync: a new
// or changed credential takes its value file's modification time (at
// least one second after what was known), a vanished one becomes a
// tombstone. Sealed, SSH, share-key and gated credentials never sync
// (export.rs `readable`).

use std::collections::BTreeMap;

use kepr_core::generate::ZeroString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::bundle::ItemMeta;
use crate::daemon_eco::cipher;
use crate::daemon_sharing::kem::ShareSecret;
use crate::daemon_sharing::{load, save, state_path};
use crate::store::{cred_exists, cred_path, validate_name};

pub const TOMBSTONE_TTL: u64 = 30 * 86_400;

#[derive(Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub recs: BTreeMap<String, Rec>,
    /// Per sending device (its X25519 key, hex): the newest bundle `at`
    /// merged. An older bundle from it is a stale or replayed copy and is
    /// ignored: once a tombstone has expired, it would bring back what
    /// was deleted.
    #[serde(default)]
    pub seen: BTreeMap<String, u64>,
    /// The `at` of the last bundle this device built; each new one takes
    /// a later one, so "older" is exact.
    #[serde(default)]
    pub built: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rec {
    pub at: u64,
    pub origin: String,
    /// `None`: deleted (a tombstone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
}

impl Rec {
    /// Last writer wins; the device id breaks a tie.
    pub fn beats(&self, other: &Rec) -> bool {
        (self.at, &self.origin) > (other.at, &other.origin)
    }
}

/// A credential as sync carries it.
pub struct Local {
    pub value: ZeroString,
    pub meta: ItemMeta,
}

pub fn load_state(uid: u32) -> State {
    load(&state_path("sync", uid))
}

pub fn save_state(uid: u32, st: &State) -> Result<(), String> {
    save(&state_path("sync", uid), st)
}

/// The fingerprint key: derived from the share key, never stored.
pub fn fp_key(me: &ShareSecret) -> Zeroizing<[u8; 32]> {
    let secret = Zeroizing::new(me.x.to_bytes());
    cipher::hkdf_sha256(None, secret.as_ref(), &[b"kepr-sync-fingerprint-v1"])
}

pub fn fingerprint(key: &[u8; 32], name: &str, l: &Local) -> String {
    let meta = serde_json::to_vec(&l.meta).unwrap_or_default();
    let mut msg = Vec::new();
    for part in [name.as_bytes(), l.value.as_bytes(), &meta] {
        msg.extend_from_slice(&(part.len() as u64).to_be_bytes());
        msg.extend_from_slice(part);
    }
    hex::encode(&cipher::hmac_sha256(key, &[&msg])[..16])
}

/// The value file's modification time (seconds), if it has one.
fn mtime(uid: u32, name: &str) -> Option<u64> {
    let path = cred_path(uid, name);
    if let Some((_, t)) = crate::daemon_vault::stat(&path) {
        return Some(t);
    }
    let t = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// `name` as sync carries it, if `get` could read it now with no prompt.
pub fn local_one(who: (u32, i32), username: &str, name: &str) -> Option<Local> {
    let _lock = crate::daemon_credlock::lock(who.0, name);
    let meta = super::export::readable(who, username, name).ok()?;
    let value = crate::crypto::default_backend().decrypt(who.0, name).ok()?;
    let meta = super::export::item_meta(&meta);
    Some(Local { value, meta })
}

/// Every credential sync carries for `uid` now.
pub fn local(who: (u32, i32), username: &str) -> BTreeMap<String, Local> {
    crate::store::list_for_uid(who.0)
        .into_iter()
        .filter(|(name, _)| validate_name(name).is_ok())
        .filter_map(|(name, _)| local_one(who, username, &name).map(|l| (name, l)))
        .collect()
}

impl State {
    /// Record local changes as of `now` (`me` = this device's id).
    pub fn refresh(
        &mut self,
        uid: u32,
        local: &BTreeMap<String, Local>,
        (key, me): (&[u8; 32], &str),
        now: u64,
    ) {
        for (name, l) in local {
            let fp = fingerprint(key, name, l);
            let prev = self.recs.get(name);
            if prev.is_some_and(|r| r.fp.as_deref() == Some(fp.as_str())) {
                continue;
            }
            let after = prev.map_or(0, |r| r.at.saturating_add(1));
            let at = mtime(uid, name).unwrap_or(now).max(after);
            let rec = Rec {
                at,
                origin: me.to_string(),
                fp: Some(fp),
            };
            self.recs.insert(name.clone(), rec);
        }
        for (name, r) in self.recs.iter_mut() {
            if r.fp.is_some() && !local.contains_key(name) && !cred_exists(uid, name) {
                *r = Rec {
                    at: now.max(r.at.saturating_add(1)),
                    origin: me.to_string(),
                    fp: None,
                };
            }
        }
        self.recs
            .retain(|_, r| r.fp.is_some() || now < r.at.saturating_add(TOMBSTONE_TTL));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn local_of(pairs: &[(&str, &str)]) -> BTreeMap<String, Local> {
        pairs
            .iter()
            .map(|(n, v)| {
                let l = Local {
                    value: ZeroString::from(*v),
                    meta: ItemMeta::default(),
                };
                (n.to_string(), l)
            })
            .collect()
    }

    #[test]
    fn changes_deletes_and_old_tombstones() {
        let uid = testkit::uid();
        let key = [7u8; 32];
        let mut st = State::default();
        testkit::set(uid, "SS_A", "1");
        st.refresh(uid, &local_of(&[("SS_A", "1")]), (&key, "me"), 100);
        let first = st.recs["SS_A"].clone();
        assert_eq!(first.origin, "me");
        assert!(first.fp.is_some());

        // Unchanged: nothing moves. Changed: later than before.
        st.refresh(uid, &local_of(&[("SS_A", "1")]), (&key, "me"), 200);
        assert_eq!(st.recs["SS_A"], first);
        st.recs.get_mut("SS_A").unwrap().at = u64::MAX / 2; // a far-future writer
        st.recs.get_mut("SS_A").unwrap().origin = "zz".into();
        st.refresh(uid, &local_of(&[("SS_A", "2")]), (&key, "me"), 300);
        assert_eq!(
            st.recs["SS_A"].at,
            u64::MAX / 2 + 1,
            "a local edit beats what it saw"
        );

        // Gone from the store: a tombstone, dropped after 30 days.
        crate::daemon_history::purge(uid, "SS_A");
        crate::crypto::default_backend()
            .delete(uid, "SS_A")
            .unwrap();
        st.recs.get_mut("SS_A").unwrap().at = 400;
        st.refresh(uid, &BTreeMap::new(), (&key, "me"), 500);
        assert_eq!(
            st.recs["SS_A"],
            Rec {
                at: 500,
                origin: "me".into(),
                fp: None
            }
        );
        st.refresh(uid, &BTreeMap::new(), (&key, "me"), 500 + TOMBSTONE_TTL);
        assert!(st.recs.is_empty());
    }

    #[test]
    fn ties_go_to_the_higher_device_id() {
        let r = |at, o: &str| Rec {
            at,
            origin: o.into(),
            fp: None,
        };
        assert!(r(2, "a").beats(&r(1, "z")));
        assert!(r(2, "b").beats(&r(2, "a")));
        assert!(!r(2, "a").beats(&r(2, "a")));
    }

    #[test]
    fn fingerprints_cover_value_and_meta_and_depend_on_the_key() {
        let l = |v: &str, tags: Option<Vec<String>>| Local {
            value: ZeroString::from(v),
            meta: ItemMeta {
                tags,
                ..Default::default()
            },
        };
        let k = [1u8; 32];
        let base = fingerprint(&k, "A", &l("v", None));
        assert_ne!(base, fingerprint(&k, "A", &l("w", None)));
        assert_ne!(base, fingerprint(&k, "A", &l("v", Some(vec!["t".into()]))));
        assert_ne!(base, fingerprint(&[2u8; 32], "A", &l("v", None)));
        assert_eq!(base, fingerprint(&k, "A", &l("v", None)));
    }

    fn fixed(x: u8, seed: u8) -> ShareSecret {
        ShareSecret {
            x: x25519_dalek::StaticSecret::from([x; 32]),
            mlkem_seed: Some(Zeroizing::new([seed; 64])),
        }
    }

    // Computed by the code before it moved onto the cipher seam (T12.42).
    #[test]
    fn fingerprints_match_the_old_code() {
        let k = fp_key(&fixed(5, 6));
        assert_eq!(
            hex::encode(*k),
            "c953c6e2eeab7d1e111133a6ba4b237f0658da58ccc6e28b39e7e83b65d28032"
        );
        let l = Local {
            value: ZeroString::from("v"),
            meta: ItemMeta::default(),
        };
        assert_eq!(
            fingerprint(&k, "NAME", &l),
            "16e6eca716d1ed67628f55871923465d"
        );
    }
}
