// cli_desktop/ss/store.rs — what the Secret Service server needs from
// storage, as one trait. `MemStore` keeps everything in memory (secrets in
// wiped buffers): it backs the transient `session` collection and the
// server's unit tests. `DaemonStore` (daemon_store.rs) talks to kepr. Both
// pass the same `conformance` suite, so the in-memory one is a fair test
// double for the real one.

use std::collections::BTreeMap;
use std::sync::Mutex;

use kepr_core::protocol_desktop::{self as pd, SsCollectionInfo, SsItemInfo};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// kepr is locked: nothing can be read or written until it is unlocked.
    Locked,
    NotFound,
    Invalid(String),
    Other(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Locked => f.write_str(pd::ERR_LOCKED),
            StoreError::NotFound => f.write_str(pd::ERR_NO_ITEM),
            StoreError::Invalid(e) | StoreError::Other(e) => f.write_str(e),
        }
    }
}

pub type Res<T> = Result<T, StoreError>;
pub type Attrs = BTreeMap<String, String>;
pub type Secret = (Zeroizing<Vec<u8>>, String);

/// A change to an item: absent fields stay.
#[derive(Default)]
pub struct Change {
    pub label: Option<String>,
    pub attributes: Option<Attrs>,
    pub content_type: Option<String>,
    pub secret: Option<Zeroizing<Vec<u8>>>,
}

pub trait Store: Send + Sync {
    fn locked(&self) -> Res<bool>;
    fn collections(&self) -> Res<(Vec<SsCollectionInfo>, BTreeMap<String, String>)>;
    fn create_collection(&self, label: &str, alias: Option<&str>) -> Res<SsCollectionInfo>;
    fn rename_collection(&self, id: &str, label: &str) -> Res<SsCollectionInfo>;
    fn delete_collection(&self, id: &str) -> Res<u32>;
    fn set_alias(&self, alias: &str, collection: Option<&str>) -> Res<()>;
    fn items(&self, collection: Option<&str>, want: &Attrs) -> Res<Vec<SsItemInfo>>;
    /// `(collection, label, attributes)`, `(content type, secret)`.
    fn create_item(
        &self,
        place: (&str, &str, &Attrs),
        value: (&str, &[u8]),
        replace: bool,
    ) -> Res<SsItemInfo>;
    fn secret(&self, id: &str) -> Res<Secret>;
    fn update_item(&self, id: &str, change: Change) -> Res<SsItemInfo>;
    fn delete_item(&self, id: &str) -> Res<()>;
    /// What exists even while kepr is locked: collections that live in
    /// memory only, and their items.
    fn transient(&self) -> (Vec<SsCollectionInfo>, Vec<SsItemInfo>) {
        (Vec::new(), Vec::new())
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn rand_id(prefix: &str, bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    let _ = getrandom::fill(&mut b);
    format!("{prefix}{}", hex::encode(b))
}

struct MemItem {
    info: SsItemInfo,
    secret: Zeroizing<Vec<u8>>,
}

struct Mem {
    items: BTreeMap<String, MemItem>,
    collections: Vec<SsCollectionInfo>,
    aliases: BTreeMap<String, String>,
    locked: bool,
}

pub struct MemStore(Mutex<Mem>);

impl MemStore {
    /// A store with just the collections `ids` (`login` for the tests).
    pub fn new(ids: &[&str]) -> MemStore {
        let t = now();
        let collections = ids
            .iter()
            .map(|id| SsCollectionInfo {
                id: (*id).into(),
                label: (*id).into(),
                created: t,
                modified: t,
                items: 0,
            })
            .collect();
        let aliases = ids
            .first()
            .map(|id| ("default".to_string(), (*id).to_string()))
            .into_iter()
            .collect();
        MemStore(Mutex::new(Mem {
            items: BTreeMap::new(),
            collections,
            aliases,
            locked: false,
        }))
    }

    /// Test control: pretend kepr is locked.
    pub fn set_locked(&self, locked: bool) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).locked = locked;
    }

    fn m(&self) -> Res<std::sync::MutexGuard<'_, Mem>> {
        let g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if g.locked {
            Err(StoreError::Locked)
        } else {
            Ok(g)
        }
    }
}

fn subset(have: &Attrs, want: &Attrs) -> bool {
    want.iter().all(|(k, v)| have.get(k) == Some(v))
}

impl Store for MemStore {
    fn locked(&self) -> Res<bool> {
        Ok(self.0.lock().unwrap_or_else(|p| p.into_inner()).locked)
    }

    fn collections(&self) -> Res<(Vec<SsCollectionInfo>, BTreeMap<String, String>)> {
        let m = self.m()?;
        let cs = m
            .collections
            .iter()
            .map(|c| SsCollectionInfo {
                items: m
                    .items
                    .values()
                    .filter(|i| i.info.collection == c.id)
                    .count() as u32,
                ..c.clone()
            })
            .collect();
        Ok((cs, m.aliases.clone()))
    }

    fn create_collection(&self, label: &str, alias: Option<&str>) -> Res<SsCollectionInfo> {
        pd::validate_label(label).map_err(StoreError::Invalid)?;
        let mut m = self.m()?;
        let t = now();
        let c = SsCollectionInfo {
            id: rand_id("c", 6),
            label: label.into(),
            created: t,
            modified: t,
            items: 0,
        };
        if let Some(a) = alias {
            if !pd::valid_alias(a) {
                return Err(StoreError::Invalid("not a valid alias".into()));
            }
            m.aliases.insert(a.into(), c.id.clone());
        }
        m.collections.push(c.clone());
        Ok(c)
    }

    fn rename_collection(&self, id: &str, label: &str) -> Res<SsCollectionInfo> {
        pd::validate_label(label).map_err(StoreError::Invalid)?;
        let mut m = self.m()?;
        let c = m
            .collections
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(StoreError::NotFound)?;
        c.label = label.into();
        c.modified = now();
        Ok(c.clone())
    }

    fn delete_collection(&self, id: &str) -> Res<u32> {
        if id == pd::LOGIN {
            return Err(StoreError::Invalid(
                "the login collection cannot be deleted".into(),
            ));
        }
        let mut m = self.m()?;
        if !m.collections.iter().any(|c| c.id == id) {
            return Err(StoreError::NotFound);
        }
        let before = m.items.len();
        m.items.retain(|_, i| i.info.collection != id);
        let gone = (before - m.items.len()) as u32;
        m.collections.retain(|c| c.id != id);
        m.aliases.retain(|_, t| t != id);
        Ok(gone)
    }

    fn set_alias(&self, alias: &str, collection: Option<&str>) -> Res<()> {
        let mut m = self.m()?;
        match collection {
            Some(c) if m.collections.iter().any(|x| x.id == c) => {
                m.aliases.insert(alias.into(), c.into());
            }
            Some(_) => return Err(StoreError::NotFound),
            None => {
                m.aliases.remove(alias);
            }
        }
        Ok(())
    }

    fn items(&self, collection: Option<&str>, want: &Attrs) -> Res<Vec<SsItemInfo>> {
        let m = self.m()?;
        let mut v: Vec<_> = m
            .items
            .values()
            .filter(|i| {
                collection.is_none_or(|c| i.info.collection == c)
                    && subset(&i.info.attributes, want)
            })
            .map(|i| i.info.clone())
            .collect();
        v.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        Ok(v)
    }

    fn create_item(
        &self,
        (collection, label, attributes): (&str, &str, &Attrs),
        (content_type, secret): (&str, &[u8]),
        replace: bool,
    ) -> Res<SsItemInfo> {
        pd::validate_label(label).map_err(StoreError::Invalid)?;
        pd::validate_attributes(attributes).map_err(StoreError::Invalid)?;
        pd::validate_content_type(content_type).map_err(StoreError::Invalid)?;
        if secret.len() > pd::MAX_SECRET_BYTES {
            return Err(StoreError::Invalid("the secret is too large".into()));
        }
        let mut m = self.m()?;
        if !m.collections.iter().any(|c| c.id == collection) {
            return Err(StoreError::Invalid(pd::ERR_NO_COLLECTION.into()));
        }
        let t = now();
        let same = m
            .items
            .values()
            .find(|i| {
                replace && i.info.collection == collection && i.info.attributes == *attributes
            })
            .map(|i| (i.info.id.clone(), i.info.created));
        let (id, created) = same.unwrap_or_else(|| (rand_id("", 13).to_uppercase(), t));
        let info = SsItemInfo {
            id: id.clone(),
            collection: collection.into(),
            label: label.into(),
            attributes: attributes.clone(),
            content_type: content_type.into(),
            created,
            modified: t,
        };
        m.items.insert(
            id,
            MemItem {
                info: info.clone(),
                secret: Zeroizing::new(secret.to_vec()),
            },
        );
        Ok(info)
    }

    fn secret(&self, id: &str) -> Res<Secret> {
        let m = self.m()?;
        let i = m.items.get(id).ok_or(StoreError::NotFound)?;
        Ok((i.secret.clone(), i.info.content_type.clone()))
    }

    fn update_item(&self, id: &str, c: Change) -> Res<SsItemInfo> {
        let mut m = self.m()?;
        let i = m.items.get_mut(id).ok_or(StoreError::NotFound)?;
        if let Some(l) = c.label {
            pd::validate_label(&l).map_err(StoreError::Invalid)?;
            i.info.label = l;
        }
        if let Some(a) = c.attributes {
            pd::validate_attributes(&a).map_err(StoreError::Invalid)?;
            i.info.attributes = a;
        }
        if let Some(ct) = c.content_type {
            pd::validate_content_type(&ct).map_err(StoreError::Invalid)?;
            i.info.content_type = ct;
        }
        if let Some(s) = c.secret {
            i.secret = s;
        }
        i.info.modified = now();
        Ok(i.info.clone())
    }

    fn delete_item(&self, id: &str) -> Res<()> {
        self.m()?
            .items
            .remove(id)
            .map(drop)
            .ok_or(StoreError::NotFound)
    }

    /// Everything in a store that never locks.
    fn transient(&self) -> (Vec<SsCollectionInfo>, Vec<SsItemInfo>) {
        let m = self.0.lock().unwrap_or_else(|p| p.into_inner());
        (
            m.collections.clone(),
            m.items.values().map(|i| i.info.clone()).collect(),
        )
    }
}

/// What every `Store` must do. `fresh` makes an empty store whose only
/// collection is `login`.
#[cfg(test)]
pub fn conformance(s: &dyn Store) {
    let a = |p: &[(&str, &str)]| -> Attrs {
        p.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let (cs, aliases) = s.collections().unwrap();
    assert!(cs.iter().any(|c| c.id == pd::LOGIN));
    assert_eq!(aliases["default"], pd::LOGIN);

    let one = s
        .create_item(
            (pd::LOGIN, "One", &a(&[("user", "alice"), ("site", "x")])),
            ("text/plain", b"pw1"),
            false,
        )
        .unwrap();
    let two = s
        .create_item(
            (pd::LOGIN, "Two", &a(&[("user", "bob")])),
            ("text/plain", b"pw2"),
            false,
        )
        .unwrap();
    assert_ne!(one.id, two.id);
    assert_eq!(s.items(None, &Attrs::new()).unwrap().len(), 2);
    assert_eq!(
        s.items(None, &a(&[("user", "alice")])).unwrap()[0].id,
        one.id
    );
    assert!(s.items(None, &a(&[("user", "carol")])).unwrap().is_empty());
    assert_eq!(&s.secret(&one.id).unwrap().0[..], b"pw1");

    // replace: same attributes → same item; other attributes → new item.
    let r = s
        .create_item(
            (
                pd::LOGIN,
                "One again",
                &a(&[("user", "alice"), ("site", "x")]),
            ),
            ("text/plain", b"pw1b"),
            true,
        )
        .unwrap();
    assert_eq!(r.id, one.id);
    assert_eq!(&s.secret(&one.id).unwrap().0[..], b"pw1b");
    assert_eq!(s.items(None, &Attrs::new()).unwrap().len(), 2);

    let up = s
        .update_item(
            &one.id,
            Change {
                label: Some("Renamed".into()),
                secret: Some(Zeroizing::new(b"pw1c".to_vec())),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(up.label, "Renamed");
    assert_eq!(&s.secret(&one.id).unwrap().0[..], b"pw1c");
    assert_eq!(up.attributes, a(&[("user", "alice"), ("site", "x")]));
    assert_eq!(
        s.update_item("NOPE", Change::default()).unwrap_err(),
        StoreError::NotFound
    );

    // Binary secrets are bytes, not text.
    let bin: Vec<u8> = (0..=255).collect();
    let b = s
        .create_item(
            (pd::LOGIN, "Bin", &a(&[("k", "bin")])),
            ("application/octet-stream", &bin),
            false,
        )
        .unwrap();
    assert_eq!(&s.secret(&b.id).unwrap().0[..], &bin[..]);

    // Collections.
    let w = s.create_collection("Work", Some("work")).unwrap();
    s.create_item((&w.id, "W", &a(&[("k", "w")])), ("text/plain", b"w"), false)
        .unwrap();
    assert_eq!(s.items(Some(&w.id), &Attrs::new()).unwrap().len(), 1);
    assert_eq!(s.collections().unwrap().1["work"], w.id);
    assert_eq!(
        s.rename_collection(&w.id, "Work 2").unwrap().label,
        "Work 2"
    );
    assert!(s
        .create_item(("nosuch", "x", &Attrs::new()), ("text/plain", b"x"), false)
        .is_err());
    assert_eq!(s.delete_collection(&w.id).unwrap(), 1);
    assert!(!s.collections().unwrap().1.contains_key("work"));

    s.delete_item(&two.id).unwrap();
    assert_eq!(s.delete_item(&two.id).unwrap_err(), StoreError::NotFound);
    assert_eq!(s.secret(&two.id).unwrap_err(), StoreError::NotFound);
    assert!(s
        .create_item(
            (pd::LOGIN, &"x".repeat(300), &Attrs::new()),
            ("text/plain", b"x"),
            false
        )
        .is_err());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_in_memory_store_conforms() {
        conformance(&MemStore::new(&[pd::LOGIN]));
    }

    #[test]
    fn a_locked_memory_store_refuses_everything_but_the_question() {
        let s = MemStore::new(&[pd::LOGIN]);
        let it = s
            .create_item((pd::LOGIN, "L", &Attrs::new()), ("text/plain", b"x"), false)
            .unwrap();
        s.set_locked(true);
        assert_eq!(s.locked(), Ok(true));
        assert_eq!(s.secret(&it.id).unwrap_err(), StoreError::Locked);
        assert_eq!(
            s.items(None, &Attrs::new()).unwrap_err(),
            StoreError::Locked
        );
        assert_eq!(StoreError::Locked.to_string(), pd::ERR_LOCKED);
        s.set_locked(false);
        assert_eq!(&s.secret(&it.id).unwrap().0[..], b"x");
    }
}
