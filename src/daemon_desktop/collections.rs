// daemon_desktop/collections.rs — collections and aliases. A collection is
// only a label items refer to by id; the registry (one small encrypted
// credential, `SSCOLLECTIONS`) lists them and the aliases. `login` always
// exists and cannot be deleted; `default` points at it until changed.

use std::collections::BTreeMap;

use kepr_core::generate::ZeroString;
use kepr_core::protocol_desktop::{self as pd, DesktopResponse as R, SsCollectionInfo};
use serde::{Deserialize, Serialize};

use super::doc::{self, Failure};
use super::items;
use crate::expiry::now_unix;
use crate::store::cred_exists;

const REGISTRY: &str = "SSCOLLECTIONS";

#[derive(Serialize, Deserialize, Clone)]
struct Coll {
    id: String,
    label: String,
    created: u64,
    modified: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct Registry {
    #[serde(default)]
    v: u8,
    #[serde(default)]
    collections: Vec<Coll>,
    #[serde(default)]
    aliases: BTreeMap<String, String>,
}

impl Registry {
    /// The registry with `login` and `default` filled in.
    fn complete(mut self) -> Self {
        if !self.collections.iter().any(|c| c.id == pd::LOGIN) {
            let now = now_unix();
            self.collections.insert(
                0,
                Coll {
                    id: pd::LOGIN.into(),
                    label: "Login".into(),
                    created: now,
                    modified: now,
                },
            );
        }
        self.aliases
            .entry("default".into())
            .or_insert_with(|| pd::LOGIN.into());
        self.v = 1;
        self
    }

    fn has(&self, id: &str) -> bool {
        self.collections.iter().any(|c| c.id == id)
    }
}

fn load(uid: u32) -> Result<Registry, Failure> {
    if doc::locked() {
        return Err(Failure::Locked);
    }
    if !cred_exists(uid, REGISTRY) {
        return Ok(Registry::default().complete());
    }
    let text = doc::read(uid, REGISTRY)?;
    let reg: Registry = serde_json::from_str(text.as_str())
        .map_err(|_| Failure::Other("the collection list is damaged".into()))?;
    Ok(reg.complete())
}

fn save(uid: u32, reg: &Registry) -> Result<(), Failure> {
    let json = serde_json::to_string(reg).map_err(|_| Failure::Other("cannot encode".into()))?;
    doc::write(uid, REGISTRY, &ZeroString::from_string(json))
}

/// Ok if `id` is a collection.
pub fn require(uid: u32, id: &str) -> Result<(), Failure> {
    if !pd::valid_collection_id(id) {
        return Err(Failure::Invalid(pd::ERR_NO_COLLECTION.into()));
    }
    if id == pd::LOGIN || load(uid)?.has(id) {
        Ok(())
    } else {
        Err(Failure::Invalid(pd::ERR_NO_COLLECTION.into()))
    }
}

fn info(c: &Coll, uid: u32) -> SsCollectionInfo {
    SsCollectionInfo {
        id: c.id.clone(),
        label: c.label.clone(),
        created: c.created,
        modified: c.modified,
        items: items::count_in(uid, &c.id) as u32,
    }
}

pub fn list(uid: u32) -> Result<R, Failure> {
    let reg = load(uid)?;
    let collections = reg.collections.iter().map(|c| info(c, uid)).collect();
    Ok(R::SsCollections {
        collections,
        aliases: reg.aliases,
    })
}

fn new_id() -> Result<String, Failure> {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b).map_err(|e| Failure::Other(format!("CSPRNG failure: {e}")))?;
    Ok(format!("c{}", hex::encode(b)))
}

pub fn create(uid: u32, username: &str, label: &str, alias: Option<&str>) -> Result<R, Failure> {
    let _lock = crate::daemon_credlock::lock(uid, REGISTRY);
    let r = (|| -> Result<Coll, Failure> {
        pd::validate_label(label).map_err(Failure::Invalid)?;
        if let Some(a) = alias {
            if !pd::valid_alias(a) {
                return Err(Failure::Invalid("not a valid alias".into()));
            }
        }
        let mut reg = load(uid)?;
        if reg.collections.len() >= pd::MAX_COLLECTIONS {
            return Err(Failure::Invalid("too many collections".into()));
        }
        let now = now_unix();
        let c = Coll {
            id: new_id()?,
            label: label.to_string(),
            created: now,
            modified: now,
        };
        if let Some(a) = alias {
            reg.aliases.insert(a.to_string(), c.id.clone());
        }
        reg.collections.push(c.clone());
        save(uid, &reg)?;
        Ok(c)
    })();
    items::audit_op("ss-collection", Some(REGISTRY), uid, username, &r);
    r.map(|c| R::SsCollection {
        collection: Box::new(info(&c, uid)),
    })
}

pub fn rename(uid: u32, username: &str, id: &str, label: &str) -> Result<R, Failure> {
    let _lock = crate::daemon_credlock::lock(uid, REGISTRY);
    let r = (|| -> Result<Coll, Failure> {
        pd::validate_label(label).map_err(Failure::Invalid)?;
        let mut reg = load(uid)?;
        let c = reg
            .collections
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or_else(|| Failure::Invalid(pd::ERR_NO_COLLECTION.into()))?;
        c.label = label.to_string();
        c.modified = now_unix();
        let c = c.clone();
        save(uid, &reg)?;
        Ok(c)
    })();
    items::audit_op("ss-collection", Some(REGISTRY), uid, username, &r);
    r.map(|c| R::SsCollection {
        collection: Box::new(info(&c, uid)),
    })
}

pub fn delete(uid: u32, username: &str, id: &str) -> Result<R, Failure> {
    let _lock = crate::daemon_credlock::lock(uid, REGISTRY);
    let r = (|| -> Result<u32, Failure> {
        if id == pd::LOGIN {
            return Err(Failure::Invalid(
                "the login collection cannot be deleted".into(),
            ));
        }
        let mut reg = load(uid)?;
        if !reg.has(id) {
            return Err(Failure::Invalid(pd::ERR_NO_COLLECTION.into()));
        }
        let gone = items::delete_in(uid, username, id)?;
        reg.collections.retain(|c| c.id != id);
        reg.aliases.retain(|_, target| target != id);
        save(uid, &reg.complete())?;
        Ok(gone)
    })();
    items::audit_op("ss-collection", Some(REGISTRY), uid, username, &r);
    r.map(|items| R::SsDeleted {
        id: id.to_string(),
        items,
    })
}

pub fn set_alias(
    uid: u32,
    username: &str,
    alias: &str,
    target: Option<&str>,
) -> Result<R, Failure> {
    let _lock = crate::daemon_credlock::lock(uid, REGISTRY);
    let r = (|| -> Result<(), Failure> {
        if !pd::valid_alias(alias) {
            return Err(Failure::Invalid("not a valid alias".into()));
        }
        let mut reg = load(uid)?;
        match target {
            Some(t) if reg.has(t) => {
                reg.aliases.insert(alias.to_string(), t.to_string());
            }
            Some(_) => return Err(Failure::Invalid(pd::ERR_NO_COLLECTION.into())),
            // `default` always points somewhere.
            None => {
                reg.aliases.remove(alias);
            }
        }
        save(uid, &reg.complete())
    })();
    items::audit_op("ss-collection", Some(REGISTRY), uid, username, &r);
    r.map(|()| R::SsAliasOk)
}
