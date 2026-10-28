// cli_desktop/ss/view.rs — the server's view of the store.
//
// `Routed` adds the transient `session` collection (memory only, gone when
// the server exits) in front of the real store. `View` caches the
// non-secret part, labels, attributes and times (what the Secret Service
// calls the item's properties and expects to read without unlocking). While
// kepr is locked, searches and property reads answer from that cache and
// only secrets are refused, which is what lets a client discover the item,
// ask to unlock it and carry on. The cache is replaced from the store
// whenever it is unlocked and older than FRESH; it never holds a secret.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kepr_core::protocol_desktop::{SsCollectionInfo, SsItemInfo};

use super::store::{Attrs, Change, MemStore, Res, Secret, Store, StoreError};

pub const SESSION: &str = "session";
const FRESH: Duration = Duration::from_millis(500);

pub struct Routed {
    main: Arc<dyn Store>,
    mem: MemStore,
}

impl Routed {
    pub fn new(main: Arc<dyn Store>) -> Routed {
        Routed {
            main,
            mem: MemStore::new(&[SESSION]),
        }
    }
}

impl Store for Routed {
    fn locked(&self) -> Res<bool> {
        self.main.locked()
    }

    fn collections(&self) -> Res<(Vec<SsCollectionInfo>, BTreeMap<String, String>)> {
        let (mut cs, mut aliases) = self.main.collections()?;
        if let Ok((mem, _)) = self.mem.collections() {
            cs.extend(mem);
        }
        aliases.insert(SESSION.into(), SESSION.into());
        Ok((cs, aliases))
    }

    fn create_collection(&self, label: &str, alias: Option<&str>) -> Res<SsCollectionInfo> {
        if alias == Some(SESSION) {
            return Err(StoreError::Invalid("the session alias is fixed".into()));
        }
        self.main.create_collection(label, alias)
    }

    fn rename_collection(&self, id: &str, label: &str) -> Res<SsCollectionInfo> {
        if id == SESSION {
            return Err(StoreError::Invalid(
                "the session collection cannot be changed".into(),
            ));
        }
        self.main.rename_collection(id, label)
    }

    fn delete_collection(&self, id: &str) -> Res<u32> {
        if id == SESSION {
            return Err(StoreError::Invalid(
                "the session collection cannot be deleted".into(),
            ));
        }
        self.main.delete_collection(id)
    }

    fn set_alias(&self, alias: &str, collection: Option<&str>) -> Res<()> {
        if alias == SESSION || collection == Some(SESSION) {
            return Err(StoreError::Invalid("the session alias is fixed".into()));
        }
        self.main.set_alias(alias, collection)
    }

    fn items(&self, collection: Option<&str>, want: &Attrs) -> Res<Vec<SsItemInfo>> {
        match collection {
            Some(SESSION) => self.mem.items(Some(SESSION), want),
            Some(c) => self.main.items(Some(c), want),
            None => {
                let mut v = self.main.items(None, want)?;
                v.extend(self.mem.items(None, want)?);
                Ok(v)
            }
        }
    }

    fn create_item(
        &self,
        place: (&str, &str, &Attrs),
        value: (&str, &[u8]),
        replace: bool,
    ) -> Res<SsItemInfo> {
        if place.0 == SESSION {
            self.mem.create_item(place, value, replace)
        } else {
            self.main.create_item(place, value, replace)
        }
    }

    fn secret(&self, id: &str) -> Res<Secret> {
        match self.mem.secret(id) {
            Err(StoreError::NotFound) => self.main.secret(id),
            r => r,
        }
    }

    fn update_item(&self, id: &str, c: Change) -> Res<SsItemInfo> {
        // `Change` is not Clone (it may hold a secret): decide by id first.
        if self.mem.secret(id).is_ok() {
            self.mem.update_item(id, c)
        } else {
            self.main.update_item(id, c)
        }
    }

    fn delete_item(&self, id: &str) -> Res<()> {
        match self.mem.delete_item(id) {
            Err(StoreError::NotFound) => self.main.delete_item(id),
            r => r,
        }
    }

    fn transient(&self) -> (Vec<SsCollectionInfo>, Vec<SsItemInfo>) {
        self.mem.transient()
    }
}

#[derive(Default)]
struct Cache {
    items: BTreeMap<String, SsItemInfo>,
    colls: Vec<SsCollectionInfo>,
    aliases: BTreeMap<String, String>,
    loaded: Option<Instant>,
    locked: bool,
    reported: Option<bool>,
    /// The cache has held the real store's contents at least once.
    warm: bool,
    /// The last "cannot ask kepr" message shown, so a daemon that stays
    /// away is reported once, not every second.
    unreachable: Option<String>,
}

pub struct View {
    store: Arc<dyn Store>,
    c: Mutex<Cache>,
}

impl View {
    pub fn new(store: Arc<dyn Store>) -> View {
        View {
            store,
            c: Mutex::new(Cache::default()),
        }
    }

    pub fn store(&self) -> &dyn Store {
        self.store.as_ref()
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.c.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Bring the cache up to date if kepr is unlocked and it is stale;
    /// whether kepr is locked.
    pub fn sync(&self) -> bool {
        let mut c = self.cache();
        if c.loaded.is_some_and(|t| t.elapsed() < FRESH) {
            return c.locked;
        }
        match self.store.locked() {
            Ok(false) => {}
            _ => {
                // Locked: what was cached stays, and what never locks is
                // refreshed.
                c.locked = true;
                c.loaded = Some(Instant::now());
                let (colls, items) = self.store.transient();
                let ids: Vec<String> = colls.iter().map(|x| x.id.clone()).collect();
                c.items.retain(|_, i| !ids.contains(&i.collection));
                c.colls.retain(|x| !ids.contains(&x.id));
                for id in &ids {
                    c.aliases.insert(id.clone(), id.clone());
                }
                c.items.extend(items.into_iter().map(|i| (i.id.clone(), i)));
                c.colls.extend(colls);
                return true;
            }
        }
        c.locked = false;
        match (
            self.store.items(None, &Attrs::new()),
            self.store.collections(),
        ) {
            (Ok(items), Ok((colls, aliases))) => {
                c.items = items.into_iter().map(|i| (i.id.clone(), i)).collect();
                c.colls = colls;
                c.aliases = aliases;
                c.loaded = Some(Instant::now());
                c.warm = true;
            }
            (Err(StoreError::Locked), _) | (_, Err(StoreError::Locked)) => c.locked = true,
            _ => {} // keep what we had
        }
        c.locked
    }

    pub fn locked(&self) -> bool {
        self.sync()
    }

    /// Locked, and the real store's contents have never been seen: there
    /// is nothing honest to answer with until it is unlocked.
    pub fn cold(&self) -> bool {
        let locked = self.sync();
        locked && !self.cache().warm
    }

    /// `Some(now locked)` the first time the state differs from the last
    /// time this returned.
    pub fn lock_change(&self) -> Option<bool> {
        let asked = self.store.locked();
        let mut c = self.cache();
        let locked = match asked {
            Ok(l) => {
                c.unreachable = None;
                l
            }
            Err(e) => {
                // Treated as locked: nothing is revealed while kepr can't be asked.
                let text = e.to_string();
                if c.unreachable.as_deref() != Some(text.as_str()) {
                    eprintln!("kepr secret-service: cannot ask kepr: {text}; answering as locked");
                    c.unreachable = Some(text);
                }
                true
            }
        };
        let changed = c.reported != Some(locked);
        c.reported = Some(locked);
        if changed {
            c.loaded = None; // reload on the next question
        }
        changed.then_some(locked)
    }

    pub fn items(&self, collection: Option<&str>, want: &Attrs) -> Vec<SsItemInfo> {
        self.sync();
        self.cache()
            .items
            .values()
            .filter(|i| {
                collection.is_none_or(|c| i.collection == c)
                    && want.iter().all(|(k, v)| i.attributes.get(k) == Some(v))
            })
            .cloned()
            .collect()
    }

    pub fn item(&self, id: &str) -> Option<SsItemInfo> {
        if let Some(i) = self.cache().items.get(id) {
            return Some(i.clone());
        }
        // Unknown: it may be new. Look once more, past the freshness window.
        self.cache().loaded = None;
        self.sync();
        self.cache().items.get(id).cloned()
    }

    pub fn collections(&self) -> (Vec<SsCollectionInfo>, BTreeMap<String, String>) {
        self.sync();
        let c = self.cache();
        (c.colls.clone(), c.aliases.clone())
    }

    pub fn collection(&self, id: &str) -> Option<SsCollectionInfo> {
        self.collections().0.into_iter().find(|c| c.id == id)
    }

    /// An alias's collection id (an id itself resolves to itself).
    pub fn resolve(&self, name: &str) -> Option<String> {
        let (cs, aliases) = self.collections();
        aliases
            .get(name)
            .cloned()
            .or_else(|| cs.iter().any(|c| c.id == name).then(|| name.to_string()))
    }

    /// After a change through the store: reload next time.
    pub fn stale(&self) {
        self.cache().loaded = None;
    }

    pub fn forget_items(&self) {
        let mut c = self.cache();
        c.items.clear();
        c.loaded = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::protocol_desktop as pd;

    fn setup() -> (Arc<MemStore>, View) {
        let mem = Arc::new(MemStore::new(&[pd::LOGIN]));
        (Arc::clone(&mem), View::new(Arc::new(Routed::new(mem))))
    }

    fn attrs(k: &str, v: &str) -> Attrs {
        BTreeMap::from([(k.to_string(), v.to_string())])
    }

    #[test]
    fn the_session_collection_lives_in_memory_beside_the_real_one() {
        let (_, v) = setup();
        let s = v.store();
        let (cs, aliases) = s.collections().unwrap();
        assert!(cs.iter().any(|c| c.id == SESSION) && cs.iter().any(|c| c.id == pd::LOGIN));
        assert_eq!(aliases[SESSION], SESSION);
        let a = s
            .create_item(
                (SESSION, "temp", &attrs("k", "v")),
                ("text/plain", b"t"),
                false,
            )
            .unwrap();
        let b = s
            .create_item(
                (pd::LOGIN, "kept", &attrs("k", "v")),
                ("text/plain", b"k"),
                false,
            )
            .unwrap();
        assert_eq!(s.items(None, &attrs("k", "v")).unwrap().len(), 2);
        assert_eq!(s.items(Some(SESSION), &Attrs::new()).unwrap().len(), 1);
        assert_eq!(&s.secret(&a.id).unwrap().0[..], b"t");
        assert_eq!(&s.secret(&b.id).unwrap().0[..], b"k");
        s.update_item(
            &a.id,
            Change {
                label: Some("temp2".into()),
                ..Default::default()
            },
        )
        .unwrap();
        s.update_item(
            &b.id,
            Change {
                label: Some("kept2".into()),
                ..Default::default()
            },
        )
        .unwrap();
        s.delete_item(&a.id).unwrap();
        assert_eq!(s.delete_item(&a.id).unwrap_err(), StoreError::NotFound);
        assert!(
            s.rename_collection(SESSION, "x").is_err() && s.delete_collection(SESSION).is_err()
        );
        assert!(s.set_alias("a", Some(SESSION)).is_err());
        assert_eq!(s.items(None, &Attrs::new()).unwrap()[0].label, "kept2");
    }

    #[test]
    fn a_locked_store_still_answers_searches_from_the_cache_but_not_secrets() {
        let (mem, v) = setup();
        let it = v
            .store()
            .create_item(
                (pd::LOGIN, "Mail", &attrs("user", "alice")),
                ("text/plain", b"pw"),
                false,
            )
            .unwrap();
        v.stale();
        assert!(!v.locked());
        assert_eq!(v.items(None, &attrs("user", "alice"))[0].label, "Mail");
        mem.set_locked(true);
        v.stale();
        assert!(v.locked());
        // Metadata from the cache; the secret is refused.
        assert_eq!(v.items(None, &attrs("user", "alice"))[0].id, it.id);
        assert_eq!(v.item(&it.id).unwrap().label, "Mail");
        assert_eq!(v.store().secret(&it.id).unwrap_err(), StoreError::Locked);
        assert!(
            v.collections().0.iter().any(|c| c.id == pd::LOGIN),
            "collections too"
        );
        mem.set_locked(false);
        v.stale();
        assert!(!v.locked());
    }

    #[test]
    fn lock_changes_are_reported_once() {
        let (mem, v) = setup();
        assert_eq!(v.lock_change(), Some(false), "first look");
        assert_eq!(v.lock_change(), None);
        mem.set_locked(true);
        assert_eq!(v.lock_change(), Some(true));
        assert_eq!(v.lock_change(), None);
        mem.set_locked(false);
        assert_eq!(v.lock_change(), Some(false));
    }

    #[test]
    fn new_items_are_seen_and_resolution_follows_aliases() {
        let (_, v) = setup();
        assert!(v.items(None, &Attrs::new()).is_empty());
        let it = v
            .store()
            .create_item((pd::LOGIN, "x", &Attrs::new()), ("text/plain", b"x"), false)
            .unwrap();
        // Not yet in the cache, but a lookup by id looks again.
        assert_eq!(v.item(&it.id).unwrap().id, it.id);
        assert_eq!(v.resolve("default").as_deref(), Some(pd::LOGIN));
        assert_eq!(v.resolve(pd::LOGIN).as_deref(), Some(pd::LOGIN));
        assert_eq!(v.resolve("nope"), None);
        assert!(v.collection(SESSION).is_some());
        assert!(v.item("MISSING").is_none());
    }
}
