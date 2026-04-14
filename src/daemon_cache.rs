// daemon_cache.rs — per-uid in-memory cache of the credstore directory scan.
//
// The daemon owns *all* writes to the credstore, so cache invalidation is
// trivial: invalidate on handle_set and handle_delete. Readers that hit the
// cache skip the full `read_dir` of `/etc/credstore.encrypted/` (which
// scales with the number of credentials across ALL users on the host).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

use crate::store;

type CacheMap = HashMap<u32, Vec<(String, PathBuf)>>;

static CACHE: OnceLock<RwLock<CacheMap>> = OnceLock::new();

fn cache() -> &'static RwLock<CacheMap> {
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn list_for_uid(uid: u32) -> Vec<(String, PathBuf)> {
    // Fast path — shared read.
    if let Some(v) = cache().read().unwrap().get(&uid) {
        return v.clone();
    }
    // Miss — scan and populate. Double-check under the write lock in case
    // another thread populated between our read drop and write acquire.
    let fresh = store::list_for_uid(uid);
    let mut w = cache().write().unwrap();
    w.entry(uid).or_insert_with(|| fresh.clone());
    fresh
}

pub fn invalidate(uid: u32) {
    cache().write().unwrap().remove(&uid);
}
