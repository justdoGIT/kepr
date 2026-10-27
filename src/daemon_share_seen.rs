// daemon_share_seen.rs — single-use shares (P6.2): the ids of shares this
// user already received, kept until each share's own expiry, so the same
// envelope can't be imported twice. One small JSON file per uid in the
// daemon's state directory; entries prune themselves once expired.

use std::collections::HashMap;
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

fn path(uid: u32) -> std::path::PathBuf {
    crate::daemon_sharing::state_path("share-seen", uid)
}

fn load(p: &std::path::Path) -> HashMap<String, u64> {
    std::fs::read(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save(p: &std::path::Path, seen: &HashMap<String, u64>) -> Result<(), String> {
    crate::daemon_sharing::save(p, seen).map_err(|e| format!("cannot record the share: {e}"))
}

/// Forget `id` again: the share was claimed but storing it failed.
pub fn release(uid: u32, id: &str) {
    let Ok(_g) = LOCK.lock() else { return };
    let p = path(uid);
    let mut seen = load(&p);
    if seen.remove(id).is_some() {
        let _ = save(&p, &seen);
    }
}

/// Record `id` (valid until `expires`) as received, or refuse a repeat.
pub fn claim(uid: u32, id: &str, expires: u64) -> Result<(), String> {
    let _g = LOCK.lock().map_err(|_| "share state lock poisoned")?;
    let p = path(uid);
    let mut seen = load(&p);
    let now = crate::expiry::now_unix();
    seen.retain(|_, exp| *exp > now);
    if seen.contains_key(id) {
        return Err("this share was already received (shares are single-use)".into());
    }
    seen.insert(id.to_string(), expires);
    save(&p, &seen)
}
