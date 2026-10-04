// daemon_share_seen.rs — single-use shares (P6.2): the ids of shares this
// user already received, kept until each share's own expiry, so the same
// envelope can't be imported twice. One small JSON file per uid in the
// daemon's state directory; entries prune themselves once expired.

use std::collections::HashMap;
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

fn path(uid: u32) -> std::path::PathBuf {
    crate::state_dir().join(format!("share-seen-{uid}.json"))
}

/// Record `id` (valid until `expires`) as received, or refuse a repeat.
pub fn claim(uid: u32, id: &str, expires: u64) -> Result<(), String> {
    let _g = LOCK.lock().map_err(|_| "share state lock poisoned")?;
    let p = path(uid);
    let mut seen: HashMap<String, u64> = std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let now = crate::expiry::now_unix();
    seen.retain(|_, exp| *exp > now);
    if seen.contains_key(id) {
        return Err("this share was already received (shares are single-use)".into());
    }
    seen.insert(id.to_string(), expires);
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(&seen).map_err(|e| e.to_string())?)
        .and_then(|_| std::fs::rename(&tmp, &p))
        .map_err(|e| format!("cannot record the share: {e}"))
}
