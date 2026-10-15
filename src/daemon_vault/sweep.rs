// daemon_vault/sweep.rs — TTL expiry for credentials in the image (T4.06).
//
// The per-file sweeper (daemon_expiry.rs) walks `.meta` files; with the
// image there are none, so the same tick calls this instead. Same steps
// as `handle_delete`, audited as `expire`: re-check under the
// credential's lock, crypto-shred the record (meta included) and its
// history, tell running gates, drop the list cache.

use super::backend::ImageBackend;
use crate::audit::{self, username_for_uid, AuditEvent, AuditResult};
use crate::crypto::Backend;
use crate::expiry::CredMeta;
use crate::{daemon_cache, expiry, store};

/// Expire everything due at `now`. Returns how many were removed.
pub fn sweep_expired(now: u64) -> usize {
    let Some(b) = super::active() else {
        return 0;
    };
    let mut removed = 0;
    for (uid, name) in b.expired(now) {
        let _lock = crate::daemon_credlock::lock(uid, &name);
        let meta = expiry::read_meta(&expiry::meta_path_for(&store::cred_path(uid, &name)));
        if !matches!(meta, Some(Ok(m)) if m.expires_at_unix.is_some_and(|t| t <= now)) {
            continue;
        }
        let r = b.delete(uid, &name);
        crate::daemon_history::purge(uid, &name);
        crate::daemon_gate::bump_generation();
        daemon_cache::invalidate(uid);
        let username = username_for_uid(uid);
        audit::log(&AuditEvent {
            op: "expire",
            name: Some(&name),
            uid,
            username: &username,
            result: match &r {
                Ok(()) => AuditResult::Ok,
                Err(e) => AuditResult::Fail(e.clone()),
            },
        });
        removed += usize::from(r.is_ok());
    }
    removed
}

impl ImageBackend {
    /// Every credential whose `.meta` expiry is at or before `now`, as
    /// (uid, NAME). Reads each record's meta; values stay in the image.
    pub fn expired(&self, now: u64) -> Vec<(u32, String)> {
        let due = self.with_index(|img, keys, ix| {
            let mut out = Vec::new();
            for (k, _) in ix.entries.iter().filter(|(_, e)| e.has_value) {
                let Ok(Some(rec)) = img.read_record(keys, ix, k) else {
                    continue;
                };
                let meta: Option<CredMeta> = rec.meta.and_then(|m| serde_json::from_slice(&m).ok());
                if meta
                    .and_then(|m| m.expires_at_unix)
                    .is_some_and(|t| t <= now)
                {
                    out.extend(store::from_cred_name(k));
                }
            }
            Ok(out)
        });
        due.ok().flatten().unwrap_or_default()
    }
}
