// daemon_vault/sweep.rs — TTL expiry for credentials in the image (T4.06).
//
// The per-file sweeper (daemon_expiry.rs) walks `.meta` files; with the
// image there are none, so the same tick calls this instead. Same steps
// as `handle_delete`, audited as `expire`: re-check under the
// credential's lock, crypto-shred the record (meta included) and its
// history, tell running gates, drop the list cache.

use crate::audit::{self, username_for_uid, AuditEvent, AuditResult};
use crate::crypto::Backend;
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
