// daemon_store/trash.rs — T11.2: `kepr rm` moves a credential to the trash
// for KEPR_TRASH_DAYS days (default 30; 0 = off, rm deletes at once).
//
// A trash entry is the value re-encrypted as `NAME~t<unix>` (`~` fails
// validate_name: no request can name it and listings never show it), with
// the credential's whole `.meta` plus `trashed_at`, so a sealed credential
// stays sealed to the same bindings while in the trash and after restore.
// Its history slots (`NAME~t<unix>~N`) and attachment chunks (T5.03) move
// along. The expiry sweeper calls `sweep` to purge old entries.
// `rm --force` (DeleteNow) and the leak response skip the trash.

use kepr_core::protocol::Response;
use kepr_core::protocol_store::{StoreResponse, TrashItem};

use super::files;
use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_handlers::handle_delete;
use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};
use crate::{crypto, daemon_cache};

const DEFAULT_DAYS: u64 = 30;
const DAY: u64 = 86_400;

/// KEPR_TRASH_DAYS from the daemon's environment.
pub fn days() -> u64 {
    std::env::var("KEPR_TRASH_DAYS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_DAYS)
}

/// `(name, trash entry)` for each of `uid`'s trash entries, oldest first.
fn entries(uid: u32) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = files::all_of(uid)
        .into_iter()
        .filter_map(|(n, _)| {
            let (name, rest) = n.split_once("~t")?;
            (!rest.contains('~')).then(|| (name.to_string(), n.clone()))
        })
        .collect();
    out.sort_by_key(|(_, e)| stamp(e));
    out
}

fn stamp(entry: &str) -> u64 {
    entry
        .rsplit_once("~t")
        .and_then(|(_, t)| t.parse().ok())
        .unwrap_or(0)
}

fn entry_meta(uid: u32, entry: &str) -> Result<CredMeta, String> {
    expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, entry)))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn log(op: &str, uid: u32, username: &str, name: Option<&str>, r: &Result<(), String>) {
    audit::log(&AuditEvent {
        op,
        name,
        uid,
        username,
        result: match r {
            Ok(()) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}

/// `Request::Delete`: into the trash, or deleted at once when the trash
/// is off or the value can't be kept (missing, unreadable).
pub fn handle_rm(uid: u32, username: &str, name: &str) -> Response {
    if let Some(r) = super::alias::remove_if_alias(uid, username, name) {
        return r;
    }
    rm(uid, username, name, days())
}

fn rm(uid: u32, username: &str, name: &str, days: u64) -> Response {
    if days == 0 || validate_name(name).is_err() {
        return handle_delete(uid, username, name);
    }
    let upper = name.to_uppercase();
    let _lock = crate::daemon_credlock::lock(uid, &upper);
    match move_to_trash(uid, &upper, expiry::now_unix()) {
        Ok(Some(_)) => {
            daemon_cache::invalidate(uid);
            crate::daemon_gate::bump_generation();
            log("trash", uid, username, Some(&upper), &Ok(()));
            Response::DeleteOk { name: upper }
        }
        Ok(None) => handle_delete(uid, username, &upper),
        Err(e) => {
            log("trash", uid, username, Some(&upper), &Err(e.clone()));
            Response::fail(e)
        }
    }
}

/// Move `upper` (locked by the caller) to the trash. `Ok(None)`: nothing
/// worth keeping, delete it outright instead.
pub fn move_to_trash(uid: u32, upper: &str, now: u64) -> Result<Option<String>, String> {
    let path = cred_path(uid, upper);
    let meta = match expiry::read_meta(&expiry::meta_path_for(&path)) {
        None => CredMeta::default(),
        Some(Ok(m)) => m,
        // Never copy a policy this daemon can't read.
        Some(Err(_)) => return Ok(None),
    };
    if !path.exists() {
        return Ok(None);
    }
    if crypto::backend_is_locked() {
        return Err("the credential store is locked; unlock it first \
                    (or `kepr rm NAME --force` to delete without the trash)"
            .into());
    }
    let Ok(value) = crypto::default_backend().decrypt(uid, upper) else {
        return Ok(None);
    };
    let mut ts = now;
    while cred_path(uid, &format!("{upper}~t{ts}")).exists() {
        ts += 1;
    }
    let entry = format!("{upper}~t{ts}");
    let entry_meta_path = expiry::meta_path_for(&cred_path(uid, &entry));
    let mut tmeta = meta;
    tmeta.trashed_at = Some(now);
    expiry::write_meta(&entry_meta_path, &tmeta)?;
    let stored = crypto::default_backend()
        .encrypt(uid, &entry, value.as_bytes())
        .and_then(|()| crypto::default_backend().delete(uid, upper));
    if let Err(e) = stored {
        purge_entry(uid, &entry);
        return Err(e);
    }
    expiry::delete_meta(&expiry::meta_path_for(&path));
    files::move_history(uid, upper, &entry);
    crate::daemon_recordsx::move_attachments(uid, upper, &entry); // T5.03
    crate::daemon_history::purge(uid, upper);
    Ok(Some(entry))
}

/// Delete one trash entry: value, meta and its history slots.
fn purge_entry(uid: u32, entry: &str) {
    let _ = crypto::default_backend().delete(uid, entry);
    expiry::delete_meta(&expiry::meta_path_for(&cred_path(uid, entry)));
    crate::daemon_history::purge(uid, entry);
}

pub fn handle_list(uid: u32, username: &str) -> Response {
    let days = days();
    let items = entries(uid)
        .into_iter()
        .map(|(name, entry)| {
            let meta = entry_meta(uid, &entry).unwrap_or_default();
            let at = meta.trashed_at.unwrap_or_else(|| stamp(&entry));
            TrashItem {
                name,
                trashed_at: expiry::format_expires_at(at),
                purge_at: expiry::format_expires_at(at.saturating_add(days * DAY)),
                size: crate::store::file_size(&cred_path(uid, &entry)),
                sealed: meta.sealed.filter(|s| *s),
                record_type: meta.record_type,
            }
        })
        .collect();
    log("trash-list", uid, username, None, &Ok(()));
    Response::Store(StoreResponse::TrashListOk { items })
}

pub fn handle_restore(uid: u32, username: &str, name: &str) -> Response {
    let upper = name.to_uppercase();
    let _lock = crate::daemon_credlock::lock(uid, &upper);
    let r = restore(uid, &upper);
    log("trash-restore", uid, username, Some(&upper), &r);
    match r {
        Ok(()) => {
            daemon_cache::invalidate(uid);
            crate::daemon_gate::bump_generation();
            Response::Store(StoreResponse::TrashRestoreOk { name: upper })
        }
        Err(e) => Response::fail(e),
    }
}

fn restore(uid: u32, upper: &str) -> Result<(), String> {
    validate_name(upper)?;
    let path = cred_path(uid, upper);
    if path.exists() || super::alias::target_of(uid, upper).is_some() {
        return Err(format!(
            "{upper} exists again; rename or delete it before restoring"
        ));
    }
    let (_, entry) = entries(uid)
        .into_iter()
        .rfind(|(n, _)| n == upper)
        .ok_or_else(|| format!("{upper} is not in the trash"))?;
    let mut meta = entry_meta(uid, &entry).map_err(|_| "trash entry metadata unreadable")?;
    meta.trashed_at = None;
    let value = crypto::default_backend()
        .decrypt(uid, &entry)
        .map_err(|e| crypto::sanitize_lookup_error(&e))?;
    // Policy first, as `set` does for sealed values: the value must never
    // be readable without its seal, even for an instant.
    let mp = expiry::meta_path_for(&path);
    if meta.is_empty() {
        expiry::delete_meta(&mp);
    } else {
        expiry::write_meta(&mp, &meta)?;
    }
    if let Err(e) = crypto::default_backend().encrypt(uid, upper, value.as_bytes()) {
        expiry::delete_meta(&mp);
        return Err(e);
    }
    crate::daemon_history::purge(uid, upper);
    files::move_history(uid, &entry, upper);
    crate::daemon_recordsx::move_attachments(uid, &entry, upper); // T5.03
    purge_entry(uid, &entry);
    Ok(())
}

pub fn handle_purge(uid: u32, username: &str, name: Option<&str>) -> Response {
    let upper = name.map(str::to_uppercase);
    if let Some(Err(e)) = upper.as_deref().map(validate_name) {
        return Response::fail(e);
    }
    let mut purged = 0;
    for (n, entry) in entries(uid) {
        if upper.as_ref().is_none_or(|u| *u == n) {
            let _lock = crate::daemon_credlock::lock(uid, &n);
            purge_entry(uid, &entry);
            purged += 1;
        }
    }
    log("trash-purge", uid, username, upper.as_deref(), &Ok(()));
    Response::Store(StoreResponse::TrashPurgeOk { purged })
}

/// Purge entries older than `days` (or past their TTL). `only` limits the
/// pass to one uid (tests); the sweeper passes `None`.
pub fn sweep_in(only: Option<u32>, now: u64, days: u64) -> usize {
    let mut purged = 0;
    for (uid, entry, _) in files::all_in(&crate::store::store_dir()) {
        let Some((name, rest)) = entry.split_once("~t") else {
            continue;
        };
        if rest.contains('~') || only.is_some_and(|u| u != uid) {
            continue;
        }
        let meta = entry_meta(uid, &entry).unwrap_or_default();
        let at = meta.trashed_at.unwrap_or_else(|| stamp(&entry));
        let old = now >= at.saturating_add(days.saturating_mul(DAY));
        if old || meta.expires_at_unix.is_some_and(|t| t <= now) {
            let _lock = crate::daemon_credlock::lock(uid, name);
            purge_entry(uid, &entry);
            let user = audit::username_for_uid(uid);
            log("trash-purge", uid, &user, Some(name), &Ok(()));
            purged += 1;
        }
    }
    purged
}

/// The sweeper's hook (daemon_expiry.rs).
pub fn sweep(now: u64) {
    sweep_in(None, now, days());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;
    use kepr_core::protocol::HistoryEntry;

    fn items(uid: u32) -> Vec<TrashItem> {
        match handle_list(uid, "t") {
            Response::Store(StoreResponse::TrashListOk { items }) => items,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn history(uid: u32, name: &str) -> Vec<HistoryEntry> {
        match crate::daemon_history::handle_history(uid, "t", name) {
            Response::HistoryOk { versions, .. } => versions,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rm_list_restore_round_trip_with_history_and_tags() {
        let uid = testkit::uid();
        testkit::set(uid, "TR_A", "one");
        testkit::set(uid, "TR_A", "two");
        super::super::organize::handle_organize(uid, "t", "TR_A", (&["keep".into()], &[]), None);
        assert!(matches!(
            rm(uid, "t", "tr_a", 30),
            Response::DeleteOk { .. }
        ));
        assert!(!cred_path(uid, "TR_A").exists());
        assert!(testkit::value(uid, "TR_A").is_none());
        let it = items(uid);
        assert_eq!(it.len(), 1);
        assert_eq!(it[0].name, "TR_A");
        // Not listed, not nameable.
        assert!(crate::daemon_cache::list_for_uid(uid).is_empty());

        let r = handle_restore(uid, "t", "TR_A");
        assert!(r.is_success(), "{r:?}");
        assert_eq!(testkit::value(uid, "TR_A").as_deref(), Some("two"));
        assert_eq!(
            testkit::meta(uid, "TR_A").tags,
            Some(vec!["keep".to_string()])
        );
        assert_eq!(testkit::meta(uid, "TR_A").trashed_at, None);
        assert_eq!(history(uid, "TR_A").len(), 1);
        assert!(items(uid).is_empty());
        assert_eq!(files::all_of(uid).len(), 2, "value + one history slot only");
    }

    #[test]
    fn restore_refuses_when_the_name_exists_again() {
        let uid = testkit::uid();
        testkit::set(uid, "TR_B", "old");
        rm(uid, "t", "TR_B", 30);
        testkit::set(uid, "TR_B", "new");
        let r = handle_restore(uid, "t", "TR_B");
        assert!(r.err_msg().unwrap().contains("exists again"), "{r:?}");
        assert_eq!(testkit::value(uid, "TR_B").as_deref(), Some("new"));
        assert_eq!(items(uid).len(), 1);
        assert!(handle_restore(uid, "t", "NEVER")
            .err_msg()
            .unwrap()
            .contains("not in the trash"));
    }

    #[test]
    fn sealed_creds_keep_their_seal_and_bindings() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "TR_S", "sk-live");
        let before = testkit::meta(uid, "TR_S");
        rm(uid, "t", "TR_S", 30);
        let it = items(uid);
        assert_eq!(it[0].sealed, Some(true));
        let entry = &entries(uid)[0].1;
        assert_eq!(entry_meta(uid, entry).unwrap().sealed, Some(true));
        assert!(handle_restore(uid, "t", "TR_S").is_success());
        let after = testkit::meta(uid, "TR_S");
        assert_eq!(after.sealed, Some(true));
        assert_eq!(after.bindings, before.bindings);
        // Still refused to `get`.
        let r = crate::daemon_handlers_get::handle_get(uid, 0, "t", "TR_S", None);
        assert_eq!(r.err_msg(), Some("credential unavailable"));
    }

    #[test]
    fn purge_one_or_all_and_sweep_old_entries() {
        let uid = testkit::uid();
        for n in ["TR_P1", "TR_P2", "TR_P3"] {
            testkit::set(uid, n, "v");
            rm(uid, "t", n, 30);
        }
        assert!(handle_purge(uid, "t", Some("tr_p1")).is_success());
        assert_eq!(items(uid).len(), 2);
        let now = expiry::now_unix();
        assert_eq!(sweep_in(Some(uid), now, 30), 0);
        assert_eq!(sweep_in(Some(uid), now + 31 * DAY, 30), 2);
        assert!(items(uid).is_empty());
        assert!(files::all_of(uid).is_empty());
        testkit::set(uid, "TR_P4", "v");
        rm(uid, "t", "TR_P4", 30);
        match handle_purge(uid, "t", None) {
            Response::Store(StoreResponse::TrashPurgeOk { purged }) => assert_eq!(purged, 1),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn trash_off_deletes_at_once_and_bad_names_are_refused() {
        let uid = testkit::uid();
        testkit::set(uid, "TR_OFF", "v");
        assert!(matches!(
            rm(uid, "t", "TR_OFF", 0),
            Response::DeleteOk { .. }
        ));
        assert!(items(uid).is_empty());
        assert!(files::all_of(uid).is_empty());
        assert!(!rm(uid, "t", "../x", 30).is_success());
        assert_eq!(
            rm(uid, "t", "MISSING", 30).err_msg(),
            Some("credential unavailable")
        );
    }
}
