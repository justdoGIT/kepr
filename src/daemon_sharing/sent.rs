// daemon_sharing/sent.rs — the sent-share ledger and self-destruct (T6.05;
// T11.15's report reads the same ledger).
//
// Every one-time link (and envelope) a user sends is one ledger row: id,
// name, recipient, relay, sent / expires / opened times. No value, no key.
//
// Self-destruct: `share send NAME --once --self-destruct` marks the record
// (`.meta` `self_destruct_share` = the link id). It is deleted, with its
// history, the trash skipped, when
//   - this daemon stores a share with that id (the receive path calls
//     `on_received`), or the owner reports its relay blob gone
//     (`ShareLinkOpened`), or
//   - the link expires (the expiry sweeper calls `sweep`).
// A new `set` drops the mark, so a value replaced since is never deleted.

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{SentShare, SharingResponse};

use super::{audit_r, load, save, state_path, state_root, LOCK};
use crate::audit::username_for_uid;
use crate::expiry;
use crate::store::{cred_path, validate_name};

const KIND: &str = "share-sent";
/// Rows are kept this long after their share expired.
const KEEP_AFTER_EXPIRY: u64 = 90 * 86_400;
const MAX_ROWS: usize = 500;

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Ledger {
    #[serde(default)]
    sent: Vec<SentShare>,
}

fn meta_path(uid: u32, name: &str) -> std::path::PathBuf {
    expiry::meta_path_for(&cred_path(uid, name))
}

/// Append a row to `uid`'s ledger.
pub(crate) fn record(uid: u32, row: SentShare, now: u64) -> Result<(), String> {
    let _g = LOCK.lock().map_err(|_| "state lock poisoned")?;
    let path = state_path(KIND, uid);
    let mut l: Ledger = load(&path);
    l.sent
        .retain(|s| s.expires_unix.saturating_add(KEEP_AFTER_EXPIRY) > now);
    l.sent.push(row);
    let over = l.sent.len().saturating_sub(MAX_ROWS);
    l.sent.drain(..over);
    save(&path, &l)
}

pub(crate) fn rows(uid: u32) -> Vec<SentShare> {
    let _g = LOCK.lock();
    load::<Ledger>(&state_path(KIND, uid)).sent
}

/// Mark `name` (locked by nobody) to self-destruct with link `id`.
pub(crate) fn mark(uid: u32, name: &str, id: &str) -> Result<(), String> {
    let _lock = crate::daemon_credlock::lock(uid, name);
    let path = meta_path(uid, name);
    let mut meta = match expiry::read_meta(&path) {
        None => expiry::CredMeta::default(),
        Some(Ok(m)) => m,
        Some(Err(_)) => return Err("this credential can't be shared".into()),
    };
    meta.self_destruct_share = Some(id.to_string());
    expiry::write_meta(&path, &meta)
}

/// Delete `name` if it is still marked for link `id`. `Ok(false)`: the
/// mark is gone (replaced or deleted since), nothing to do.
pub(crate) fn destroy(uid: u32, name: &str, id: &str) -> Result<bool, String> {
    validate_name(name)?;
    let _lock = crate::daemon_credlock::lock(uid, name);
    let marked = matches!(
        expiry::read_meta(&meta_path(uid, name)),
        Some(Ok(m)) if m.self_destruct_share.as_deref() == Some(id)
    );
    if !marked {
        return Ok(false);
    }
    let username = username_for_uid(uid);
    // The trash is skipped on purpose: no copy may linger.
    let r = match crate::daemon_handlers::handle_delete(uid, &username, name) {
        Response::DeleteOk { .. } => Ok(true),
        Response::Err { error } => Err(error),
        _ => Err("unexpected store reply".to_string()),
    };
    audit_r("self-destruct", uid, &username, Some(name), &r);
    r
}

/// Every uid that has a ledger.
fn ledger_uids() -> Vec<u32> {
    let Ok(rd) = std::fs::read_dir(state_root()) else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            n.strip_prefix("share-sent-")?
                .strip_suffix(".json")?
                .parse()
                .ok()
        })
        .collect()
}

/// Set `opened_unix` on the row with `id`; returns its owner and row.
fn set_opened(id: &str, only_uid: Option<u32>, now: u64) -> Option<(u32, SentShare)> {
    let _g = LOCK.lock().ok()?;
    for uid in only_uid.map_or_else(ledger_uids, |u| vec![u]) {
        let path = state_path(KIND, uid);
        let mut l: Ledger = load(&path);
        if let Some(row) = l.sent.iter_mut().find(|s| s.id == id) {
            row.opened_unix.get_or_insert(now);
            let row = row.clone();
            let _ = save(&path, &l);
            return Some((uid, row));
        }
    }
    None
}

fn set_settled(uid: u32, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let Ok(_g) = LOCK.lock() else { return };
    let path = state_path(KIND, uid);
    let mut l: Ledger = load(&path);
    for row in l.sent.iter_mut().filter(|s| ids.contains(&s.id)) {
        row.settled = true;
    }
    let _ = save(&path, &l);
}

fn opened(id: &str, only_uid: Option<u32>, now: u64) -> Result<bool, String> {
    let Some((uid, row)) = set_opened(id, only_uid, now) else {
        return Ok(false);
    };
    if row.self_destruct && !row.settled {
        destroy(uid, &row.name, id)?;
        set_settled(uid, &[row.id]);
    }
    Ok(true)
}

/// The receive path stored a share with `id` (any user of this daemon).
pub(crate) fn on_received(id: &str, now: u64) {
    if let Err(e) = opened(id, None, now) {
        eprintln!("[kepr-daemon] self-destruct after open failed: {e}");
    }
}

/// `ShareLinkOpened`: the owner saw the relay blob gone.
pub fn handle_opened(uid: u32, username: &str, id: &str) -> Response {
    let r = opened(id, Some(uid), expiry::now_unix())
        .and_then(|found| found.then_some(()).ok_or("no such sent share".to_string()));
    audit_r("share-opened", uid, username, None, &r);
    match r {
        Ok(()) => super::done("marked opened"),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_list(uid: u32) -> Response {
    SharingResponse::ShareSent { shares: rows(uid) }.into()
}

/// Self-destruct what is due for `uid`: opened, or past its expiry.
pub(crate) fn sweep_uid(uid: u32, now: u64) {
    let due: Vec<SentShare> = rows(uid)
        .into_iter()
        .filter(|s| s.self_destruct && !s.settled)
        .filter(|s| s.opened_unix.is_some() || now >= s.expires_unix)
        .collect();
    let mut settled = Vec::new();
    for s in due {
        match destroy(uid, &s.name, &s.id) {
            Ok(_) => settled.push(s.id),
            Err(e) => eprintln!("[kepr-daemon] self-destruct sweep failed: {e}"),
        }
    }
    set_settled(uid, &settled);
}

/// Every ledger's due self-destructs (from the expiry sweeper's tick).
pub fn sweep(now: u64) {
    for uid in ledger_uids() {
        sweep_uid(uid, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_sharing::link::{handle_create, handle_open};
    use crate::daemon_store::testkit;
    use kepr_core::protocol_sharing::SharingResponse as S;

    fn link(uid: u32, name: &str, self_destruct: bool) -> (String, String, String) {
        match handle_create((uid, 0), "t", name, Some(60), self_destruct, None) {
            Response::Sharing(S::ShareLink { key, blob, id, .. }) => {
                (id, key.as_str().to_string(), blob)
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn opening_the_link_destroys_the_record_and_its_history() {
        super::super::test_chain();
        let (a, b) = (testkit::uid(), testkit::uid());
        testkit::set(a, "SD_OPEN", "old");
        testkit::set(a, "SD_OPEN", "s3cret"); // one history slot
        let (id, key, blob) = link(a, "SD_OPEN", true);
        assert_eq!(testkit::meta(a, "SD_OPEN").self_destruct_share, Some(id));
        assert!(handle_open(b, "t", &blob, &key, Some("SD_GOT")).is_success());
        assert_eq!(testkit::value(b, "SD_GOT").as_deref(), Some("s3cret"));
        let row = &rows(a)[0];
        assert!(row.opened_unix.is_some() && row.settled);
        assert!(super::super::audited(a, "self-destruct", "SD_OPEN"));
        // No file of `a` is left: value, .meta, history slot, trash entry.
        assert_eq!(files_of(a), Vec::<String>::new());
    }

    fn files_of(uid: u32) -> Vec<String> {
        let prefix = format!("kepr-{uid}-");
        std::fs::read_dir(crate::store::store_dir())
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with(&prefix))
            .collect()
    }

    #[test]
    fn an_unmarked_link_leaves_the_record() {
        let (a, b) = (testkit::uid(), testkit::uid());
        testkit::set(a, "SD_KEEP", "v");
        let (_, key, blob) = link(a, "SD_KEEP", false);
        assert!(handle_open(b, "t", &blob, &key, None).is_success());
        assert!(crate::store::cred_exists(a, "SD_KEEP"));
        assert!(rows(a)[0].opened_unix.is_some());
    }

    #[test]
    fn the_sweeper_destroys_an_expired_link_record() {
        let a = testkit::uid();
        testkit::set(a, "SD_EXPIRE", "v");
        let (_, _, _) = link(a, "SD_EXPIRE", true);
        let now = expiry::now_unix();
        sweep_uid(a, now);
        assert!(crate::store::cred_exists(a, "SD_EXPIRE"), "not due yet");
        sweep_uid(a, now + 61);
        assert!(!crate::store::cred_exists(a, "SD_EXPIRE"));
        assert!(rows(a)[0].settled);
    }

    #[test]
    fn a_new_set_cancels_the_self_destruct() {
        let a = testkit::uid();
        testkit::set(a, "SD_RESET", "v");
        let (id, _, _) = link(a, "SD_RESET", true);
        testkit::set(a, "SD_RESET", "new");
        assert_eq!(testkit::meta(a, "SD_RESET").self_destruct_share, None);
        assert_eq!(destroy(a, "SD_RESET", &id), Ok(false));
        sweep_uid(a, expiry::now_unix() + 61);
        assert_eq!(testkit::value(a, "SD_RESET").as_deref(), Some("new"));
    }

    #[test]
    fn the_owner_reports_a_relay_open() {
        let (a, other) = (testkit::uid(), testkit::uid());
        testkit::set(a, "SD_RELAY", "v");
        let (id, _, _) = link(a, "SD_RELAY", true);
        // Another user can't name someone else's share.
        assert!(!handle_opened(other, "t", &id).is_success());
        assert!(crate::store::cred_exists(a, "SD_RELAY"));
        assert!(handle_opened(a, "t", &id).is_success());
        assert!(!crate::store::cred_exists(a, "SD_RELAY"));
    }
}
