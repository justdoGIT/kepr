// daemon_syncx/sync_merge.rs — T6.10 the daemon side of `kepr sync now`.
//
//   SyncDevice   this device's id (its bundle's file name on a remote)
//   SyncBuild    record local changes, then a bundle of every synced
//                credential (and tombstone) for the enrolled devices
//   SyncMerge    open another device's bundle (uploaded like an import)
//                and apply each entry that is newer than what we know:
//                a value is stored as `set` would (history keeps the old
//                one), a tombstone moves the credential to the trash.
//                A bundle older than one already merged from the same
//                device is ignored: a replayed copy would otherwise bring
//                back what was deleted once its tombstone expired
//
// A credential that doesn't sync here (sealed, SSH, share key, gated) is
// never replaced or deleted by a merge. Network and files stay in the CLI:
// the daemon only sees bundle bytes.

use std::sync::Mutex;
use std::time::Instant;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_syncx::{BundleRow, SyncxResponse, MAX_REPORT_ROWS};

use super::bundle::Item;
use super::device_bundle::{self, device_id, Entry, SyncBody};
use super::sync_state::{self, fingerprint, Local, Rec, State};
use super::{audit_r, import, transfer};
use crate::daemon_sharing::kem::{Recipient, ShareSecret};
use crate::expiry::now_unix;
use crate::store::{cred_exists, validate_name};

/// One sync at a time per daemon: the state file is read-modify-write.
static SYNC: Mutex<()> = Mutex::new(());

fn me(uid: u32) -> Result<(ShareSecret, String), String> {
    let secret = crate::daemon_share::load_secret(uid)?;
    let id = device_id(&secret.recipient().text());
    Ok((secret, id))
}

/// The enrolled devices (T6.03): who bundles go to and come from.
fn devices(uid: u32) -> Vec<Recipient> {
    crate::daemon_sharing::devices::sync_recipients(uid)
        .iter()
        .filter_map(|t| Recipient::parse(t).ok())
        .collect()
}

/// Load the state and record local changes; returns it with the local
/// credentials it was compared against.
fn refreshed(
    who: (u32, i32),
    username: &str,
    key: &[u8; 32],
    id: &str,
) -> (State, std::collections::BTreeMap<String, Local>) {
    let local = sync_state::local(who, username);
    let mut st = sync_state::load_state(who.0);
    st.refresh(who.0, &local, (key, id), now_unix());
    (st, local)
}

pub fn handle_device(uid: u32) -> Response {
    match me(uid) {
        Ok((_, device)) => SyncxResponse::SyncDeviceOk {
            device,
            devices: devices(uid).len() as u32,
        }
        .into(),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_build(who: (u32, i32), username: &str) -> Response {
    let uid = who.0;
    let r = (|| {
        let _g = SYNC.lock().map_err(|_| "sync lock poisoned")?;
        let (secret, id) = me(uid)?;
        let key = sync_state::fp_key(&secret);
        let (mut st, mut local) = refreshed(who, username, &key, &id);
        st.built = now_unix().max(st.built.saturating_add(1));
        let entries: Vec<Entry> = st
            .recs
            .iter()
            .filter_map(|(name, r)| {
                let (value, meta) = match (&r.fp, local.remove(name)) {
                    (Some(_), Some(l)) => (Some(l.value), l.meta),
                    (Some(_), None) => return None, // exists, doesn't sync now
                    (None, _) => (None, Default::default()),
                };
                Some(Entry {
                    name: name.clone(),
                    at: r.at,
                    origin: r.origin.clone(),
                    value,
                    meta,
                })
            })
            .collect();
        let items = entries.len() as u32;
        let bytes = device_bundle::seal(&secret, &devices(uid), &SyncBody { entries }, st.built)?;
        sync_state::save_state(uid, &st)?;
        let size = bytes.len() as u64;
        let (id, chunks) = transfer::put_export(uid, bytes, now_unix())?;
        Ok((id, size, chunks, items))
    })();
    audit_r("sync-build", uid, username, None, &r);
    match r {
        Ok((id, size, chunks, items)) => SyncxResponse::BundleReady {
            id,
            size,
            chunks,
            items,
            omitted: vec![],
            omitted_count: 0,
        }
        .into(),
        Err(e) => Response::fail(e),
    }
}

fn row(name: &str, change: &str, reason: Option<String>) -> BundleRow {
    BundleRow {
        name: name.to_string(),
        change: change.to_string(),
        reason,
    }
}

/// Apply one entry newer than ours. Returns the row (None: no visible
/// change) and the record to keep. Caller holds the credential's lock.
fn merge_one(
    who: (u32, i32),
    username: &str,
    e: &Entry,
    (local, key): (Option<&Local>, &[u8; 32]),
) -> (Option<BundleRow>, Option<Rec>) {
    let uid = who.0;
    let mut rec = Rec {
        at: e.at,
        origin: e.origin.clone(),
        fp: None,
    };
    let exists = cred_exists(uid, &e.name);
    if exists && local.is_none() {
        let why = "a credential that doesn't sync has this name";
        return (Some(row(&e.name, "skipped", Some(why.into()))), None);
    }
    let Some(value) = &e.value else {
        if !exists {
            return (None, Some(rec));
        }
        let r = crate::daemon_store::handle_rm(uid, username, &e.name);
        return match r {
            Response::Err { error } => (Some(row(&e.name, "failed", Some(error))), None),
            _ => (Some(row(&e.name, "delete", None)), Some(rec)),
        };
    };
    let item = Item {
        name: e.name.clone(),
        value: ZeroString::from(value.as_str()),
        meta: e.meta.clone(),
        history: vec![],
        files: vec![],
    };
    let incoming = Local {
        value: ZeroString::from(value.as_str()),
        meta: e.meta.clone(),
    };
    if local.is_some_and(|l| fingerprint(key, &e.name, l) == fingerprint(key, &e.name, &incoming)) {
        rec.fp = Some(fingerprint(key, &e.name, &incoming));
        return (None, Some(rec));
    }
    if !import::set_allowed(who, username, &e.name, e.meta.expires_at_unix) {
        return (
            Some(row(&e.name, "skipped", Some("denied by policy".into()))),
            None,
        );
    }
    let change = if exists { "update" } else { "create" };
    match import::apply(uid, username, &e.name, &item, !exists) {
        Err(err) => (Some(row(&e.name, "failed", Some(err))), None),
        Ok(notes) => {
            // Fingerprint what is stored now, so the next refresh doesn't
            // take a meta field this store can't hold for a local edit.
            let stored = sync_state::local_one(who, username, &e.name);
            rec.fp = Some(fingerprint(
                key,
                &e.name,
                stored.as_ref().unwrap_or(&incoming),
            ));
            let notes = (!notes.is_empty()).then(|| notes.join("; "));
            (Some(row(&e.name, change, notes)), Some(rec))
        }
    }
}

/// The whole bundle refused: drop the upload, audit why.
fn refuse(uid: u32, username: &str, upload: &str, e: String) -> Response {
    transfer::drop_upload(uid, upload);
    audit_r::<()>("sync-merge", uid, username, None, &Err(e.clone()));
    Response::fail(e)
}

pub fn handle_merge(who: (u32, i32), username: &str, upload: &str, start: u32) -> Response {
    let uid = who.0;
    let opened = transfer::upload_bytes(uid, upload).and_then(|bytes| {
        let (secret, id) = me(uid)?;
        let b = device_bundle::open(&secret, &devices(uid), &bytes)?;
        Ok((secret, id, b))
    });
    let (secret, id, b) = match opened {
        Ok(x) => x,
        Err(e) => return refuse(uid, username, upload, e),
    };
    let Ok(_g) = SYNC.lock() else {
        return Response::fail("sync lock poisoned");
    };
    let key = sync_state::fp_key(&secret);
    let (mut st, local) = refreshed(who, username, &key, &id);
    if st.seen.get(&b.from).is_some_and(|seen| b.at < *seen) {
        let e = "older than a bundle already merged from that device (a stale or \
                 replayed copy): ignored";
        return refuse(uid, username, upload, e.into());
    }
    let seen = st.seen.entry(b.from.clone()).or_insert(0);
    *seen = (*seen).max(b.at);
    let body = &b.body;
    let (started, total) = (Instant::now(), body.entries.len());
    let (mut rows, mut unchanged, mut i) = (Vec::new(), 0u32, start as usize);
    while i < total && rows.len() < MAX_REPORT_ROWS && started.elapsed() < import::ROUND_TIME {
        let e = &body.entries[i];
        i += 1;
        if validate_name(&e.name).is_err() || e.name == crate::daemon_share::KEY_NAME {
            rows.push(row(
                &e.name,
                "skipped",
                Some("not a valid name here".into()),
            ));
            continue;
        }
        let incoming = Rec {
            at: e.at,
            origin: e.origin.clone(),
            fp: None,
        };
        if st.recs.get(&e.name).is_some_and(|cur| !incoming.beats(cur)) {
            unchanged += 1;
            continue;
        }
        let _lock = crate::daemon_credlock::lock(uid, &e.name);
        let (shown, rec) = merge_one(who, username, e, (local.get(&e.name), &key));
        if let Some(rec) = rec {
            st.recs.insert(e.name.clone(), rec);
        }
        match shown {
            Some(r) => {
                let ok = r.change != "failed";
                let res = if ok {
                    Ok(())
                } else {
                    Err(r.reason.clone().unwrap_or_default())
                };
                audit_r("sync-merge", uid, username, Some(&e.name), &res);
                rows.push(r);
            }
            None => unchanged += 1,
        }
    }
    if let Err(e) = sync_state::save_state(uid, &st) {
        return Response::fail(e);
    }
    let next = (i < total).then(|| u32::try_from(i).unwrap_or(u32::MAX));
    if next.is_none() {
        transfer::drop_upload(uid, upload);
        audit_r::<()>("sync-merge", uid, username, None, &Ok(()));
    }
    SyncxResponse::BundleImported {
        applied: true,
        rows,
        unchanged,
        next,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{device, enroll, pair};
    use super::*;
    use crate::daemon_handlers::{handle_set, SetFlags};
    use crate::daemon_store::testkit;
    use base64::Engine;
    use kepr_core::protocol_sharing::SharingRequest;
    use kepr_core::protocol_syncx::{SyncxRequest, BUNDLE_CHUNK_BYTES};

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    fn call(uid: u32, r: SyncxRequest) -> Response {
        super::super::dispatch(uid, 0, "t", r)
    }

    fn build(uid: u32) -> Result<Vec<u8>, String> {
        let (id, chunks) = match call(uid, SyncxRequest::SyncBuild) {
            Response::Syncx(SyncxResponse::BundleReady { id, chunks, .. }) => (id, chunks),
            Response::Err { error } => return Err(error),
            other => panic!("{other:?}"),
        };
        let mut out = Vec::new();
        for index in 0..chunks {
            let r = call(
                uid,
                SyncxRequest::ExportChunk {
                    id: id.clone(),
                    index,
                },
            );
            let Response::Syncx(SyncxResponse::BundleChunk { data, .. }) = r else {
                panic!("{r:?}");
            };
            out.extend(B64.decode(data).unwrap());
        }
        Ok(out)
    }

    fn merge(uid: u32, bytes: &[u8]) -> Result<Vec<BundleRow>, String> {
        let mut upload = None;
        let parts: Vec<&[u8]> = bytes.chunks(BUNDLE_CHUNK_BYTES).collect();
        for (i, c) in parts.iter().enumerate() {
            let put = SyncxRequest::ImportPut {
                upload: upload.take(),
                index: i as u32,
                chunk: B64.encode(c),
                last: i + 1 == parts.len(),
            };
            let Response::Syncx(SyncxResponse::ImportPutOk { upload: u, .. }) = call(uid, put)
            else {
                panic!("put");
            };
            upload = Some(u);
        }
        let (upload, mut rows, mut start) = (upload.unwrap(), Vec::new(), 0);
        loop {
            let r = call(
                uid,
                SyncxRequest::SyncMerge {
                    upload: upload.clone(),
                    start,
                },
            );
            match r {
                Response::Syncx(SyncxResponse::BundleImported { rows: r, next, .. }) => {
                    rows.extend(r);
                    match next {
                        Some(n) => start = n,
                        None => return Ok(rows),
                    }
                }
                Response::Err { error } => return Err(error),
                other => panic!("{other:?}"),
            }
        }
    }

    /// One full exchange: a → b, then b → a.
    fn exchange(a: u32, b: u32) {
        merge(b, &build(a).unwrap()).unwrap();
        merge(a, &build(b).unwrap()).unwrap();
    }

    #[test]
    fn two_devices_converge_and_deletes_propagate() {
        let (a, b) = pair();
        testkit::set(a, "SY_ONE", "one");
        testkit::set(b, "SY_TWO", "two");
        exchange(a, b);
        for d in [a, b] {
            assert_eq!(testkit::value(d, "SY_ONE").as_deref(), Some("one"));
            assert_eq!(testkit::value(d, "SY_TWO").as_deref(), Some("two"));
        }
        // An edit on a reaches b; b's old value goes to its history.
        testkit::set(a, "SY_ONE", "one-b");
        let rows = merge(b, &build(a).unwrap()).unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(
            (rows[0].name.as_str(), rows[0].change.as_str()),
            ("SY_ONE", "update")
        );
        assert_eq!(testkit::value(b, "SY_ONE").as_deref(), Some("one-b"));
        let (old, _) = crate::daemon_history::version_value(b, "SY_ONE", 1).unwrap();
        assert_eq!(old.as_str(), "one");
        // A delete on b reaches a (into its trash).
        assert!(crate::daemon_store::handle_rm(b, "t", "SY_TWO").is_success());
        let rows = merge(a, &build(b).unwrap()).unwrap();
        assert!(
            rows.iter()
                .any(|r| r.name == "SY_TWO" && r.change == "delete"),
            "{rows:?}"
        );
        assert!(!cred_exists(a, "SY_TWO"));
        // Nothing left to move: another exchange changes nothing.
        let quiet = merge(b, &build(a).unwrap()).unwrap();
        assert!(quiet.is_empty(), "{quiet:?}");
        assert!(merge(a, &build(b).unwrap()).unwrap().is_empty());
        assert!(!cred_exists(b, "SY_TWO"));
    }

    #[test]
    fn conflicting_edits_settle_on_one_value_everywhere() {
        let (a, b) = pair();
        testkit::set(a, "SY_X", "from-a");
        testkit::set(b, "SY_X", "from-b");
        let (ba, bb) = (build(a).unwrap(), build(b).unwrap());
        merge(a, &bb).unwrap();
        merge(b, &ba).unwrap();
        let (va, vb) = (testkit::value(a, "SY_X"), testkit::value(b, "SY_X"));
        assert_eq!(va, vb);
        assert!(va.is_some());
    }

    #[test]
    fn a_bundle_from_an_unknown_device_is_ignored() {
        let (a, stranger) = (device(), device());
        enroll(stranger, a); // the stranger knows a's key; a never enrolled it
        testkit::set(stranger, "SY_EVIL", "x");
        let e = merge(a, &build(stranger).unwrap()).unwrap_err();
        assert!(e.contains("unknown device"), "{e}");
        assert!(!cred_exists(a, "SY_EVIL"));
    }

    #[test]
    fn a_removed_device_cannot_open_bundles_built_after() {
        let (a, b) = pair();
        testkit::set(a, "SY_R", "v1");
        assert!(merge(b, &build(a).unwrap()).is_ok());
        let rm = SharingRequest::DeviceRemove {
            device: format!("d{b}"),
        };
        assert!(crate::daemon_sharing::dispatch(a, 0, "t", rm).is_success());
        assert!(build(a).unwrap_err().contains("no devices"));
        let c = device();
        enroll(a, c);
        testkit::set(a, "SY_R", "v2");
        let e = merge(b, &build(a).unwrap()).unwrap_err();
        assert_eq!(e, "not encrypted to this device");
        assert_eq!(testkit::value(b, "SY_R").as_deref(), Some("v1"));
    }

    #[test]
    fn credentials_that_dont_sync_are_never_sent_or_replaced() {
        let (a, b) = pair();
        testkit::set_sealed(a, "SY_SEALED_A", "sealed-secret-a");
        let consent = SetFlags {
            requires_consent: Some(true),
            ..Default::default()
        };
        assert!(handle_set(a, "t", "SY_ASK", Some("ask-secret"), None, consent).is_success());
        testkit::set(a, "SY_S", "plain-from-a");
        testkit::set_sealed(b, "SY_S", "sealed-on-b");
        let rows = merge(b, &build(a).unwrap()).unwrap();
        assert!(
            rows.iter()
                .any(|r| r.name == "SY_S" && r.change == "skipped"),
            "{rows:?}"
        );
        assert_eq!(testkit::meta(b, "SY_S").sealed, Some(true));
        assert_eq!(testkit::value(b, "SY_S").as_deref(), Some("sealed-on-b"));
        for n in ["SY_SEALED_A", "SY_ASK", "KEPR_SHARE_KEY"] {
            assert!(!rows.iter().any(|r| r.name == n), "{n} was sent");
        }
        assert!(!cred_exists(b, "SY_SEALED_A") && !cred_exists(b, "SY_ASK"));
    }

    /// Security review (T6.10): a replayed old bundle must not bring back
    /// a credential deleted long enough ago that its tombstone is gone.
    #[test]
    fn an_older_bundle_from_a_device_is_ignored() {
        let (a, b) = pair();
        testkit::set(a, "SR_GONE", "old-secret");
        let old = build(a).unwrap();
        merge(b, &old).unwrap();
        assert!(crate::daemon_store::handle_rm(a, "t", "SR_GONE").is_success());
        let new = build(a).unwrap();
        merge(b, &new).unwrap();
        assert!(!cred_exists(b, "SR_GONE"));
        // What refresh's retain does once the tombstone is 30 days old.
        let mut st = sync_state::load_state(b);
        assert!(st.recs.remove("SR_GONE").is_some());
        sync_state::save_state(b, &st).unwrap();
        let e = merge(b, &old).unwrap_err();
        assert!(e.contains("older"), "{e}");
        assert!(!cred_exists(b, "SR_GONE"));
        // The newest bundle again (nothing new on the remote) is fine.
        assert!(merge(b, &new).unwrap().is_empty());
    }
}
