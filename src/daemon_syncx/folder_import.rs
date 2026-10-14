// daemon_syncx/folder_import.rs — T6.02 shared folders, the import side.
//
//   FolderImport  a bundle from a pinned contact (T11.15), signature and
//                 sender checked (folder_bundle.rs), written plain or
//                 sealed per its flag
//
// Re-importing a newer bundle of the same folder updates only what
// changed in it: the importer keeps a fingerprint (HMAC under a key
// derived from its share key) of what each import wrote, per folder id
// (folder_state.rs), and never compares against the stored value itself,
// so an import can't test guesses against a sealed or gated credential.
// A bundle older than one of the same folder already imported is refused
// (no rollback to a value the sender has since rotated). A name that exists
// and didn't come from this folder is left alone unless --overwrite; an
// SSH or share key is never replaced and a sealed credential is never
// replaced by a plain one. A sealed import binds each value to its
// provider's host (the key prefix or name says which); one with no known
// provider is skipped rather than stored readable.

use std::time::Instant;

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::SharingResponse;
use kepr_core::protocol_store::StoreRequest;
use kepr_core::protocol_syncx::{SyncxResponse, MAX_REPORT_ROWS};

use super::folder::meta_of;
use super::folder_bundle::{self, Opened, Payload};
use super::folder_state::{self, fingerprint, fp_key, Record, State};
use super::import::{self, row, ROUND_TIME};
use super::{audit_r, transfer};
use crate::daemon_handlers::{handle_set, SetFlags};
use crate::daemon_sharing::contacts;
use crate::daemon_sharing::kem::{Recipient, ShareSecret};
use crate::expiry::{self, now_unix, CredMeta};
use crate::store::{cred_exists, cred_path};

/// The pinned contact's name for a public key (canonical text).
fn pinned(uid: u32) -> impl Fn(&str) -> Option<String> {
    let list = match contacts::handle_list(uid) {
        Response::Sharing(SharingResponse::ShareContacts { contacts }) => contacts,
        _ => Vec::new(),
    };
    move |public: &str| {
        list.iter()
            .find(|c| Recipient::parse(&c.public).is_ok_and(|r| r.text() == public))
            .map(|c| c.name.clone())
    }
}

/// What importing `p` as `name` would do. Caller holds the lock.
fn plan(
    who: (u32, i32),
    username: &str,
    (name, p, sealed): (&str, &Payload, bool),
    (recorded, fp, overwrite): (Option<&Record>, &str, bool),
) -> (&'static str, Option<String>) {
    let skip = |why: &str| ("skipped", Some(why.to_string()));
    let expires = p.meta.expires_at_unix;
    if expires.is_some_and(|t| t <= now_unix()) {
        return skip("expired");
    }
    let exists = cred_exists(who.0, name);
    if exists {
        let Some(meta) = meta_of(who.0, name).or_else(|| meta_missing(who.0, name)) else {
            return skip("unreadable");
        };
        if meta.ssh.is_some() || meta.share_key == Some(true) {
            return skip("a sign-only credential has this name");
        }
        if meta.sealed == Some(true) && !sealed {
            return skip("a sealed credential has this name");
        }
        // The folder's own: what its import wrote, still carrying the mark
        // (not set again, nor deleted and made again here since).
        let ours = recorded.filter(|r| meta.folder_mark.as_deref() == Some(r.mark.as_str()));
        if ours.is_some_and(|r| r.fp == fp) {
            return ("unchanged", None);
        }
        if !overwrite && ours.is_none() {
            return skip(match recorded {
                Some(_) => "changed here since this folder wrote it (use --overwrite)",
                None => "already in kepr, not from this folder (use --overwrite)",
            });
        }
        // A gate set here (a sealed folder's own seal aside) is never
        // lifted by an update the user didn't ask for.
        let mut here = meta.clone();
        here.sealed = here.sealed.filter(|_| !sealed);
        if let Some(why) = here.gated().filter(|_| !overwrite) {
            return skip(&format!("{why}-gated here (use --overwrite)"));
        }
    }
    if !import::set_allowed(who, username, name, expires) {
        return skip("denied by policy");
    }
    if sealed && kepr_core::providers::detect(Some(name), p.value.as_str()).is_none() {
        return skip("no known provider to bind the sealed value to");
    }
    (if exists { "update" } else { "create" }, None)
}

/// No `.meta` at all reads as defaults; a damaged one as None.
fn meta_missing(uid: u32, name: &str) -> Option<CredMeta> {
    expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, name)))
        .is_none()
        .then(CredMeta::default)
}

/// Store `p` as `name`. Caller holds the lock.
fn write(
    uid: u32,
    username: &str,
    name: &str,
    p: &Payload,
    (sealed, fresh): (bool, bool),
) -> Result<Vec<String>, String> {
    let item = super::bundle::Item {
        name: name.to_string(),
        value: p.value.as_str().into(),
        meta: p.meta.clone(),
        history: vec![],
        files: vec![],
    };
    if !sealed {
        return import::apply(uid, username, name, &item, fresh);
    }
    let provider =
        kepr_core::providers::detect(Some(name), p.value.as_str()).ok_or("no known provider")?;
    let flags = SetFlags {
        ttl_secs: p
            .meta
            .expires_at_unix
            .map(|t| t.saturating_sub(now_unix()).max(1)),
        sealed: Some(true),
        bindings: Some(vec![provider.binding()]),
        ..Default::default()
    };
    if let Response::Err { error } =
        handle_set(uid, username, name, Some(p.value.as_str()), None, flags)
    {
        return Err(error);
    }
    let req = StoreRequest::Organize {
        name: name.to_string(),
        add_tags: p.meta.tags.clone().unwrap_or_default(),
        remove_tags: vec![],
        folder: p.meta.folder.clone(),
    };
    Ok(match crate::daemon_store::dispatch(uid, 0, username, req) {
        Response::Err { error } => vec![format!("tags: {error}")],
        _ => vec![],
    })
}

pub struct ImportArgs<'a> {
    pub upload: &'a str,
    pub overwrite: bool,
    pub apply: bool,
    pub start: u32,
}

fn open(uid: u32, upload: &str) -> Result<(ShareSecret, Opened), String> {
    let bytes = transfer::upload_bytes(uid, upload)?;
    let me = crate::daemon_share::load_secret(uid)?;
    let opened = folder_bundle::open(&me, &bytes, pinned(uid))?;
    Ok((me, opened))
}

/// The whole import refused: drop the upload, audit why.
fn refuse(uid: u32, username: &str, upload: &str, e: String) -> Response {
    transfer::drop_upload(uid, upload);
    audit_r::<()>("folder-import", uid, username, None, &Err(e.clone()));
    Response::fail(e)
}

pub fn handle_import(who: (u32, i32), username: &str, a: ImportArgs) -> Response {
    let uid = who.0;
    let (me, b) = match open(uid, a.upload) {
        Ok(x) => x,
        Err(e) => return refuse(uid, username, a.upload, e),
    };
    let Ok(_g) = folder_state::LOCK.lock() else {
        return Response::fail("import lock poisoned");
    };
    let mut st = State::load(uid);
    if let Err(e) = st.check_fresh(&b) {
        return refuse(uid, username, a.upload, e);
    }
    if a.apply {
        st.saw(&b.id, b.at);
    }
    let key = fp_key(&me);
    let (started, total) = (Instant::now(), b.items.len());
    let (mut rows, mut unchanged, mut i) = (Vec::new(), 0u32, a.start as usize);
    while i < total && rows.len() < MAX_REPORT_ROWS && started.elapsed() < ROUND_TIME {
        let (raw, p) = &b.items[i];
        i += 1;
        let name = match import::local_name(None, raw) {
            Ok(n) if !b.items[..i - 1].iter().any(|(o, _)| o == raw) => n,
            Ok(n) => {
                rows.push(row(&n, "skipped", Some("appears more than once".into())));
                continue;
            }
            Err(e) => {
                rows.push(row(raw, "skipped", Some(e)));
                continue;
            }
        };
        let _lock = crate::daemon_credlock::lock(uid, &name);
        let fp = fingerprint(&key, &name, p, b.sealed);
        let recorded = st.records.get(&b.id).and_then(|f| f.get(&name));
        let (change, reason) = plan(
            who,
            username,
            (&name, p, b.sealed),
            (recorded, &fp, a.overwrite),
        );
        if change == "unchanged" {
            unchanged += 1;
            continue;
        }
        if !a.apply || change == "skipped" {
            rows.push(row(&name, change, reason));
            continue;
        }
        let r = write(uid, username, &name, p, (b.sealed, change == "create"))
            .and_then(|notes| Ok((notes, folder_state::mark(uid, &name)?)));
        audit_r(
            "folder-import",
            uid,
            username,
            Some(&name),
            &r.as_ref().map(drop).map_err(Clone::clone),
        );
        if let Ok((_, mark)) = &r {
            let rec = Record {
                fp,
                mark: mark.clone(),
            };
            st.records
                .entry(b.id.clone())
                .or_default()
                .insert(name.clone(), rec);
        }
        rows.push(match r {
            Ok((notes, _)) => row(&name, change, (!notes.is_empty()).then(|| notes.join("; "))),
            Err(e) => row(&name, "failed", Some(e)),
        });
    }
    if a.apply {
        if let Err(e) = st.save(uid) {
            return Response::fail(e);
        }
    }
    let next = (i < total).then(|| u32::try_from(i).unwrap_or(u32::MAX));
    if next.is_none() {
        transfer::drop_upload(uid, a.upload);
        audit_r::<()>("folder-import", uid, username, None, &Ok(()));
    }
    SyncxResponse::FolderImported {
        from: b.contact,
        folder: b.folder,
        sealed: b.sealed,
        applied: a.apply,
        rows,
        unchanged,
        next,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;
    use base64::Engine;
    use kepr_core::protocol_syncx::{BundleOmitted, BundleRow, SyncxRequest, BUNDLE_CHUNK_BYTES};

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    fn call(uid: u32, r: SyncxRequest) -> Response {
        super::super::dispatch(uid, 0, "t", r)
    }

    /// A user with a share key.
    fn user() -> u32 {
        let uid = testkit::uid();
        assert!(crate::daemon_share::handle_key(uid, "t", true).is_success());
        uid
    }

    fn public(uid: u32) -> String {
        crate::daemon_share::load_secret(uid)
            .unwrap()
            .recipient()
            .text()
    }

    fn pin(on: u32, name: &str, who: u32) {
        assert!(contacts::handle_add(on, "t", name, &public(who)).is_success());
    }

    fn file(uid: u32, name: &str, value: &str, folder: &str) {
        testkit::set(uid, name, value);
        let req = StoreRequest::Organize {
            name: name.into(),
            add_tags: vec![],
            remove_tags: vec![],
            folder: Some(folder.into()),
        };
        assert!(crate::daemon_store::dispatch(uid, 0, "t", req).is_success());
    }

    fn export(
        uid: u32,
        folder: &str,
        to: &[&str],
        sealed: bool,
    ) -> Result<(Vec<u8>, Vec<BundleOmitted>), String> {
        let req = SyncxRequest::FolderExport {
            folder: folder.into(),
            recipients: to.iter().map(|s| s.to_string()).collect(),
            sealed,
        };
        let (id, chunks, omitted) = match call(uid, req) {
            Response::Syncx(SyncxResponse::BundleReady {
                id,
                chunks,
                omitted,
                ..
            }) => (id, chunks, omitted),
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
        Ok((out, omitted))
    }

    /// Upload and import `bytes` (all rounds): (from, rows, unchanged).
    fn import(
        uid: u32,
        bytes: &[u8],
        overwrite: bool,
    ) -> Result<(String, Vec<BundleRow>, u32), String> {
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
        let (upload, mut rows, mut start, mut unchanged) = (upload.unwrap(), Vec::new(), 0, 0);
        loop {
            let req = SyncxRequest::FolderImport {
                upload: upload.clone(),
                overwrite,
                apply: true,
                start,
            };
            match call(uid, req) {
                Response::Syncx(SyncxResponse::FolderImported {
                    from,
                    rows: r,
                    unchanged: u,
                    next,
                    ..
                }) => {
                    rows.extend(r);
                    unchanged += u;
                    match next {
                        Some(n) => start = n,
                        None => return Ok((from, rows, unchanged)),
                    }
                }
                Response::Err { error } => return Err(error),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn two_recipients_import_it_and_a_third_cannot() {
        let (a, b, c, d) = (user(), user(), user(), user());
        file(a, "FS_ONE", "one", "team/api");
        file(a, "FS_TWO", "two", "team");
        file(a, "FS_OUT", "out", "personal");
        pin(a, "bob", b);
        pin(a, "carol", c);
        let (bytes, _) = export(a, "/team/", &["bob", "carol", "bob"], false).unwrap();
        for (me, _) in [(b, "bob"), (c, "carol")] {
            pin(me, "alice", a);
            let (from, rows, _) = import(me, &bytes, false).unwrap();
            assert_eq!(from, "alice");
            assert_eq!(rows.len(), 2, "{rows:?}");
            assert!(rows.iter().all(|r| r.change == "create"));
            assert_eq!(testkit::value(me, "FS_ONE").as_deref(), Some("one"));
            assert_eq!(
                testkit::meta(me, "FS_ONE").folder.as_deref(),
                Some("team/api")
            );
            assert!(!cred_exists(me, "FS_OUT"));
        }
        pin(d, "alice", a);
        assert_eq!(
            import(d, &bytes, false).unwrap_err(),
            "not encrypted to your share key"
        );
        assert!(!cred_exists(d, "FS_ONE"));
    }

    #[test]
    fn a_modified_bundle_or_an_unpinned_sender_is_refused() {
        let (a, b) = (user(), user());
        file(a, "FM_ONE", "one", "shared");
        let (bytes, _) = export(a, "shared", &[&public(b)], false).unwrap();
        let e = import(b, &bytes, false).unwrap_err();
        assert!(e.contains("haven't pinned"), "{e}");
        pin(b, "alice", a);
        let mut bad = bytes.clone();
        let at = bad.windows(6).position(|w| w == b"FM_ONE").unwrap();
        bad[at + 5] = b'X';
        assert_eq!(
            import(b, &bad, false).unwrap_err(),
            folder_bundle::BAD_SIGNATURE
        );
        assert!(!cred_exists(b, "FM_ONE") && !cred_exists(b, "FM_ONX"));
    }

    #[test]
    fn reimport_updates_only_changed_values() {
        let (a, b) = (user(), user());
        file(a, "FR_ONE", "one", "f");
        file(a, "FR_TWO", "two", "f");
        pin(a, "bob", b);
        pin(b, "alice", a);
        import(b, &export(a, "f", &["bob"], false).unwrap().0, false).unwrap();
        testkit::set(a, "FR_TWO", "two-b");
        let (_, rows, unchanged) =
            import(b, &export(a, "f", &["bob"], false).unwrap().0, false).unwrap();
        assert_eq!(unchanged, 1);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(
            (rows[0].name.as_str(), rows[0].change.as_str()),
            ("FR_TWO", "update")
        );
        assert_eq!(testkit::value(b, "FR_TWO").as_deref(), Some("two-b"));
        // A name b had before, not from this folder: left alone.
        testkit::set(b, "FR_MINE", "mine");
        file(a, "FR_MINE", "theirs", "f");
        let (_, rows, _) = import(b, &export(a, "f", &["bob"], false).unwrap().0, false).unwrap();
        assert!(
            rows.iter()
                .any(|r| r.name == "FR_MINE" && r.change == "skipped"),
            "{rows:?}"
        );
        assert_eq!(testkit::value(b, "FR_MINE").as_deref(), Some("mine"));
    }

    #[test]
    fn sealed_folders_store_sealed_and_secrets_that_never_leave_stay_out() {
        let (a, b) = (user(), user());
        file(
            a,
            "FX_OPENAI",
            "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
            "x",
        );
        file(a, "FX_PLAIN", "not-a-provider-key", "x");
        testkit::set_sealed(a, "FX_SEALED", "sealed-secret");
        let req = StoreRequest::Organize {
            name: "FX_SEALED".into(),
            add_tags: vec![],
            remove_tags: vec![],
            folder: Some("x".into()),
        };
        assert!(crate::daemon_store::dispatch(a, 0, "t", req).is_success());
        pin(a, "bob", b);
        pin(b, "alice", a);
        let (bytes, omitted) = export(a, "x", &["bob"], true).unwrap();
        assert!(omitted
            .iter()
            .any(|o| o.name == "FX_SEALED" && o.omitted == "sealed"));
        assert!(!String::from_utf8_lossy(&bytes).contains("FX_SEALED"));
        let (_, rows, _) = import(b, &bytes, false).unwrap();
        assert!(
            rows.iter()
                .any(|r| r.name == "FX_OPENAI" && r.change == "create"),
            "{rows:?}"
        );
        assert!(
            rows.iter()
                .any(|r| r.name == "FX_PLAIN" && r.change == "skipped"),
            "{rows:?}"
        );
        assert_eq!(testkit::meta(b, "FX_OPENAI").sealed, Some(true));
        assert!(!cred_exists(b, "FX_PLAIN"));
        // A plain folder never replaces a sealed credential.
        testkit::set_sealed(b, "FX_PLAIN", "kept");
        let (bytes, _) = export(a, "x", &["bob"], false).unwrap();
        let (_, rows, _) = import(b, &bytes, true).unwrap();
        assert!(
            rows.iter()
                .any(|r| r.name == "FX_PLAIN" && r.change == "skipped"),
            "{rows:?}"
        );
        assert_eq!(testkit::value(b, "FX_PLAIN").as_deref(), Some("kept"));
        assert!(export(a, "/", &["bob"], false)
            .unwrap_err()
            .contains("name a folder"));
    }

    /// Security review (T6.02): whoever controls the shared path can put
    /// back an older signed bundle; it must not roll values back.
    #[test]
    fn an_older_bundle_of_a_folder_is_refused() {
        let (a, b) = (user(), user());
        file(a, "FR_KEY", "v1-compromised", "f");
        pin(a, "bob", b);
        pin(b, "alice", a);
        let old = export(a, "f", &["bob"], false).unwrap().0;
        import(b, &old, false).unwrap();
        testkit::set(a, "FR_KEY", "v2-rotated");
        let new = export(a, "f", &["bob"], false).unwrap().0;
        import(b, &new, false).unwrap();
        assert_eq!(testkit::value(b, "FR_KEY").as_deref(), Some("v2-rotated"));
        let e = import(b, &old, false).unwrap_err();
        assert!(e.contains("older"), "{e}");
        assert_eq!(testkit::value(b, "FR_KEY").as_deref(), Some("v2-rotated"));
        // The newest one again is fine (nothing changed).
        let (_, rows, unchanged) = import(b, &new, false).unwrap();
        assert!(rows.is_empty() && unchanged == 1, "{rows:?}");
    }

    fn skipped(rows: &[BundleRow], name: &str) -> bool {
        rows.iter().any(|r| r.name == name && r.change == "skipped")
    }

    /// Security review (T6.02): a credential deleted and made again here
    /// is the user's own, so a later import must not overwrite it (and
    /// drop its consent gate); a gated one is never updated either, unless
    /// --overwrite says so.
    #[test]
    fn a_recreated_or_gated_credential_is_not_overwritten() {
        use crate::daemon_handlers::handle_delete;
        let (a, b) = (user(), user());
        let names = ["FG_GATED", "FG_PLAIN", "FG_QUORUM"];
        for n in names {
            file(a, n, "from-alice", "f");
        }
        pin(a, "bob", b);
        pin(b, "alice", a);
        import(b, &export(a, "f", &["bob"], false).unwrap().0, false).unwrap();
        for n in ["FG_GATED", "FG_PLAIN"] {
            assert!(handle_delete(b, "t", n).is_success());
        }
        let consent = SetFlags {
            requires_consent: Some(true),
            ..Default::default()
        };
        assert!(handle_set(b, "t", "FG_GATED", Some("bobs-own"), None, consent).is_success());
        let plain = SetFlags::default();
        assert!(handle_set(b, "t", "FG_PLAIN", Some("bobs-own"), None, plain).is_success());
        let q = super::super::quorum_cmd::handle_set(b, "t", "FG_QUORUM", 2, now_unix());
        assert!(q.is_success(), "{q:?}");
        for n in names {
            testkit::set(a, n, "alice-new");
        }
        let bundle = export(a, "f", &["bob"], false).unwrap().0;
        let (_, rows, _) = import(b, &bundle, false).unwrap();
        for n in names {
            assert!(skipped(&rows, n), "{n}: {rows:?}");
        }
        assert_eq!(testkit::value(b, "FG_GATED").as_deref(), Some("bobs-own"));
        assert_eq!(testkit::meta(b, "FG_GATED").requires_consent, Some(true));
        assert_eq!(testkit::value(b, "FG_PLAIN").as_deref(), Some("bobs-own"));
        assert_eq!(
            testkit::value(b, "FG_QUORUM").as_deref(),
            Some("from-alice")
        );
        // --overwrite is the explicit way.
        let (_, rows, _) = import(b, &bundle, true).unwrap();
        assert!(!skipped(&rows, "FG_PLAIN"), "{rows:?}");
        assert_eq!(testkit::value(b, "FG_PLAIN").as_deref(), Some("alice-new"));
    }
}
