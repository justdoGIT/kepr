// daemon_syncx/import.rs — T6.09 `kepr import BUNDLE`: open an uploaded
// bundle with its passphrase and store what it carries.
//
// Per credential: `create` (new name: earlier values, value, meta,
// attachments), `update` (exists, differs, --overwrite: the old value goes
// to history as with any `set`), `unchanged`, or `skipped`. Values are
// compared only when the caller could read the existing one without a
// prompt (export.rs `readable`), so an import can't test guesses against a
// consent- or FIDO2-gated value. A sealed, SSH or share-key credential is
// never replaced. Every write is checked against the policy file as a
// `set`. A round stops after ROUND_TIME or a full reply; the CLI asks again
// from `next` (the bundle is opened again each round; no plaintext waits).

use std::time::{Duration, Instant};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_records::{RecordsRequest, RecordsResponse, CHUNK_BYTES};
use kepr_core::protocol_store::StoreRequest;
use kepr_core::protocol_syncx::{BundleRow, SyncxResponse, MAX_REPORT_ROWS};

use super::bundle::{self, File, Item};
use super::{audit_r, export::readable, transfer};
use crate::daemon_handlers::{handle_set, SetFlags};
use crate::expiry::now_unix;
use crate::store::{cred_exists, validate_name};

pub(super) const ROUND_TIME: Duration = Duration::from_secs(4);

pub struct Args<'a> {
    pub upload: &'a str,
    pub passphrase: &'a ZeroString,
    pub prefix: Option<&'a str>,
    pub overwrite: bool,
    pub apply: bool,
    pub start: u32,
}

/// The local name of bundle entry `name`.
fn local_name(prefix: Option<&str>, name: &str) -> Result<String, String> {
    let n = match prefix {
        Some(p) => format!("{}_{name}", p.to_uppercase()),
        None => name.to_uppercase(),
    };
    validate_name(&n)?;
    if n == crate::daemon_share::KEY_NAME {
        return Err("this name is reserved".into());
    }
    Ok(n)
}

/// Equal lengths and bytes, in time independent of where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Would the policy file (T6.11) let the caller `set` `name`?
pub(super) fn set_allowed(
    who: (u32, i32),
    username: &str,
    name: &str,
    expires: Option<u64>,
) -> bool {
    let probe = Request::Set {
        name: name.to_string(),
        value: None,
        generate: None,
        ttl_secs: expires.map(|t| t.saturating_sub(now_unix())),
        requires_consent: None,
        requires_fido2: None,
        sealed: None,
        bindings: None,
    };
    crate::daemon_policy::enforce(who.0, who.1, username, &probe).is_none()
}

/// What importing `item` as `name` would do now. Caller holds the lock.
fn plan(
    who: (u32, i32),
    username: &str,
    (name, item): (&str, &Item),
    overwrite: bool,
) -> (&'static str, Option<String>) {
    let uid = who.0;
    if item.meta.expires_at_unix.is_some_and(|t| t <= now_unix()) {
        return ("skipped", Some("expired".into()));
    }
    if !set_allowed(who, username, name, item.meta.expires_at_unix) {
        return ("skipped", Some("denied by policy".into()));
    }
    if !cred_exists(uid, name) {
        return ("create", None);
    }
    match readable(who, username, name) {
        Err("sealed" | "ssh" | "share_key") => {
            return (
                "skipped",
                Some("a sealed or sign-only credential has this name".into()),
            )
        }
        Ok(_) => {
            let current = crate::crypto::default_backend().decrypt(uid, name);
            if current.is_ok_and(|v| same(v.as_bytes(), item.value.as_bytes())) {
                return ("unchanged", None);
            }
        }
        Err(_) => {}
    }
    if overwrite {
        ("update", None)
    } else {
        ("skipped", Some("already in kepr (use --overwrite)".into()))
    }
}

/// Store one attachment through the attachment handler, chunk by chunk.
fn put_file(uid: u32, username: &str, name: &str, f: &File) -> Result<(), String> {
    let text = f.data.as_str();
    if !text.is_ascii() {
        return Err(format!("attachment {} is damaged", f.file));
    }
    // CHUNK_BYTES is a multiple of 3: one stored chunk is this much base64.
    let pieces: Vec<&[u8]> = match text.len() {
        0 => vec![&[]],
        _ => text.as_bytes().chunks(CHUNK_BYTES / 3 * 4).collect(),
    };
    let mut upload = None;
    for (i, piece) in pieces.iter().enumerate() {
        let req = RecordsRequest::AttachPut {
            name: name.to_string(),
            file: f.file.clone(),
            upload: upload.take(),
            index: i as u32,
            chunk: ZeroString::from(std::str::from_utf8(piece).unwrap_or_default()),
            last: i + 1 == pieces.len(),
        };
        match crate::daemon_recordsx::dispatch(uid, 0, username, req) {
            Response::Records(RecordsResponse::AttachPutOk { done: true, .. }) => return Ok(()),
            Response::Records(RecordsResponse::AttachPutOk { upload: u, .. }) => upload = Some(u),
            Response::Err { error } => return Err(format!("attachment {}: {error}", f.file)),
            _ => break,
        }
    }
    Err(format!("attachment {} was not stored", f.file))
}

/// Write `item` as `name` (`fresh`: it doesn't exist yet). Returns notes
/// on parts that didn't apply. Caller holds the credential's lock.
pub(super) fn apply(
    uid: u32,
    username: &str,
    name: &str,
    item: &Item,
    fresh: bool,
) -> Result<Vec<String>, String> {
    if fresh {
        for v in &item.history {
            crate::daemon_history::import_version(uid, name, v.as_str())?;
        }
    }
    let flags = SetFlags {
        ttl_secs: item
            .meta
            .expires_at_unix
            .map(|t| t.saturating_sub(now_unix()).max(1)),
        record_type: item.meta.record_type.clone(),
        ..Default::default()
    };
    if let Response::Err { error } =
        handle_set(uid, username, name, Some(item.value.as_str()), None, flags)
    {
        if fresh {
            crate::daemon_history::purge(uid, name);
        }
        return Err(error);
    }
    let mut notes = Vec::new();
    let m = &item.meta;
    if m.tags.is_some() || m.folder.is_some() {
        let req = StoreRequest::Organize {
            name: name.to_string(),
            add_tags: m.tags.clone().unwrap_or_default(),
            remove_tags: vec![],
            folder: m.folder.clone(),
        };
        if let Response::Err { error } = crate::daemon_store::dispatch(uid, 0, username, req) {
            notes.push(format!("tags: {error}"));
        }
    }
    if m.requires_reauth == Some(true) {
        let r = crate::daemon_session::reauth::handle_flag(uid, username, name, true);
        if let Response::Err { error } = r {
            notes.push(format!("re-auth flag: {error}"));
        }
    }
    for f in &item.files {
        if let Err(e) = put_file(uid, username, name, f) {
            notes.push(e);
        }
    }
    Ok(notes)
}

fn row(name: &str, change: &str, reason: Option<String>) -> BundleRow {
    BundleRow {
        name: name.to_string(),
        change: change.to_string(),
        reason,
    }
}

pub fn handle_import(who: (u32, i32), username: &str, a: Args) -> Response {
    let uid = who.0;
    let body = transfer::upload_bytes(uid, a.upload)
        .and_then(|bytes| bundle::open(&bytes, a.passphrase.as_bytes()));
    let body = match body {
        Ok(b) => b,
        Err(e) => {
            transfer::drop_upload(uid, a.upload);
            audit_r::<()>("bundle-import", uid, username, None, &Err(e.clone()));
            return Response::fail(e);
        }
    };
    let (started, total) = (Instant::now(), body.items.len() + body.omitted.len());
    let (mut rows, mut unchanged, mut i) = (Vec::new(), 0u32, a.start as usize);
    while i < total && rows.len() < MAX_REPORT_ROWS && started.elapsed() < ROUND_TIME {
        let Some(item) = body.items.get(i) else {
            let o = &body.omitted[i - body.items.len()];
            rows.push(row(&o.name, "omitted", Some(o.omitted.clone())));
            i += 1;
            continue;
        };
        i += 1;
        let name = match local_name(a.prefix, &item.name) {
            Ok(n) => n,
            Err(e) => {
                rows.push(row(&item.name, "skipped", Some(e)));
                continue;
            }
        };
        if body.items[..i - 1].iter().any(|o| o.name == item.name) {
            rows.push(row(&name, "skipped", Some("appears more than once".into())));
            continue;
        }
        let _lock = crate::daemon_credlock::lock(uid, &name);
        let (change, reason) = plan(who, username, (&name, item), a.overwrite);
        if change == "unchanged" {
            unchanged += 1;
            continue;
        }
        if !a.apply || change == "skipped" {
            rows.push(row(&name, change, reason));
            continue;
        }
        let r = apply(uid, username, &name, item, change == "create");
        audit_r(
            "bundle-import",
            uid,
            username,
            Some(&name),
            &r.as_ref().map(drop).map_err(Clone::clone),
        );
        rows.push(match r {
            Ok(notes) if notes.is_empty() => row(&name, change, None),
            Ok(notes) => row(&name, change, Some(notes.join("; "))),
            Err(e) => row(&name, "failed", Some(e)),
        });
    }
    let next = (i < total).then(|| u32::try_from(i).unwrap_or(u32::MAX));
    if next.is_none() {
        transfer::drop_upload(uid, a.upload);
    }
    SyncxResponse::BundleImported {
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
    use kepr_core::protocol_syncx::{SyncxRequest, BUNDLE_CHUNK_BYTES};

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    const PASS: &str = "bundle passphrase 1";

    fn call(uid: u32, r: SyncxRequest) -> Response {
        super::super::dispatch(uid, 0, "t", r)
    }

    fn export_bytes(uid: u32) -> (Vec<u8>, Vec<(String, String)>) {
        let r = call(
            uid,
            SyncxRequest::ExportBundle {
                passphrase: PASS.into(),
            },
        );
        let Response::Syncx(SyncxResponse::BundleReady {
            id,
            size,
            chunks,
            omitted,
            ..
        }) = r
        else {
            panic!("export: {r:?}");
        };
        let mut bytes = Vec::new();
        for index in 0..chunks {
            let r = call(
                uid,
                SyncxRequest::ExportChunk {
                    id: id.clone(),
                    index,
                },
            );
            let Response::Syncx(SyncxResponse::BundleChunk { data, .. }) = r else {
                panic!("chunk: {r:?}");
            };
            bytes.extend(B64.decode(data).unwrap());
        }
        assert_eq!(bytes.len() as u64, size);
        (
            bytes,
            omitted.into_iter().map(|o| (o.name, o.omitted)).collect(),
        )
    }

    fn upload(uid: u32, bytes: &[u8]) -> String {
        let parts: Vec<&[u8]> = bytes.chunks(BUNDLE_CHUNK_BYTES).collect();
        let mut upload = None;
        for (i, c) in parts.iter().enumerate() {
            let r = call(
                uid,
                SyncxRequest::ImportPut {
                    upload: upload.clone(),
                    index: i as u32,
                    chunk: B64.encode(c),
                    last: i + 1 == parts.len(),
                },
            );
            let Response::Syncx(SyncxResponse::ImportPutOk { upload: u, .. }) = r else {
                panic!("put: {r:?}");
            };
            upload = Some(u);
        }
        upload.unwrap()
    }

    /// Every row of a whole import (all rounds), and the unchanged count.
    fn import(
        uid: u32,
        bytes: &[u8],
        pass: &str,
        flags: (Option<&str>, bool, bool),
    ) -> Result<(Vec<BundleRow>, u32), String> {
        let id = upload(uid, bytes);
        let (mut rows, mut unchanged, mut start) = (Vec::new(), 0, 0);
        loop {
            let r = call(
                uid,
                SyncxRequest::ImportBundle {
                    upload: id.clone(),
                    passphrase: pass.into(),
                    prefix: flags.0.map(String::from),
                    overwrite: flags.1,
                    apply: flags.2,
                    start,
                },
            );
            match r {
                Response::Syncx(SyncxResponse::BundleImported {
                    rows: r,
                    unchanged: u,
                    next,
                    ..
                }) => {
                    rows.extend(r);
                    unchanged += u;
                    match next {
                        Some(n) => start = n,
                        None => return Ok((rows, unchanged)),
                    }
                }
                Response::Err { error } => return Err(error),
                other => panic!("import: {other:?}"),
            }
        }
    }

    fn change(rows: &[BundleRow], name: &str) -> String {
        let r = rows
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("{name}: {rows:?}"));
        match &r.reason {
            Some(why) => format!("{} ({why})", r.change),
            None => r.change.clone(),
        }
    }

    fn attach(uid: u32, name: &str, file: &str, data: &[u8]) {
        let req = RecordsRequest::AttachPut {
            name: name.into(),
            file: file.into(),
            upload: None,
            index: 0,
            chunk: B64.encode(data).into(),
            last: true,
        };
        let r = crate::daemon_recordsx::dispatch(uid, 0, "t", req);
        assert!(r.is_success(), "{r:?}");
    }

    fn attachment(uid: u32, name: &str, file: &str) -> Vec<u8> {
        let req = RecordsRequest::AttachGet {
            name: name.into(),
            file: file.into(),
            index: 0,
        };
        match crate::daemon_recordsx::dispatch(uid, 0, "t", req) {
            Response::Records(RecordsResponse::AttachChunkOk { data, .. }) => {
                B64.decode(data.as_bytes()).unwrap()
            }
            other => panic!("{other:?}"),
        }
    }

    fn set_with(uid: u32, name: &str, value: &str, flags: SetFlags) {
        assert!(handle_set(uid, "t", name, Some(value), None, flags).is_success());
    }

    fn organize(uid: u32, name: &str) {
        let req = StoreRequest::Organize {
            name: name.into(),
            add_tags: vec!["work".into()],
            remove_tags: vec![],
            folder: Some("team/a".into()),
        };
        assert!(crate::daemon_store::dispatch(uid, 0, "t", req).is_success());
    }

    /// A store with one of everything an export has to decide about.
    fn source() -> u32 {
        let uid = testkit::uid();
        testkit::set(uid, "BX_API", "first-value");
        testkit::set(uid, "BX_API", "second-value");
        organize(uid, "BX_API");
        attach(uid, "BX_API", "notes.txt", b"attached bytes");
        let record = SetFlags {
            record_type: Some("login".into()),
            ttl_secs: Some(3600),
            ..Default::default()
        };
        set_with(
            uid,
            "BX_LOGIN",
            r#"{"username":"u","password":"p"}"#,
            record,
        );
        testkit::set_sealed(uid, "BX_SEALED", "sealed-secret-xyz");
        let consent = SetFlags {
            requires_consent: Some(true),
            ..Default::default()
        };
        set_with(uid, "BX_ASK", "consent-secret-xyz", consent);
        assert!(crate::daemon_share::handle_key(uid, "t", true).is_success());
        uid
    }

    #[test]
    fn sealed_and_gated_values_never_enter_the_body() {
        let uid = source();
        let body = super::super::export::collect((uid, 0), "t");
        let plain = serde_json::to_string(&body).unwrap();
        assert!(plain.contains("second-value"));
        for secret in ["sealed-secret-xyz", "consent-secret-xyz", "kepr-sk"] {
            assert!(!plain.contains(secret), "{secret} in the body");
        }
        let omitted: Vec<(&str, &str)> = body
            .omitted
            .iter()
            .map(|o| (o.name.as_str(), o.omitted.as_str()))
            .collect();
        assert!(omitted.contains(&("BX_SEALED", "sealed")), "{omitted:?}");
        assert!(omitted.contains(&("BX_ASK", "consent")), "{omitted:?}");
        assert!(
            omitted.contains(&("KEPR_SHARE_KEY", "share_key")),
            "{omitted:?}"
        );
        let names: Vec<&str> = body.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["BX_API", "BX_LOGIN"]);
    }

    #[test]
    fn round_trip_into_another_store() {
        let (bytes, omitted) = export_bytes(source());
        assert!(omitted.contains(&("BX_SEALED".into(), "sealed".into())));
        let to = testkit::uid();
        // Without --yes: a plan, nothing stored.
        let (rows, _) = import(to, &bytes, PASS, (None, false, false)).unwrap();
        assert_eq!(change(&rows, "BX_API"), "create");
        assert!(!cred_exists(to, "BX_API"));

        let (rows, _) = import(to, &bytes, PASS, (None, false, true)).unwrap();
        assert_eq!(change(&rows, "BX_API"), "create");
        assert_eq!(change(&rows, "BX_SEALED"), "omitted (sealed)");
        assert_eq!(change(&rows, "BX_ASK"), "omitted (consent)");
        assert_eq!(change(&rows, "KEPR_SHARE_KEY"), "omitted (share_key)");
        assert_eq!(
            testkit::value(to, "BX_API").as_deref(),
            Some("second-value")
        );
        let (old, sealed) = crate::daemon_history::version_value(to, "BX_API", 1).unwrap();
        assert_eq!((old.as_str(), sealed), ("first-value", false));
        let meta = testkit::meta(to, "BX_API");
        assert_eq!(meta.tags, Some(vec!["work".to_string()]));
        assert_eq!(meta.folder.as_deref(), Some("team/a"));
        assert_eq!(attachment(to, "BX_API", "notes.txt"), b"attached bytes");
        let login = testkit::meta(to, "BX_LOGIN");
        assert_eq!(login.record_type.as_deref(), Some("login"));
        assert!(login.expires_at_unix.is_some_and(|t| t > now_unix()));
        assert!(!cred_exists(to, "BX_SEALED"));

        // Again: everything is unchanged.
        let (rows, unchanged) = import(to, &bytes, PASS, (None, false, true)).unwrap();
        assert_eq!(unchanged, 2);
        assert!(rows.iter().all(|r| r.change == "omitted"), "{rows:?}");
    }

    #[test]
    fn a_wrong_passphrase_is_refused_and_stores_nothing() {
        let (bytes, _) = export_bytes(source());
        let to = testkit::uid();
        let e = import(to, &bytes, "not the passphrase", (None, false, true)).unwrap_err();
        assert_eq!(e, "wrong passphrase or damaged bundle");
        assert!(!cred_exists(to, "BX_API"));
    }

    #[test]
    fn existing_values_need_overwrite_and_sealed_ones_are_never_replaced() {
        let (bytes, _) = export_bytes(source());
        let to = testkit::uid();
        testkit::set(to, "BX_API", "local-value");
        testkit::set_sealed(to, "BX_LOGIN", "local-sealed");
        let (rows, _) = import(to, &bytes, PASS, (None, false, true)).unwrap();
        assert_eq!(
            change(&rows, "BX_API"),
            "skipped (already in kepr (use --overwrite))"
        );
        assert_eq!(testkit::value(to, "BX_API").as_deref(), Some("local-value"));
        let (rows, _) = import(to, &bytes, PASS, (None, true, true)).unwrap();
        assert_eq!(change(&rows, "BX_API"), "update");
        assert_eq!(
            testkit::value(to, "BX_API").as_deref(),
            Some("second-value")
        );
        let (old, _) = crate::daemon_history::version_value(to, "BX_API", 1).unwrap();
        assert_eq!(old.as_str(), "local-value");
        assert!(change(&rows, "BX_LOGIN").starts_with("skipped (a sealed"));
        assert_eq!(testkit::meta(to, "BX_LOGIN").sealed, Some(true));
    }

    #[test]
    fn a_gated_value_is_never_compared_and_prefix_renames() {
        let (bytes, _) = export_bytes(source());
        let to = testkit::uid();
        let consent = SetFlags {
            requires_consent: Some(true),
            ..Default::default()
        };
        set_with(to, "BX_API", "second-value", consent);
        let (rows, unchanged) = import(to, &bytes, PASS, (None, false, false)).unwrap();
        assert_eq!(
            unchanged, 0,
            "an equal gated value must not show as unchanged"
        );
        assert!(change(&rows, "BX_API").starts_with("skipped"));
        let (rows, _) = import(to, &bytes, PASS, (Some("old"), false, true)).unwrap();
        assert_eq!(change(&rows, "OLD_BX_API"), "create");
        assert_eq!(
            testkit::value(to, "OLD_BX_API").as_deref(),
            Some("second-value")
        );
    }
}
