// daemon_syncx/folder.rs — T6.02 shared folders, the export side.
//
//   FolderExport  every credential filed under FOLDER (or below, T5.01)
//                 that `get` could read now, sealed for the recipients
//                 (folder_bundle.rs); the rest are listed by name only, as
//                 for `kepr export`: sealed / SSH / share-key values and
//                 gated ones never go into a bundle
//
// FolderImport is folder_import.rs.

use kepr_core::protocol::Response;
use kepr_core::protocol_syncx::{BundleOmitted, SyncxResponse, MAX_BUNDLE_BYTES, MAX_REPORT_ROWS};

use super::folder_bundle::{self, Payload};
use super::{audit_r, export, transfer};
use crate::daemon_sharing::contacts;
use crate::daemon_sharing::kem::Recipient;
use crate::expiry::{self, now_unix, CredMeta};
use crate::store::{cred_path, validate_name};

const MAX_RECIPIENTS: usize = 64;

pub(super) fn meta_of(uid: u32, name: &str) -> Option<CredMeta> {
    expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, name))).and_then(Result::ok)
}

fn in_folder(meta: Option<&CredMeta>, folder: &str) -> bool {
    meta.and_then(|m| m.folder.as_deref())
        .is_some_and(|f| f == folder || f.strip_prefix(folder).is_some_and(|r| r.starts_with('/')))
}

/// The recipients, each once, from contact names or share keys.
fn recipients(uid: u32, to: &[String]) -> Result<Vec<Recipient>, String> {
    if to.is_empty() || to.len() > MAX_RECIPIENTS {
        return Err(format!(
            "name 1 to {MAX_RECIPIENTS} recipients (--to NAME|KEY)"
        ));
    }
    let mut out: Vec<Recipient> = Vec::new();
    for t in to {
        let (r, _) = contacts::resolve(uid, t)?;
        if !out.iter().any(|o| o.x25519() == r.x25519()) {
            out.push(r);
        }
    }
    Ok(out)
}

fn read_payload(who: (u32, i32), username: &str, name: &str) -> Result<Payload, &'static str> {
    let _lock = crate::daemon_credlock::lock(who.0, name);
    let meta = export::readable(who, username, name)?;
    let value = crate::crypto::default_backend()
        .decrypt(who.0, name)
        .map_err(|_| "unreadable")?;
    Ok(Payload {
        value,
        meta: export::item_meta(&meta),
    })
}

pub fn handle_export(
    who: (u32, i32),
    username: &str,
    folder: &str,
    to: &[String],
    sealed: bool,
) -> Response {
    let uid = who.0;
    let r = (|| {
        let folder = crate::daemon_store::normalize_folder(folder)?
            .ok_or("name a folder (kepr mv KEY FOLDER files a key under one)")?;
        let to = recipients(uid, to)?;
        let me = crate::daemon_share::load_secret(uid)?;
        let (mut items, mut omitted) = (Vec::new(), Vec::new());
        for (name, _) in crate::store::list_for_uid(uid) {
            if validate_name(&name).is_err() || !in_folder(meta_of(uid, &name).as_ref(), &folder) {
                continue;
            }
            match read_payload(who, username, &name) {
                Ok(p) => items.push((name, p)),
                Err(why) => omitted.push(BundleOmitted {
                    name,
                    omitted: why.into(),
                }),
            }
        }
        let id = folder_bundle::folder_id(&me.recipient().text(), &folder);
        let at = super::folder_state::next_at(uid, &id, now_unix())?;
        let bytes = folder_bundle::seal(&me, &to, (&folder, sealed, at), &items)?;
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err("the folder is over 16 MiB as a bundle".into());
        }
        let size = bytes.len() as u64;
        let (id, chunks) = transfer::put_export(uid, bytes, now_unix())?;
        let names: Vec<String> = items.into_iter().map(|(n, _)| n).collect();
        Ok((id, size, chunks, names, omitted))
    })();
    audit_r("folder-share", uid, username, None, &r);
    let (id, size, chunks, names, mut omitted) = match r {
        Ok(x) => x,
        Err(e) => return Response::fail(e),
    };
    for n in &names {
        audit_r("folder-share", uid, username, Some(n), &Ok(()));
    }
    let omitted_count = u32::try_from(omitted.len()).unwrap_or(u32::MAX);
    omitted.truncate(MAX_REPORT_ROWS);
    SyncxResponse::BundleReady {
        id,
        size,
        chunks,
        items: u32::try_from(names.len()).unwrap_or(u32::MAX),
        omitted,
        omitted_count,
    }
    .into()
}
