// daemon_syncx/export.rs — T6.09 `kepr export --encrypted -o FILE`.
//
// Builds a bundle body of every credential the caller could read with
// `get` right now that nothing else guards: value, record type, tags,
// folder, expiry, earlier values and attachments. Everything else is
// listed by name with the reason it was left out (`CredMeta::gated`; the
// same gate decides what sync (T6.10) and folder bundles (T6.02) carry):
//
//   sealed / ssh / share_key   never readable (no new path may return one)
//   consent / fido2            needs a prompt or a key per credential
//   reauth                     re-auth window is for `get`, not copies
//   view_window                a received share whose window has not run
//   exe_bound                  only the bound programs may read it (T10.09)
//   approvals                  M-of-N approvals; a window is for `get` (T7.12)
//   expired / policy / unreadable / size
//
// The body is encrypted under the caller's passphrase (bundle.rs) and the
// ciphertext waits in transfer.rs for the CLI to fetch.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_records::{AttachInfo, RecordsRequest, RecordsResponse};
use kepr_core::protocol_syncx::{BundleOmitted, SyncxResponse, MAX_BUNDLE_BYTES, MAX_REPORT_ROWS};

use super::bundle::{self, Body, File, Item, ItemMeta, HEADER_ROOM};
use super::{audit_r, transfer};
use crate::expiry::{self, now_unix, CredMeta};
use crate::store::{cred_path, validate_name};

/// The credential's meta, if `uid` may read `upper` now with no prompt:
/// the export gate, also what import asks before comparing values.
/// Caller holds the credential's lock.
pub(super) fn readable(
    (uid, peer_pid): (u32, i32),
    username: &str,
    upper: &str,
) -> Result<CredMeta, &'static str> {
    let meta = match expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))) {
        None => CredMeta::default(),
        Some(Ok(m)) => m,
        Some(Err(_)) => return Err("unreadable"),
    };
    if let Some(why) = meta.gated() {
        return Err(why);
    }
    // T6.11: the policy file decides as for `get` (op `export` when the
    // caller is `kepr export`).
    let probe = Request::Get {
        name: upper.to_string(),
        fido2_assertion: None,
    };
    if crate::daemon_policy::enforce(uid, peer_pid, username, &probe).is_some() {
        return Err("policy");
    }
    // Get's own gate (expiry, another uid's checkout). Everything that
    // prompts was refused above, so it never prompts.
    crate::daemon_handlers_get::precheck_meta(uid, peer_pid, upper).map_err(|e| {
        match e.as_str() {
            "expired" => "expired",
            _ => "unreadable",
        }
    })?;
    Ok(meta)
}

/// The `.meta` fields a bundle carries.
pub(super) fn item_meta(meta: &CredMeta) -> ItemMeta {
    ItemMeta {
        record_type: meta.record_type.clone(),
        tags: meta.tags.clone(),
        folder: meta.folder.clone(),
        expires_at_unix: meta.expires_at_unix,
        requires_reauth: meta.requires_reauth,
    }
}

/// An attachment's bytes as base64: its stored chunks' base64, joined
/// (every chunk but the last is a multiple of 3 bytes, so the joined
/// text is the whole file's base64).
fn read_file(uid: u32, username: &str, upper: &str, info: &AttachInfo) -> Option<ZeroString> {
    // Exact capacity: the String never reallocates (no stray copies).
    let mut out = String::with_capacity((info.size as usize).div_ceil(3) * 4 + 4);
    for index in 0..info.chunks() {
        let req = RecordsRequest::AttachGet {
            name: upper.to_string(),
            file: info.file.clone(),
            index,
        };
        match crate::daemon_recordsx::dispatch(uid, 0, username, req) {
            Response::Records(RecordsResponse::AttachChunkOk { data, .. }) => {
                out.push_str(data.as_str())
            }
            _ => {
                drop(ZeroString::from_string(out));
                return None;
            }
        }
    }
    Some(ZeroString::from_string(out))
}

/// `upper`'s bundle entry within `room` bytes, plus attachments left
/// out; or why the whole credential is left out.
fn read_item(
    who: (u32, i32),
    username: &str,
    upper: &str,
    room: usize,
) -> Result<(Item, Vec<BundleOmitted>), &'static str> {
    let uid = who.0;
    let _lock = crate::daemon_credlock::lock(uid, upper);
    let meta = readable(who, username, upper)?;
    let value = crate::crypto::default_backend()
        .decrypt(uid, upper)
        .map_err(|_| "unreadable")?;
    let mut item = Item {
        name: upper.to_string(),
        value,
        meta: item_meta(&meta),
        history: crate::daemon_history::export_versions(uid, upper),
        files: Vec::new(),
    };
    if item.weight() > room {
        return Err("size");
    }
    let mut left_out = Vec::new();
    for info in meta.attachments.iter().flatten() {
        let mut leave = |why: &str| {
            left_out.push(BundleOmitted {
                name: format!("{upper}/{}", info.file),
                omitted: why.into(),
            })
        };
        if item.weight() + (info.size as usize).div_ceil(3) * 4 + info.file.len() > room {
            leave("size");
            continue;
        }
        match read_file(uid, username, upper, info) {
            Some(data) => item.files.push(File {
                file: info.file.clone(),
                data,
            }),
            None => leave("unreadable"),
        }
    }
    Ok((item, left_out))
}

/// Every credential of `uid` as a bundle body.
pub(super) fn collect(who: (u32, i32), username: &str) -> Body {
    let mut body = Body {
        created: now_unix(),
        ..Default::default()
    };
    let mut used = 0usize;
    for (name, _) in crate::store::list_for_uid(who.0) {
        if validate_name(&name).is_err() {
            continue;
        }
        let room = (MAX_BUNDLE_BYTES - HEADER_ROOM).saturating_sub(used);
        match read_item(who, username, &name, room) {
            Ok((item, left_out)) => {
                used += item.weight();
                body.items.push(item);
                body.omitted.extend(left_out);
            }
            Err(why) => body.omitted.push(BundleOmitted {
                name,
                omitted: why.into(),
            }),
        }
    }
    body
}

pub fn handle_export(who: (u32, i32), username: &str, passphrase: &ZeroString) -> Response {
    let uid = who.0;
    let r = (|| {
        if passphrase.len() < bundle::MIN_PASSPHRASE {
            return Err(format!(
                "the bundle passphrase must be at least {} characters",
                bundle::MIN_PASSPHRASE
            ));
        }
        let body = collect(who, username);
        let bytes = bundle::seal(&body, passphrase.as_bytes())?;
        let size = bytes.len() as u64;
        let (id, chunks) = transfer::put_export(uid, bytes, now_unix())?;
        Ok((id, size, chunks, body))
    })();
    audit_r("bundle-export", uid, username, None, &r);
    let (id, size, chunks, body) = match r {
        Ok(x) => x,
        Err(e) => return Response::fail(e),
    };
    for item in &body.items {
        audit_r("bundle-export", uid, username, Some(&item.name), &Ok(()));
    }
    let omitted_count = u32::try_from(body.omitted.len()).unwrap_or(u32::MAX);
    let mut omitted = body.omitted;
    omitted.truncate(MAX_REPORT_ROWS);
    SyncxResponse::BundleReady {
        id,
        size,
        chunks,
        items: u32::try_from(body.items.len()).unwrap_or(u32::MAX),
        omitted,
        omitted_count,
    }
    .into()
}
