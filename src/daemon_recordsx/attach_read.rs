// daemon_recordsx/attach_read.rs — T5.03 reading side of attachments:
// `kepr attach get` (one chunk per request, every one audited), `ls` and
// `rm`. Reads follow the credential's policy: nothing for sealed / SSH /
// share-key or expired credentials, (there is no prompt per chunk)
// nothing for consent- or FIDO2-gated ones, and the gates `get` checks
// before any prompt: the executable binding (T10.09, the caller's pid),
// M-of-N approvals (T7.12) and another uid's checkout (T7.11).

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_records::{AttachInfo, RecordsResponse};

use super::attach::{log, no_attachments, owner, read, write};
use super::chunks::{self, chunk_name, slot_of};
use crate::crypto::{self, SANITIZED_LOOKUP_ERROR};
use crate::expiry::{self, CredMeta};
use crate::store::cred_exists;

/// Why `meta`'s attachments can't be read now (audit reason), if so.
fn read_refused(m: &CredMeta) -> Option<&'static str> {
    if no_attachments(m) {
        Some("sealed")
    } else if m.expires_at_unix.is_some_and(|t| expiry::now_unix() >= t) {
        Some("expired")
    } else if m.requires_consent == Some(true) || m.requires_fido2 == Some(true) {
        Some("consent / FIDO2 gated")
    } else {
        None
    }
}

fn find(m: &CredMeta, file: &str) -> Result<(AttachInfo, u32), String> {
    let info = m
        .attachments
        .iter()
        .flatten()
        .find(|i| i.file == file)
        .cloned()
        .ok_or_else(|| format!("no attachment {file:?}"))?;
    let slot = slot_of(&info).ok_or("damaged attachment manifest")?;
    Ok((info, slot))
}

pub fn handle_get(
    (uid, peer_pid): (u32, i32),
    username: &str,
    name: &str,
    file: &str,
    index: u32,
) -> Response {
    let r = owner(uid, name).and_then(|o| {
        let _lock = crate::daemon_credlock::lock(uid, &o);
        get((uid, peer_pid), &o, file, index).map(|x| (o, x))
    });
    let shown = r.as_ref().map_or(name.to_uppercase(), |x| x.0.clone());
    log("attach-get", uid, username, &shown, &r);
    match r {
        Ok((name, (info, data))) => Response::Records(RecordsResponse::AttachChunkOk {
            name,
            file: info.file.clone(),
            index,
            chunks: info.chunks(),
            size: info.size,
            sha256: info.sha256,
            data,
        }),
        Err(e) if e.starts_with("no attachment") || e.contains("chunk") => Response::fail(e),
        Err(e) if e == crate::daemon_session::reauth::NEEDED => Response::fail(e), // T11.14
        Err(_) => Response::fail(SANITIZED_LOOKUP_ERROR),
    }
}

fn get(
    (uid, peer_pid): (u32, i32),
    owner: &str,
    file: &str,
    index: u32,
) -> Result<(AttachInfo, ZeroString), String> {
    if !cred_exists(uid, owner) {
        return Err("not found".into());
    }
    let meta = read(uid, owner)?;
    if let Some(why) = read_refused(&meta) {
        return Err(why.into());
    }
    // The value's own gates, as in `precheck_meta` (audit-only reasons).
    crate::daemon_platform::exe::gate(&meta, peer_pid)?; // T10.09
    crate::daemon_syncx::quorum_gate(uid, owner, &meta)?; // T7.12
    crate::daemon_aws::checkout::gate(&meta, uid, expiry::now_unix())?; // T7.11
    let reauth = crate::daemon_session::reauth::window_open(uid, owner); // T11.14
    crate::daemon_session::reauth::gate(&meta, reauth)?;
    let (info, slot) = find(&meta, file)?;
    if index >= info.chunks() {
        return Err("attachment chunk index out of range".into());
    }
    let data = crypto::default_backend().decrypt(uid, &chunk_name(owner, slot, index))?;
    Ok((info, data))
}

pub fn handle_list(uid: u32, username: &str, name: &str) -> Response {
    let r = owner(uid, name).and_then(|o| {
        if !cred_exists(uid, &o) {
            return Err(SANITIZED_LOOKUP_ERROR.to_string());
        }
        Ok((o.clone(), read(uid, &o)?.attachments.unwrap_or_default()))
    });
    let shown = r.as_ref().map_or(name.to_uppercase(), |x| x.0.clone());
    log("attach-list", uid, username, &shown, &r);
    match r {
        Ok((name, files)) => Response::Records(RecordsResponse::AttachListOk { name, files }),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_remove(uid: u32, username: &str, name: &str, file: &str) -> Response {
    let r = owner(uid, name).and_then(|o| {
        let _lock = crate::daemon_credlock::lock(uid, &o);
        let mut meta = read(uid, &o)?;
        let (_, slot) = find(&meta, file)?;
        let rest: Vec<AttachInfo> = meta
            .attachments
            .take()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| i.file != file)
            .collect();
        meta.attachments = (!rest.is_empty()).then_some(rest);
        write(uid, &o, &meta)?;
        chunks::purge_slot(uid, &o, slot);
        Ok(o)
    });
    let shown = r.as_ref().map_or(name.to_uppercase(), Clone::clone);
    log("attach-rm", uid, username, &shown, &r);
    match r {
        Ok(name) => Response::Records(RecordsResponse::AttachRemoveOk {
            name,
            file: file.into(),
        }),
        Err(e) => Response::fail(e),
    }
}
