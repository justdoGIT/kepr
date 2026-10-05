// daemon_recordsx/attach.rs — T5.03 attachments, upload side (`kepr
// attach add`) and the helpers attach_read.rs shares. Files hang off a
// credential (any kind but sealed, SSH and share-key ones), up to
// MAX_FILE_BYTES each and MAX_RECORD_BYTES per credential, stored as
// encrypted chunks (chunks.rs) and listed in the `.meta` manifest
// `attachments`.
//
// An upload is a run of `AttachPut`s under the credential lock: chunk 0
// picks a free slot (dropping unfinished uploads: one upload per
// credential at a time), the last chunk hashes the slot, checks the caps
// and lists the file, replacing a file of the same name.

use std::path::PathBuf;

use base64::Engine;
use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_records::{
    validate_file_name, AttachInfo, RecordsResponse, CHUNK_BYTES, MAX_FILE_BYTES, MAX_RECORD_BYTES,
};
use zeroize::Zeroizing;

use super::chunks::{self, chunk_name, slot_of, SLOTS};
use crate::audit::{self, AuditEvent, AuditResult};
use crate::crypto::{self, SANITIZED_LOOKUP_ERROR};
use crate::expiry::{self, CredMeta};
use crate::store::{cred_exists, cred_path, validate_name};

/// Files per credential.
const MAX_FILES: usize = 32;

/// One `AttachPut`.
pub struct Put<'a> {
    pub file: &'a str,
    pub upload: Option<&'a str>,
    pub index: u32,
    pub chunk: &'a ZeroString,
    pub last: bool,
}

fn meta_path(uid: u32, upper: &str) -> PathBuf {
    expiry::meta_path_for(&cred_path(uid, upper))
}

pub(super) fn read(uid: u32, upper: &str) -> Result<CredMeta, String> {
    match expiry::read_meta(&meta_path(uid, upper)) {
        None => Ok(CredMeta::default()),
        Some(Ok(m)) => Ok(m),
        Some(Err(_)) => Err(SANITIZED_LOOKUP_ERROR.into()),
    }
}

pub(super) fn write(uid: u32, upper: &str, meta: &CredMeta) -> Result<(), String> {
    if meta.is_empty() {
        expiry::delete_meta(&meta_path(uid, upper));
        Ok(())
    } else {
        expiry::write_meta(&meta_path(uid, upper), meta)
    }
}

/// The credential a request names, aliases resolved (T11.5).
pub(super) fn owner(uid: u32, name: &str) -> Result<String, String> {
    validate_name(name)?;
    Ok(crate::daemon_store::resolve_alias(
        uid,
        &name.to_uppercase(),
    ))
}

pub(super) fn log<T>(op: &str, uid: u32, username: &str, name: &str, r: &Result<T, String>) {
    audit::log(&AuditEvent {
        op,
        name: Some(name),
        uid,
        username,
        result: match r {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}

pub(super) fn no_attachments(m: &CredMeta) -> bool {
    m.sealed == Some(true) || m.ssh.is_some() || m.share_key == Some(true)
}

pub fn handle_put(uid: u32, username: &str, name: &str, p: Put) -> Response {
    let r = owner(uid, name).and_then(|o| {
        let _lock = crate::daemon_credlock::lock(uid, &o);
        put(uid, &o, &p).map(|(slot, done)| (o, slot, done))
    });
    if !matches!(r, Ok((_, _, false))) {
        let shown = r.as_ref().map_or(name.to_uppercase(), |x| x.0.clone());
        log("attach-add", uid, username, &shown, &r);
    }
    match r {
        Ok((name, slot, done)) => Response::Records(RecordsResponse::AttachPutOk {
            name,
            file: p.file.into(),
            upload: slot.to_string(),
            done,
        }),
        Err(e) => Response::fail(e),
    }
}

fn put(uid: u32, owner: &str, p: &Put) -> Result<(u32, bool), String> {
    validate_file_name(p.file)?;
    if !cred_exists(uid, owner) {
        return Err(SANITIZED_LOOKUP_ERROR.into());
    }
    let meta = read(uid, owner)?;
    if no_attachments(&meta) {
        return Err("sealed, SSH and share-key credentials can't have attachments".into());
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(p.chunk.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| "attachment chunk is not base64".to_string())?;
    if data.len() > CHUNK_BYTES || (!p.last && data.len() != CHUNK_BYTES) {
        return Err(format!(
            "attachment chunks are {CHUNK_BYTES} bytes (the last may be shorter)"
        ));
    }
    let listed = meta.attachments.clone().unwrap_or_default();
    let slot = match (p.index, p.upload) {
        (0, _) => start(uid, owner, &listed, p.file)?,
        (_, Some(u)) => resume(uid, owner, &listed, u, p.index)?,
        (_, None) => return Err("upload id missing".into()),
    };
    let end = u64::from(p.index) * CHUNK_BYTES as u64 + data.len() as u64;
    if end > MAX_FILE_BYTES {
        chunks::purge_slot(uid, owner, slot);
        return Err(format!(
            "attachment too large (at most {} MiB)",
            MAX_FILE_BYTES >> 20
        ));
    }
    let stored = crypto::default_backend().encrypt(
        uid,
        &chunk_name(owner, slot, p.index),
        p.chunk.as_bytes(),
    );
    if let Err(e) = stored {
        chunks::purge_slot(uid, owner, slot);
        return Err(e);
    }
    if !p.last {
        return Ok((slot, false));
    }
    finish(uid, owner, meta, p.file, slot, p.index + 1)?;
    Ok((slot, true))
}

/// Chunk 0: a free slot. Unlisted slots are unfinished uploads.
fn start(uid: u32, owner: &str, listed: &[AttachInfo], file: &str) -> Result<u32, String> {
    for k in chunks::used_slots(uid, owner) {
        if !listed.iter().any(|i| slot_of(i) == Some(k)) {
            chunks::purge_slot(uid, owner, k);
        }
    }
    if listed.len() >= MAX_FILES && !listed.iter().any(|i| i.file == file) {
        return Err(format!("at most {MAX_FILES} attachments per credential"));
    }
    (0..SLOTS)
        .find(|k| {
            !listed.iter().any(|i| slot_of(i) == Some(*k))
                && !cred_exists(uid, &chunk_name(owner, *k, 0))
        })
        .ok_or_else(|| "no free attachment slot".to_string())
}

fn resume(
    uid: u32,
    owner: &str,
    listed: &[AttachInfo],
    upload: &str,
    index: u32,
) -> Result<u32, String> {
    let k: u32 = upload
        .parse()
        .ok()
        .filter(|k| *k < SLOTS)
        .ok_or("bad upload id")?;
    if listed.iter().any(|i| slot_of(i) == Some(k))
        || !cred_exists(uid, &chunk_name(owner, k, index - 1))
    {
        return Err("upload interrupted; start it again".into());
    }
    Ok(k)
}

/// Last chunk: hash the slot, check the per-credential cap, list it.
fn finish(
    uid: u32,
    owner: &str,
    mut meta: CredMeta,
    file: &str,
    slot: u32,
    count: u32,
) -> Result<(), String> {
    let r = (|| {
        // A restarted upload may have left chunks past the new end.
        let mut n = count;
        while cred_exists(uid, &chunk_name(owner, slot, n)) {
            crypto::default_backend().delete(uid, &chunk_name(owner, slot, n))?;
            n += 1;
        }
        let (size, sha256) = chunks::digest(uid, owner, slot, count)?;
        let mut listed = meta.attachments.take().unwrap_or_default();
        let replaced = listed
            .iter()
            .position(|i| i.file == file)
            .map(|i| listed.remove(i));
        let total = listed.iter().map(|i| i.size).sum::<u64>() + size;
        if total > MAX_RECORD_BYTES {
            return Err(format!(
                "a credential's attachments are capped at {} MiB",
                MAX_RECORD_BYTES >> 20
            ));
        }
        listed.push(AttachInfo {
            id: slot.to_string(),
            file: file.into(),
            size,
            sha256,
        });
        meta.attachments = Some(listed);
        write(uid, owner, &meta)?;
        if let Some(old) = replaced.as_ref().and_then(slot_of) {
            chunks::purge_slot(uid, owner, old);
        }
        Ok(())
    })();
    if r.is_err() {
        chunks::purge_slot(uid, owner, slot);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_handlers::{handle_set, SetFlags};
    use crate::daemon_recordsx::attach_read;
    use crate::daemon_store::testkit;
    use kepr_core::protocol_store::StoreRequest;
    use sha2::Digest;

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    /// Deterministic, incompressible-looking bytes.
    pub fn bytes(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2_654_435_761).max(1);
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    pub fn upload(uid: u32, name: &str, file: &str, data: &[u8]) -> Response {
        let parts: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(CHUNK_BYTES).collect()
        };
        let mut upload: Option<String> = None;
        for (i, c) in parts.iter().enumerate() {
            let chunk = ZeroString::from_string(B64.encode(c));
            let p = Put {
                file,
                upload: upload.as_deref(),
                index: i as u32,
                chunk: &chunk,
                last: i + 1 == parts.len(),
            };
            match handle_put(uid, "t", name, p) {
                Response::Records(RecordsResponse::AttachPutOk { done: true, .. }) => {
                    return Response::Pong
                }
                Response::Records(RecordsResponse::AttachPutOk { upload: u, .. }) => {
                    upload = Some(u)
                }
                other => return other,
            }
        }
        Response::fail("not finished")
    }

    fn download(uid: u32, name: &str, file: &str) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let mut i = 0;
        loop {
            match attach_read::handle_get(uid, "t", name, file, i) {
                Response::Records(RecordsResponse::AttachChunkOk { chunks, data, .. }) => {
                    out.extend(B64.decode(data.as_bytes()).unwrap());
                    i += 1;
                    if i >= chunks {
                        return Ok(out);
                    }
                }
                Response::Err { error } => return Err(error),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    fn files(uid: u32, name: &str) -> Vec<AttachInfo> {
        match attach_read::handle_list(uid, "t", name) {
            Response::Records(RecordsResponse::AttachListOk { files, .. }) => files,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn store(uid: u32, r: StoreRequest) -> Response {
        crate::daemon_store::dispatch(uid, 0, "t", r)
    }

    fn verify(uid: u32) -> std::collections::HashMap<String, String> {
        match store(uid, StoreRequest::VerifyStore) {
            Response::CheckOk { results, .. } => results,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn all_ok(uid: u32) -> bool {
        verify(uid).values().all(|s| s == "ok")
    }

    #[test]
    fn a_200k_file_round_trips_byte_exact() {
        let uid = testkit::uid();
        testkit::set(uid, "AT_DOC", "v");
        let data = bytes(200 * 1024, 1);
        assert!(upload(uid, "at_doc", "scan.pdf", &data).is_success());
        let ls = files(uid, "AT_DOC");
        assert_eq!(ls.len(), 1);
        assert_eq!((ls[0].file.as_str(), ls[0].size), ("scan.pdf", 200 * 1024));
        assert_eq!(ls[0].sha256, hex::encode(sha2::Sha256::digest(&data)));
        assert_eq!(download(uid, "AT_DOC", "scan.pdf").unwrap(), data);
        // Replacing it keeps one entry and drops the old chunks.
        let small = bytes(10, 2);
        assert!(upload(uid, "AT_DOC", "scan.pdf", &small).is_success());
        assert_eq!(files(uid, "AT_DOC").len(), 1);
        assert_eq!(download(uid, "AT_DOC", "scan.pdf").unwrap(), small);
        assert_eq!(chunks::used_slots(uid, "AT_DOC").len(), 1);
        assert!(all_ok(uid), "{:?}", verify(uid));
        // An empty file is fine too.
        assert!(upload(uid, "AT_DOC", "empty", b"").is_success());
        assert_eq!(download(uid, "AT_DOC", "empty").unwrap(), b"");
    }

    #[test]
    fn a_tampered_chunk_is_reported() {
        let uid = testkit::uid();
        testkit::set(uid, "AT_T", "v");
        let data = bytes(3 * CHUNK_BYTES, 3);
        assert!(upload(uid, "AT_T", "f", &data).is_success());
        // Re-encrypt chunk 1 with other bytes (someone holding the key):
        // the tag checks out, the digest does not.
        let other = ZeroString::from_string(B64.encode(bytes(CHUNK_BYTES, 9)));
        crypto::default_backend()
            .encrypt(uid, &chunk_name("AT_T", 0, 1), other.as_bytes())
            .unwrap();
        assert_eq!(verify(uid)["AT_T"], "attachment f: sha256 mismatch");
        // The client checks the reassembled bytes against this digest
        // (cli_recordsx::attach::check_digest) and refuses to write them.
        let got = download(uid, "AT_T", "f").unwrap();
        let info = &files(uid, "AT_T")[0];
        assert_eq!(got.len() as u64, info.size);
        assert_ne!(hex::encode(sha2::Sha256::digest(&got)), info.sha256);
    }

    #[test]
    fn caps_and_bad_names_are_refused() {
        let uid = testkit::uid();
        testkit::set(uid, "AT_C", "v");
        for bad in ["a/b", "..", "../x", ""] {
            assert!(!upload(uid, "AT_C", bad, b"x").is_success(), "{bad:?}");
        }
        // Per file: a chunk ending past 16 MiB is refused, the upload dropped.
        let full = ZeroString::from_string(B64.encode(bytes(CHUNK_BYTES, 4)));
        let put = |upload, index, last| Put {
            file: "big",
            upload,
            index,
            chunk: &full,
            last,
        };
        assert!(handle_put(uid, "t", "AT_C", put(None, 0, false)).is_success());
        let last_ok = (MAX_FILE_BYTES / CHUNK_BYTES as u64) as u32 - 1;
        crypto::default_backend()
            .encrypt(uid, &chunk_name("AT_C", 0, last_ok), full.as_bytes())
            .unwrap();
        let r = handle_put(uid, "t", "AT_C", put(Some("0"), last_ok + 1, false));
        assert!(r.err_msg().unwrap().contains("too large"), "{r:?}");
        assert!(chunks::used_slots(uid, "AT_C").is_empty());
        // A chunk out of sequence is refused.
        assert!(!handle_put(uid, "t", "AT_C", put(Some("3"), 2, false)).is_success());
        // Per credential: 64 MiB in all.
        let mut meta = testkit::meta(uid, "AT_C");
        meta.attachments = Some(vec![AttachInfo {
            id: "9".into(),
            file: "huge".into(),
            size: MAX_RECORD_BYTES - 100,
            sha256: String::new(),
        }]);
        write(uid, "AT_C", &meta).unwrap();
        let r = upload(uid, "AT_C", "more", &bytes(200, 5));
        assert!(r.err_msg().unwrap().contains("64 MiB"), "{r:?}");
        assert!(chunks::used_slots(uid, "AT_C").is_empty());
    }

    #[test]
    fn sealed_and_gated_credentials() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "AT_S", "sk");
        let r = upload(uid, "AT_S", "f", b"x");
        assert!(r.err_msg().unwrap().contains("sealed"), "{r:?}");
        let flags = SetFlags {
            requires_consent: Some(true),
            ..Default::default()
        };
        assert!(handle_set(uid, "t", "AT_G", Some("v"), None, flags).is_success());
        assert!(upload(uid, "AT_G", "f", b"secret").is_success());
        assert_eq!(
            download(uid, "AT_G", "f").unwrap_err(),
            "credential unavailable"
        );
        assert!(download(uid, "AT_NONE", "f").is_err());
    }

    #[test]
    fn set_keeps_them_delete_and_wipe_remove_them_alias_reads_them() {
        let uid = testkit::uid();
        testkit::set(uid, "AT_K", "v1");
        assert!(upload(uid, "AT_K", "f", b"data").is_success());
        testkit::set(uid, "AT_K", "v2");
        assert_eq!(files(uid, "AT_K").len(), 1);
        let link = StoreRequest::Link {
            alias: "AT_KA".into(),
            target: "AT_K".into(),
        };
        assert!(store(uid, link).is_success());
        assert_eq!(download(uid, "AT_KA", "f").unwrap(), b"data");
        assert!(crate::daemon_handlers::handle_delete(uid, "t", "AT_K").is_success());
        assert!(chunks::used_slots(uid, "AT_K").is_empty());

        testkit::set(uid, "AT_W", "v");
        assert!(upload(uid, "AT_W", "f", &bytes(CHUNK_BYTES + 1, 6)).is_success());
        assert!(store(uid, StoreRequest::DeleteAll { confirm: true }).is_success());
        assert!(chunks::used_slots(uid, "AT_W").is_empty());
    }

    #[test]
    fn they_follow_the_record_into_the_trash_and_back() {
        let uid = testkit::uid();
        testkit::set(uid, "AT_TR", "v");
        let data = bytes(CHUNK_BYTES * 2 + 5, 7);
        assert!(upload(uid, "AT_TR", "f.bin", &data).is_success());
        assert!(crate::daemon_store::handle_rm(uid, "t", "AT_TR").is_success());
        assert!(chunks::used_slots(uid, "AT_TR").is_empty());
        assert!(all_ok(uid), "{:?}", verify(uid));
        let restore = StoreRequest::TrashRestore {
            name: "AT_TR".into(),
        };
        assert!(store(uid, restore).is_success());
        assert_eq!(download(uid, "AT_TR", "f.bin").unwrap(), data);
        // Purged from the trash: gone for good.
        crate::daemon_store::handle_rm(uid, "t", "AT_TR");
        assert!(store(uid, StoreRequest::TrashPurge { name: None }).is_success());
        assert!(verify(uid).is_empty(), "{:?}", verify(uid));
    }

    #[test]
    fn verify_reports_unfinished_uploads_and_remove_works() {
        let uid = testkit::uid();
        testkit::set(uid, "AT_V", "v");
        assert!(upload(uid, "AT_V", "keep", b"k").is_success());
        let chunk = ZeroString::from_string(B64.encode(bytes(CHUNK_BYTES, 8)));
        let p = Put {
            file: "partial",
            upload: None,
            index: 0,
            chunk: &chunk,
            last: false,
        };
        assert!(handle_put(uid, "t", "AT_V", p).is_success());
        assert_eq!(verify(uid)["AT_V"], "unfinished attachment upload 1");
        // The next upload drops the leftover.
        assert!(upload(uid, "AT_V", "other", b"o").is_success());
        assert_eq!(verify(uid)["AT_V"], "ok");
        assert!(attach_read::handle_remove(uid, "t", "AT_V", "keep").is_success());
        assert_eq!(files(uid, "AT_V").len(), 1);
        assert!(!attach_read::handle_remove(uid, "t", "AT_V", "keep").is_success());
        assert_eq!(verify(uid)["AT_V"], "ok");
    }
}
