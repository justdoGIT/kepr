// daemon_recordsx/chunks.rs — T5.03 attachment chunks in the store.
//
// An attachment lives in one of SLOTS slots of its owner (a credential,
// or a trash entry `NAME~t<unix>`): chunk `n` of slot `k` is the value
// `OWNER~a<k>~<n>`, holding the chunk's bytes as base64 text, encrypted
// like any value (AAD bound to that exact name). `~` fails validate_name,
// so no request can name a chunk and `kepr ls` never shows one. Chunks
// are contiguous from 0, so everything here finds them by probing
// `store::cred_exists` (no directory scan): it works the same on the
// per-file store and the vault image. The `.meta` manifest says which
// slot holds which file.

use std::path::Path;

use base64::Engine;
use kepr_core::protocol_records::{AttachInfo, MAX_FILE_BYTES};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::store::{cred_exists, to_cred_name};
use crate::version_state::VersionState;
use crate::{crypto, expiry};

/// Slots per owner: room for the manifest's files plus uploads and
/// replacements in flight.
pub const SLOTS: u32 = 64;
/// Most chunks one file can have (bounds every probe loop).
const MAX_CHUNKS: u32 =
    (MAX_FILE_BYTES / kepr_core::protocol_records::CHUNK_BYTES as u64) as u32 + 1;

pub fn chunk_name(owner: &str, slot: u32, n: u32) -> String {
    format!("{owner}~a{slot}~{n}")
}

/// Chunks stored in `slot` (the contiguous run from chunk 0).
pub fn count(uid: u32, owner: &str, slot: u32) -> u32 {
    (0..MAX_CHUNKS)
        .find(|n| !cred_exists(uid, &chunk_name(owner, slot, *n)))
        .unwrap_or(MAX_CHUNKS)
}

/// Slots of `owner` holding at least chunk 0.
pub fn used_slots(uid: u32, owner: &str) -> Vec<u32> {
    (0..SLOTS)
        .filter(|k| cred_exists(uid, &chunk_name(owner, *k, 0)))
        .collect()
}

/// Delete one slot's chunks, last first (a failure leaves a prefix).
pub fn purge_slot(uid: u32, owner: &str, slot: u32) {
    for n in (0..count(uid, owner, slot)).rev() {
        if let Err(e) = crypto::default_backend().delete(uid, &chunk_name(owner, slot, n)) {
            eprintln!("[kepr-daemon] attachments: purge failed: {e}");
        }
    }
}

/// Drop every attachment chunk of `owner` (delete, purge, expiry).
pub fn purge(uid: u32, owner: &str) {
    for k in used_slots(uid, owner) {
        purge_slot(uid, owner, k);
    }
}

/// `purge` for the per-file TTL sweeper, which works on a directory and
/// the version state rather than the backend.
pub fn purge_in(dir: &Path, versions: Option<&VersionState>, uid: u32, owner: &str) {
    let file = |k: u32, n: u32| to_cred_name(uid, &chunk_name(owner, k, n));
    for k in 0..SLOTS {
        let stored = (0..MAX_CHUNKS)
            .find(|n| !dir.join(file(k, *n)).exists())
            .unwrap_or(MAX_CHUNKS);
        for n in (0..stored).rev() {
            let f = file(k, n);
            if let Some(Err(e)) = versions.map(|v| v.tombstone(&f)) {
                eprintln!("[kepr-daemon] attachments: tombstone failed: {e}");
                break;
            }
            let _ = std::fs::remove_file(dir.join(&f));
        }
    }
}

/// Re-encrypt every chunk of `from` under `to` (trash and restore move
/// the meta, manifest included, themselves). Best effort per chunk.
pub fn move_all(uid: u32, from: &str, to: &str) {
    let b = crypto::default_backend();
    for k in used_slots(uid, from) {
        for n in 0..count(uid, from, k) {
            let (src, dst) = (chunk_name(from, k, n), chunk_name(to, k, n));
            let moved = b
                .decrypt(uid, &src)
                .and_then(|v| b.encrypt(uid, &dst, v.as_bytes()));
            if let Err(e) = moved {
                eprintln!("[kepr-daemon] attachments: move failed: {e}");
            }
        }
        purge_slot(uid, from, k);
    }
}

/// One chunk's bytes.
pub fn read_chunk(uid: u32, owner: &str, slot: u32, n: u32) -> Result<Zeroizing<Vec<u8>>, String> {
    let text = crypto::default_backend().decrypt(uid, &chunk_name(owner, slot, n))?;
    base64::engine::general_purpose::STANDARD
        .decode(text.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| "attachment chunk is damaged".to_string())
}

/// `(size, hex sha256)` of the first `chunks` chunks of a slot.
pub fn digest(uid: u32, owner: &str, slot: u32, chunks: u32) -> Result<(u64, String), String> {
    let mut h = Sha256::new();
    let mut size = 0u64;
    for n in 0..chunks {
        let bytes = read_chunk(uid, owner, slot, n)?;
        size += bytes.len() as u64;
        h.update(&bytes[..]);
    }
    Ok((size, hex::encode(h.finalize())))
}

/// The slot an attachment id names.
pub fn slot_of(info: &AttachInfo) -> Option<u32> {
    info.id.parse().ok().filter(|k| *k < SLOTS)
}

/// `handle_set`'s hook: a new value keeps its credential's attachments.
pub fn carry_over(uid: u32, upper: &str, meta: &mut expiry::CredMeta) {
    let path = expiry::meta_path_for(&crate::store::cred_path(uid, upper));
    if let Some(Ok(old)) = expiry::read_meta(&path) {
        meta.attachments = old.attachments;
    }
}

/// `doctor --verify`: `(name, problem)` for every manifest entry whose
/// chunks are missing or don't add up, every upload slot no manifest
/// lists, and every chunk whose owner is gone. `values` are all stored
/// value names of the uid (chunks included).
pub fn verify(uid: u32, values: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for v in values {
        if let Some((owner, _)) = v.split_once("~a") {
            if !values.iter().any(|o| o == owner) {
                out.push((v.clone(), "orphan attachment chunk".into()));
            }
        }
    }
    for owner in values.iter().filter(|v| !v.contains("~a")) {
        let meta = expiry::read_meta(&expiry::meta_path_for(&crate::store::cred_path(uid, owner)))
            .and_then(Result::ok)
            .unwrap_or_default();
        let listed = meta.attachments.unwrap_or_default();
        for info in &listed {
            if let Some(p) = check_entry(uid, owner, info) {
                out.push((owner.clone(), format!("attachment {}: {p}", info.file)));
            }
        }
        for k in used_slots(uid, owner) {
            if !listed.iter().any(|i| slot_of(i) == Some(k)) {
                out.push((owner.clone(), format!("unfinished attachment upload {k}")));
            }
        }
    }
    out
}

fn check_entry(uid: u32, owner: &str, info: &AttachInfo) -> Option<String> {
    let Some(k) = slot_of(info) else {
        return Some("bad id".into());
    };
    if count(uid, owner, k) != info.chunks() {
        return Some("chunks missing".into());
    }
    match digest(uid, owner, k, info.chunks()) {
        Err(_) => Some("a chunk does not decrypt".into()),
        Ok((size, _)) if size != info.size => Some("size mismatch".into()),
        Ok((_, sha)) if sha != info.sha256 => Some("sha256 mismatch".into()),
        Ok(_) => None,
    }
}
