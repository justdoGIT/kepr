// daemon_syncx/transfer.rs — T6.09 chunked bundle transfer.
//
// A frame holds 64 KiB, a bundle up to 16 MiB, so both directions go in
// BUNDLE_CHUNK_BYTES chunks. The daemon holds the bytes in memory between
// requests: an export's finished ciphertext until its last chunk is
// fetched, an import's ciphertext until its last `ImportBundle` round. Both are
// encrypted under the bundle passphrase, never plaintext. Each uid has at
// most one of each (a new one replaces the old), every slot expires after
// TTL, and the daemon holds at most MAX_SLOTS at once.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use kepr_core::protocol_syncx::{bundle_chunks, BUNDLE_CHUNK_BYTES, MAX_BUNDLE_BYTES};

use crate::expiry::now_unix;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const TTL: u64 = 600;
const MAX_SLOTS: usize = 16;
const NO_EXPORT: &str = "no such export (it expired or is finished); export again";
const NO_UPLOAD: &str = "no such upload (it expired); import again";

struct Slot {
    uid: u32,
    bytes: Vec<u8>,
    at: u64,
    /// Upload: the next chunk index expected; `None` once complete.
    next: Option<u32>,
}

#[derive(Default)]
struct Slots(HashMap<String, Slot>);

static EXPORTS: Mutex<Option<Slots>> = Mutex::new(None);
static UPLOADS: Mutex<Option<Slots>> = Mutex::new(None);

impl Slots {
    /// Drop expired slots and `uid`'s old one; refuse when full.
    fn make_room(&mut self, uid: u32, now: u64) -> Result<(), String> {
        self.0
            .retain(|_, s| s.uid != uid && now < s.at.saturating_add(TTL));
        if self.0.len() >= MAX_SLOTS {
            return Err("the daemon is busy with other transfers; try again shortly".into());
        }
        Ok(())
    }

    /// The live slot `id` of `uid` (another uid's id looks absent).
    fn get(&mut self, uid: u32, id: &str, now: u64) -> Option<&mut Slot> {
        self.0
            .get_mut(id)
            .filter(|s| s.uid == uid && now < s.at.saturating_add(TTL))
    }
}

fn new_id() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(hex::encode(b))
}

fn with<T>(m: &Mutex<Option<Slots>>, f: impl FnOnce(&mut Slots) -> T) -> Result<T, String> {
    let mut g = m.lock().map_err(|_| "transfer state lock poisoned")?;
    Ok(f(g.get_or_insert_with(Slots::default)))
}

/// Keep a built export; returns its id and chunk count.
pub fn put_export(uid: u32, bytes: Vec<u8>, now: u64) -> Result<(String, u32), String> {
    let chunks = bundle_chunks(bytes.len());
    let id = new_id()?;
    with(&EXPORTS, |s| {
        s.make_room(uid, now)?;
        let slot = Slot {
            uid,
            bytes,
            at: now,
            next: None,
        };
        s.0.insert(id.clone(), slot);
        Ok((id, chunks))
    })?
}

/// Chunk `index` of export `id`, as base64; the last one ends the export.
pub fn export_chunk(uid: u32, id: &str, index: u32) -> Result<String, String> {
    with(&EXPORTS, |s| {
        let slot = s.get(uid, id, now_unix()).ok_or(NO_EXPORT)?;
        let chunks = bundle_chunks(slot.bytes.len());
        if index >= chunks {
            return Err("chunk index out of range".to_string());
        }
        let from = index as usize * BUNDLE_CHUNK_BYTES;
        let to = (from + BUNDLE_CHUNK_BYTES).min(slot.bytes.len());
        let data = B64.encode(&slot.bytes[from..to]);
        if index + 1 == chunks {
            s.0.remove(id);
        }
        Ok(data)
    })?
}

/// Store upload chunk `index`; returns the upload id and whether it is
/// complete. Chunks come in order, each full-sized except the last.
pub fn put_upload(
    uid: u32,
    upload: Option<&str>,
    (index, chunk, last): (u32, &str, bool),
    now: u64,
) -> Result<(String, bool), String> {
    let data = B64.decode(chunk).map_err(|_| "chunk is not base64")?;
    if data.len() > BUNDLE_CHUNK_BYTES || (!last && data.len() != BUNDLE_CHUNK_BYTES) {
        return Err("chunk has the wrong size".into());
    }
    with(&UPLOADS, |s| {
        let id = match upload {
            None if index == 0 => {
                s.make_room(uid, now)?;
                let id = new_id()?;
                let slot = Slot {
                    uid,
                    bytes: Vec::new(),
                    at: now,
                    next: Some(0),
                };
                s.0.insert(id.clone(), slot);
                id
            }
            None => return Err("the first chunk must be chunk 0".to_string()),
            Some(id) => id.to_string(),
        };
        let slot = s.get(uid, &id, now).ok_or(NO_UPLOAD)?;
        if slot.next != Some(index) {
            return Err("chunk out of order".to_string());
        }
        if slot.bytes.len() + data.len() > MAX_BUNDLE_BYTES {
            s.0.remove(&id);
            return Err("the bundle is over 16 MiB".to_string());
        }
        slot.bytes.extend_from_slice(&data);
        slot.next = (!last).then_some(index + 1);
        Ok((id, last))
    })?
}

/// A copy of a complete upload (an import opens it once per round).
pub fn upload_bytes(uid: u32, id: &str) -> Result<Vec<u8>, String> {
    with(&UPLOADS, |s| match s.get(uid, id, now_unix()) {
        Some(slot) if slot.next.is_none() => Ok(slot.bytes.clone()),
        Some(_) => Err("the upload is not finished".to_string()),
        None => Err(NO_UPLOAD.to_string()),
    })?
}

/// Forget an upload (its import is finished or failed).
pub fn drop_upload(uid: u32, id: &str) {
    let _ = with(&UPLOADS, |s| {
        if s.get(uid, id, now_unix()).is_some() {
            s.0.remove(id);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid() -> u32 {
        crate::daemon_store::testkit::uid()
    }

    fn b64(n: usize, byte: u8) -> String {
        B64.encode(vec![byte; n])
    }

    #[test]
    fn exports_come_back_in_chunks_and_end_with_the_last() {
        let (me, other) = (uid(), uid());
        let bytes: Vec<u8> = (0..BUNDLE_CHUNK_BYTES + 10).map(|i| i as u8).collect();
        let (id, chunks) = put_export(me, bytes.clone(), now_unix()).unwrap();
        assert_eq!(chunks, 2);
        assert_eq!(export_chunk(other, &id, 0).unwrap_err(), NO_EXPORT);
        assert!(export_chunk(me, &id, 2).is_err());
        let mut got = B64.decode(export_chunk(me, &id, 0).unwrap()).unwrap();
        got.extend(B64.decode(export_chunk(me, &id, 1).unwrap()).unwrap());
        assert_eq!(got, bytes);
        assert_eq!(export_chunk(me, &id, 0).unwrap_err(), NO_EXPORT);
    }

    #[test]
    fn old_exports_expire_and_a_new_one_replaces_the_old() {
        let me = uid();
        let (old, _) = put_export(me, vec![1], now_unix() - TTL - 1).unwrap();
        assert_eq!(export_chunk(me, &old, 0).unwrap_err(), NO_EXPORT);
        let (a, _) = put_export(me, vec![1], now_unix()).unwrap();
        let (b, _) = put_export(me, vec![2], now_unix()).unwrap();
        assert_eq!(export_chunk(me, &a, 0).unwrap_err(), NO_EXPORT);
        assert_eq!(export_chunk(me, &b, 0).unwrap(), B64.encode([2]));
    }

    #[test]
    fn uploads_are_ordered_sized_and_owned() {
        let (me, other) = (uid(), uid());
        let now = now_unix();
        let full = b64(BUNDLE_CHUNK_BYTES, 7);
        assert!(put_upload(me, None, (1, &full, false), now).is_err());
        assert!(put_upload(me, None, (0, &b64(10, 1), false), now)
            .unwrap_err()
            .contains("size"));
        let (id, done) = put_upload(me, None, (0, &full, false), now).unwrap();
        assert!(!done);
        assert_eq!(
            upload_bytes(me, &id).unwrap_err(),
            "the upload is not finished"
        );
        assert!(put_upload(me, Some(&id), (2, "AA==", true), now)
            .unwrap_err()
            .contains("order"));
        assert_eq!(
            put_upload(other, Some(&id), (1, "AA==", true), now).unwrap_err(),
            NO_UPLOAD
        );
        assert!(put_upload(me, Some(&id), (1, "AA==", true), now).unwrap().1);
        assert_eq!(upload_bytes(other, &id).unwrap_err(), NO_UPLOAD);
        drop_upload(other, &id);
        assert_eq!(upload_bytes(me, &id).unwrap().len(), BUNDLE_CHUNK_BYTES + 1);
        assert!(put_upload(me, Some(&id), (2, "AA==", true), now).is_err());
        drop_upload(me, &id);
        assert_eq!(upload_bytes(me, &id).unwrap_err(), NO_UPLOAD);
    }

    #[test]
    fn uploads_stop_at_the_size_cap() {
        let me = uid();
        let now = now_unix();
        let full = b64(BUNDLE_CHUNK_BYTES, 1);
        let (id, _) = put_upload(me, None, (0, &full, false), now).unwrap();
        let mut i = 1;
        let err = loop {
            match put_upload(me, Some(&id), (i, &full, false), now) {
                Ok(_) => i += 1,
                Err(e) => break e,
            }
        };
        assert!(err.contains("16 MiB"), "{err}");
        assert_eq!(i as usize, MAX_BUNDLE_BYTES / BUNDLE_CHUNK_BYTES);
        assert_eq!(upload_bytes(me, &id).unwrap_err(), NO_UPLOAD);
    }
}
