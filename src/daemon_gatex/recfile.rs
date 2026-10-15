// daemon_gatex/recfile.rs — the on-disk format of agent session
// recordings (T7.09). A gate started with `kepr agent run --record` sends what the
// agent sent and received in batches over its private channel; the daemon
// appends each batch, encrypted, to one file per session:
//
//   <state>/recordings/<uid>/<session>.rec   (0600, directories 0700)
//     "kepr_rec1\n" ‖ u32 BE n ‖ n bytes of header JSON
//     frames: u32 BE n ‖ nonce (12) ‖ AES-256-GCM(batch JSON) ‖ tag
//
// Each session has its own random 32-byte key, kept in the header only
// wrapped: AES-256-GCM under HKDF-SHA256(master key, salt, "kepr-rec1
// wrap"), AAD uid ‖ session. Frame n is sealed under the session key with
// AAD uid ‖ session ‖ n, so frames can't be reordered, dropped from the
// middle or moved into another user's or session's file. Nothing is
// ever written in plaintext but the header's session id, start time and
// salt.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use kepr_core::gate_record::GateRecord;
use kepr_core::protocol_gatex::RecordingInfo;

const MAGIC: &[u8] = b"kepr_rec1\n";
const NONCE: usize = 12;
/// One session's recording stops growing here.
const MAX_RECORDING: u64 = 256 << 20;
/// Recordings kept per user; starting another drops the oldest.
pub const MAX_SESSIONS: usize = 50;
const MAX_HEADER: usize = 4096;
const MAX_FRAME: usize = 1 << 20;

#[derive(Serialize, Deserialize)]
struct Header {
    session: String,
    started_unix: u64,
    salt: String,
    /// The session key, wrapped (hex of nonce ‖ ciphertext ‖ tag).
    key: String,
}

/// The directory of `uid`'s recordings under `root` (the state dir).
pub fn user_dir(root: &Path, uid: u32) -> PathBuf {
    root.join("recordings").join(uid.to_string())
}

fn wrap_key(kek: &[u8; 32], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), kek)
        .expand(b"kepr-rec1 wrap", out.as_mut())
        .expect("32 bytes is a valid HKDF length");
    out
}

fn aad(uid: u32, session: &str, frame: Option<u64>) -> Vec<u8> {
    let mut a = uid.to_be_bytes().to_vec();
    a.extend_from_slice(session.as_bytes());
    if let Some(n) = frame {
        a.extend_from_slice(&n.to_be_bytes());
    }
    a
}

fn seal(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE];
    getrandom::fill(&mut nonce).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let c = Aes256Gcm::new_from_slice(key).map_err(|_| "bad key")?;
    let ct = c
        .encrypt(&nonce.into(), Payload { msg, aad })
        .map_err(|_| "encryption failed")?;
    Ok([&nonce[..], &ct].concat())
}

fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if sealed.len() < NONCE {
        return Err("damaged recording".into());
    }
    let c = Aes256Gcm::new_from_slice(key).map_err(|_| "bad key")?;
    let nonce: [u8; NONCE] = sealed[..NONCE].try_into().expect("12 bytes");
    c.decrypt(
        &nonce.into(),
        Payload {
            msg: &sealed[NONCE..],
            aad,
        },
    )
    .map(Zeroizing::new)
    .map_err(|_| "damaged recording".into())
}

fn put(f: &mut File, bytes: &[u8]) -> Result<(), String> {
    let framed = [&(bytes.len() as u32).to_be_bytes()[..], bytes].concat();
    f.write_all(&framed).map_err(|e| format!("recording: {e}"))
}

/// The next length-prefixed record, or `None` at the end. A torn tail (a
/// frame still being written) also reads as the end.
fn get(f: &mut File, max: usize) -> Result<Option<Vec<u8>>, String> {
    let eof = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => Ok(None),
        _ => Err(format!("recording: {e}")),
    };
    let mut len = [0u8; 4];
    if let Err(e) = f.read_exact(&mut len) {
        return eof(e);
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > max {
        return Err("damaged recording".into());
    }
    let mut buf = vec![0u8; n];
    match f.read_exact(&mut buf) {
        Ok(()) => Ok(Some(buf)),
        Err(e) => eof(e),
    }
}

/// Step over one frame without reading it; `false` at the end.
fn skip(f: &mut File) -> Result<bool, String> {
    let mut len = [0u8; 4];
    if f.read_exact(&mut len).is_err() {
        return Ok(false);
    }
    let n = u32::from_be_bytes(len) as i64;
    f.seek(SeekFrom::Current(n))
        .map_err(|e| format!("recording: {e}"))?;
    Ok(true)
}

/// An open recording being written.
pub struct Writer {
    uid: u32,
    session: String,
    file: File,
    key: Zeroizing<[u8; 32]>,
    frames: u64,
    size: u64,
}

impl Writer {
    pub fn create(
        root: &Path,
        uid: u32,
        session: &str,
        started_unix: u64,
        kek: &[u8; 32],
    ) -> Result<Self, String> {
        let dir = user_dir(root, uid);
        fs::create_dir_all(&dir).map_err(|e| format!("recording: {e}"))?;
        for d in [dir.parent().unwrap_or(&dir), &dir] {
            let _ = fs::set_permissions(d, fs::Permissions::from_mode(0o700));
        }
        prune(root, uid, MAX_SESSIONS - 1);
        let mut key = Zeroizing::new([0u8; 32]);
        let mut salt = [0u8; 32];
        getrandom::fill(key.as_mut())
            .and_then(|_| getrandom::fill(&mut salt))
            .map_err(|e| format!("CSPRNG failure: {e}"))?;
        let wrapped = seal(
            &wrap_key(kek, &salt),
            &aad(uid, session, None),
            key.as_ref(),
        )?;
        let header = serde_json::to_vec(&Header {
            session: session.to_string(),
            started_unix,
            salt: hex::encode(salt),
            key: hex::encode(wrapped),
        })
        .map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(format!("{session}.rec")))
            .map_err(|e| format!("recording: {e}"))?;
        file.write_all(MAGIC)
            .map_err(|e| format!("recording: {e}"))?;
        put(&mut file, &header)?;
        Ok(Writer {
            uid,
            session: session.to_string(),
            file,
            key,
            frames: 0,
            size: (MAGIC.len() + 4 + header.len()) as u64,
        })
    }

    pub fn append(&mut self, batch: &GateRecord) -> Result<(), String> {
        let plain = Zeroizing::new(serde_json::to_vec(batch).map_err(|e| e.to_string())?);
        let frame = aad(self.uid, &self.session, Some(self.frames));
        let sealed = seal(&self.key, &frame, &plain)?;
        if self.size + sealed.len() as u64 + 4 > MAX_RECORDING {
            return Err("the recording reached its size limit".into());
        }
        put(&mut self.file, &sealed)?;
        self.frames += 1;
        self.size += sealed.len() as u64 + 4;
        Ok(())
    }
}

fn read_header(f: &mut File) -> Result<Header, String> {
    let mut magic = [0u8; 10];
    f.read_exact(&mut magic).map_err(|_| "not a recording")?;
    if magic != MAGIC {
        return Err("not a recording".into());
    }
    let raw = get(f, MAX_HEADER)?.ok_or("not a recording")?;
    serde_json::from_slice(&raw).map_err(|_| "not a recording".into())
}

/// One frame of a recording, read back.
#[derive(Debug, PartialEq)]
pub struct Page {
    pub batch: GateRecord,
    /// The next frame's number (`None` after the last) and where it starts.
    pub next: Option<u64>,
    pub offset: u64,
    pub started_unix: u64,
}

/// Frame `frame` of `uid`'s recording `session`, found at byte `offset`
/// (0: count frames from the start). A wrong offset fails to decrypt:
/// the frame number is in each frame's AAD.
pub fn read(
    root: &Path,
    uid: u32,
    session: &str,
    kek: &[u8; 32],
    (frame, offset): (u64, u64),
) -> Result<Page, String> {
    let path = user_dir(root, uid).join(format!("{session}.rec"));
    let mut f = File::open(path).map_err(|_| "no such recording")?;
    let h = read_header(&mut f)?;
    let salt = hex::decode(&h.salt).map_err(|_| "damaged recording")?;
    let wrapped = hex::decode(&h.key).map_err(|_| "damaged recording")?;
    let raw_key = open(&wrap_key(kek, &salt), &aad(uid, session, None), &wrapped)?;
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(
        raw_key
            .as_slice()
            .try_into()
            .map_err(|_| "damaged recording")?,
    );
    let io = |e: std::io::Error| format!("recording: {e}");
    if offset > 0 {
        f.seek(SeekFrom::Start(offset)).map_err(io)?;
    } else {
        for _ in 0..frame {
            if !skip(&mut f)? {
                return Err("no such frame".into());
            }
        }
    }
    let mut page = Page {
        batch: GateRecord::default(),
        next: None,
        offset: 0,
        started_unix: h.started_unix,
    };
    if let Some(sealed) = get(&mut f, MAX_FRAME)? {
        let plain = open(&key, &aad(uid, session, Some(frame)), &sealed)?;
        page.batch = serde_json::from_slice(&plain).map_err(|_| "damaged recording")?;
        page.offset = f.stream_position().map_err(io)?;
        let len = f.metadata().map_err(io)?.len();
        page.next = (page.offset + 4 <= len).then_some(frame + 1);
    }
    Ok(page)
}

/// `uid`'s recordings, oldest first.
pub fn list(root: &Path, uid: u32) -> Vec<RecordingInfo> {
    let Ok(entries) = fs::read_dir(user_dir(root, uid)) else {
        return Vec::new();
    };
    let mut out: Vec<RecordingInfo> = entries
        .flatten()
        .filter_map(|e| {
            let mut f = File::open(e.path()).ok()?;
            let h = read_header(&mut f).ok()?;
            Some(RecordingInfo {
                started: crate::expiry::format_expires_at(h.started_unix),
                session: h.session,
                started_unix: h.started_unix,
                bytes: f.metadata().ok()?.len(),
            })
        })
        .filter(|r| kepr_core::protocol_gatex::valid_session(&r.session))
        .collect();
    out.sort_by_key(|r| (r.started_unix, r.session.clone()));
    out
}

/// Delete `uid`'s oldest recordings until at most `keep` remain.
fn prune(root: &Path, uid: u32, keep: usize) {
    let all = list(root, uid);
    let excess = all.len().saturating_sub(keep);
    for r in &all[..excess] {
        let _ = fs::remove_file(user_dir(root, uid).join(format!("{}.rec", r.session)));
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use kepr_core::gate_record::{RecChunk, FROM_AGENT, TO_AGENT};

    const KEK: [u8; 32] = [3u8; 32];
    pub const SID: &str = "0123456789abcdef";

    pub fn root() -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "kepr-rec-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    pub fn batch(text: &str) -> GateRecord {
        GateRecord {
            chunks: vec![
                RecChunk::new(1, 1, "db:APP", "postgres", FROM_AGENT, text.as_bytes()),
                RecChunk::new(2, 1, "db:APP", "postgres", TO_AGENT, b"rows"),
            ],
            dropped: 0,
        }
    }

    #[test]
    fn a_recording_round_trips_and_is_never_plaintext_on_disk() {
        let root = root();
        let mut w = Writer::create(&root, 1000, SID, 7, &KEK).unwrap();
        let secret = "SELECT card_number FROM very_private_table";
        w.append(&batch(secret)).unwrap();
        w.append(&batch("SELECT 2")).unwrap();
        drop(w);

        let path = user_dir(&root, 1000).join(format!("{SID}.rec"));
        let raw = fs::read(&path).unwrap();
        let b64 = RecChunk::new(0, 0, "", "", "", secret.as_bytes()).data;
        for needle in [secret.as_bytes(), b64.as_bytes(), b"very_private", b"rows"] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle));
        }
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let first = read(&root, 1000, SID, &KEK, (0, 0)).unwrap();
        assert_eq!((&first.batch, first.next), (&batch(secret), Some(1)));
        assert_eq!(first.started_unix, 7);
        let second = read(&root, 1000, SID, &KEK, (1, 0)).unwrap();
        assert_eq!((&second.batch, second.next), (&batch("SELECT 2"), None));
        // Paging by offset reads the same frame without counting.
        let again = read(&root, 1000, SID, &KEK, (1, first.offset)).unwrap();
        assert_eq!(again, second);
        let listed = list(&root, 1000);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].session, SID);
        assert!(list(&root, 1001).is_empty());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_wrong_master_key_uid_or_frame_order_reads_nothing() {
        let root = root();
        let mut w = Writer::create(&root, 1000, SID, 7, &KEK).unwrap();
        w.append(&batch("a")).unwrap();
        w.append(&batch("b")).unwrap();
        drop(w);
        assert!(read(&root, 1000, SID, &[4u8; 32], (0, 0)).is_err());
        // Another user's directory: the file isn't there, and moved
        // there it doesn't open (uid is in the AAD).
        assert!(read(&root, 1001, SID, &KEK, (0, 0)).is_err());
        fs::create_dir_all(user_dir(&root, 1001)).unwrap();
        let from = user_dir(&root, 1000).join(format!("{SID}.rec"));
        let to = user_dir(&root, 1001).join(format!("{SID}.rec"));
        fs::copy(&from, &to).unwrap();
        assert!(read(&root, 1001, SID, &KEK, (0, 0)).is_err());
        // Swap the two frames: each fails its frame-number check.
        let raw = fs::read(&from).unwrap();
        let hlen = u32::from_be_bytes(raw[10..14].try_into().unwrap()) as usize;
        let body = &raw[14 + hlen..];
        let n1 = u32::from_be_bytes(body[..4].try_into().unwrap()) as usize;
        let (f1, f2) = body.split_at(4 + n1);
        let swapped = [&raw[..14 + hlen], f2, f1].concat();
        fs::write(&from, swapped).unwrap();
        assert!(read(&root, 1000, SID, &KEK, (0, 0)).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_torn_tail_reads_as_the_end_and_a_wrong_offset_fails() {
        let root = root();
        let mut w = Writer::create(&root, 1000, SID, 1, &KEK).unwrap();
        w.append(&batch("a")).unwrap();
        drop(w);
        let path = user_dir(&root, 1000).join(format!("{SID}.rec"));
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0, 0, 1, 0, 9, 9]).unwrap(); // half a frame
        let first = read(&root, 1000, SID, &KEK, (0, 0)).unwrap();
        assert_eq!(first.batch, batch("a"));
        let tail = read(&root, 1000, SID, &KEK, (1, first.offset)).unwrap();
        assert_eq!((tail.batch, tail.next), (GateRecord::default(), None));
        assert!(read(&root, 1000, SID, &KEK, (0, first.offset - 8)).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn starting_a_recording_drops_the_oldest_beyond_the_cap() {
        let root = root();
        for i in 0..MAX_SESSIONS as u64 + 2 {
            let sid = format!("{i:016x}");
            Writer::create(&root, 1000, &sid, 100 + i, &KEK).unwrap();
        }
        let kept = list(&root, 1000);
        assert_eq!(kept.len(), MAX_SESSIONS);
        assert_eq!(kept[0].session, format!("{:016x}", 2));
        assert_eq!(kept[0].started, "1970-01-01 00:01");
        fs::remove_dir_all(&root).unwrap();
    }
}
