// daemon_vault/rollback.rs — the image's anti-rollback anchor (T12.27).
//
// The rollback state file (cred-versions.json) keeps the newest epoch of
// each image, so an older copy of `vault.img` alone is refused. Put back
// together with an older (or deleted) state file, though, such a copy
// opened, and values deleted or rotated since came back. A monotonic
// counter kept off the disk (`EpochCounter`; the TPM2 NV counter of
// T12.30) closes that gap: the header carries an anchor (counter index,
// value) that every commit raises by one, and after each commit the
// counter is raised to match. On open:
//
//   anchor == counter   the current image
//   anchor <  counter   an older copy: refused
//   anchor >  counter   a crash (or a failed increment) between the header
//                       write and the increment: the counter catches up
//   no anchor           fine while the counter is undefined (the next
//                       write anchors the image); refused once it exists
//
// A new image is anchored before its first open. An existing unanchored
// one is anchored by a commit of its own (the index re-sealed at the next
// epoch) before the first write, so a write that then fails can't leave
// an unanchored image behind a counter that now exists.

use super::backend::ImageBackend;
use super::header::Header;
use super::image::{SlotIo, VaultImage};
use super::keys::Keys;

pub trait EpochCounter: Send + Sync {
    fn index(&self) -> u32;
    /// None: not defined yet.
    fn read(&self) -> Result<Option<u64>, String>;
    /// Defines the counter on first use, adds one, returns the new value.
    fn increment(&self) -> Result<u64, String>;
}

/// Most increments a catch-up makes (each anchor step is one commit).
const MAX_CATCH_UP: usize = 1024;

const PREDATES: &str = "vault image refused: it predates the anti-rollback counter";
const OLDER: &str =
    "vault image refused: it is older than the anti-rollback counter (a rolled-back copy?)";

/// Raise the counter to `want`, one increment at a time.
fn catch_up(c: &dyn EpochCounter, want: u64) -> Result<u64, String> {
    let mut n = c
        .read()?
        .ok_or("the anti-rollback counter is not defined")?;
    for _ in 0..MAX_CATCH_UP {
        if n >= want {
            return Ok(n);
        }
        n = c.increment()?;
    }
    if n >= want {
        Ok(n)
    } else {
        Err("vault image refused: the anti-rollback counter is too far behind it".into())
    }
}

/// May an image with header `h` be opened? (See the table at the top.)
pub fn check_open(h: &Header, c: &dyn EpochCounter) -> Result<(), String> {
    let now = c.read().map_err(|e| format!("vault image refused: {e}"))?;
    let Some((index, value)) = h.anchor else {
        return match now {
            None => Ok(()),
            Some(_) => Err(PREDATES.into()),
        };
    };
    if index != c.index() {
        return Err("vault image refused: it is bound to another anti-rollback counter".into());
    }
    match now {
        None => Err("vault image refused: its anti-rollback counter is not defined".into()),
        Some(n) if n > value => Err(OLDER.into()),
        Some(n) if n == value => Ok(()),
        Some(_) => match catch_up(c, value)? {
            n if n == value => Ok(()),
            _ => Err(OLDER.into()),
        },
    }
}

/// Unanchored header: anchor at the counter's current value (defining it
/// if needed). An anchored header is left as it is.
pub fn adopt(h: &mut Header, c: &dyn EpochCounter) -> Result<(), String> {
    if h.anchor.is_some() {
        return Ok(());
    }
    let v = match c.read()? {
        Some(v) => v,
        None => c.increment()?,
    };
    h.anchor = Some((c.index(), v));
    Ok(())
}

/// After a durable commit: increment until counter == anchor value;
/// failures are logged, not returned (the commit already happened).
pub fn after_commit(h: &Header, c: &dyn EpochCounter) {
    let Some((index, value)) = h.anchor else {
        return;
    };
    if index == c.index() && catch_up(c, value).is_err() {
        eprintln!(
            "[kepr-daemon] vault: anti-rollback counter not advanced; it catches up at the next open"
        );
    }
}

impl<I: SlotIo> VaultImage<I> {
    /// Anchor an unanchored image to `c` in a commit of its own. The
    /// commit is prepared first, so the counter is only defined when
    /// nothing but IO can still fail.
    pub(super) fn anchor_to(&mut self, keys: &Keys, c: &dyn EpochCounter) -> Result<(), String> {
        if self.header.anchor.is_some() {
            return Ok(());
        }
        let ix = self.load_index(keys)?;
        let alloc = self.allocator(&ix);
        let mut commit = self.prepare_index(keys, &ix, ix.clone(), alloc, Vec::new())?;
        let mut h = self.header.clone();
        adopt(&mut h, c)?;
        commit.header.anchor = h.anchor.map(|(i, v)| (i, v + 1));
        self.commit(keys, commit)?;
        after_commit(&self.header, c);
        Ok(())
    }
}

impl ImageBackend {
    /// On open: may this header be used? (No counter: yes.)
    pub(super) fn check_counter(&self, h: &Header) -> Result<(), String> {
        self.counter().map_or(Ok(()), |c| check_open(h, c))
    }

    /// Before a write: anchor an unanchored image (T12.27).
    pub(super) fn anchor_first(&self, img: &mut VaultImage, keys: &Keys) -> Result<(), String> {
        self.counter().map_or(Ok(()), |c| img.anchor_to(keys, c))
    }

    /// After a write: the counter follows the anchor.
    pub(super) fn count_commit(&self, h: &Header) {
        if let Some(c) = self.counter() {
            after_commit(h, c);
        }
    }

    /// A new image at this backend's path, anchored to its counter (if
    /// any) before anyone opens it; removed again if anchoring fails.
    pub(super) fn create_image(&self, size_mib: u32, kek: &[u8; 32]) -> Result<VaultImage, String> {
        let mut img = VaultImage::create(self.path(), size_mib, kek)?;
        let Some(c) = self.counter() else {
            return Ok(img);
        };
        let anchored = adopt(&mut img.header, c).and_then(|()| {
            let keys = img.keys(kek);
            img.write_header(&keys)?;
            img.sync()
        });
        match anchored {
            Ok(()) => Ok(img),
            Err(e) => {
                let _ = std::fs::remove_file(self.path());
                Err(e)
            }
        }
    }
}

#[cfg(test)]
pub(super) mod fake {
    use super::EpochCounter;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// A counter in memory. Its first increment jumps to 1000, as a TPM
    /// NV counter starts at the highest value any counter has had.
    #[derive(Default)]
    pub struct FakeCounter {
        pub value: Mutex<Option<u64>>,
        /// The next increment fails without counting.
        pub fail_next: AtomicBool,
    }

    impl FakeCounter {
        pub fn at(v: Option<u64>) -> Self {
            Self {
                value: Mutex::new(v),
                ..Default::default()
            }
        }
        pub fn get(&self) -> Option<u64> {
            *self.value.lock().unwrap()
        }
    }

    impl EpochCounter for FakeCounter {
        fn index(&self) -> u32 {
            0x0180_0A12
        }
        fn read(&self) -> Result<Option<u64>, String> {
            Ok(self.get())
        }
        fn increment(&self) -> Result<u64, String> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err("counter unavailable".into());
            }
            let mut v = self.value.lock().unwrap();
            let n = v.map_or(1000, |x| x + 1);
            *v = Some(n);
            Ok(n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeCounter;
    use super::*;
    use crate::crypto::Backend;
    use crate::daemon_vault::header::{seal_body, BODY_LEN, MAX_INDEX_SLOTS};
    use crate::daemon_vault::index::{Entry, Index};
    use crate::daemon_vault::testio::MemIo;
    use crate::version_state::VersionState;
    use std::os::unix::fs::FileExt;
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    const UID: u32 = 4_212_127;
    const KEK: [u8; 32] = [0x6B; 32];
    /// Where the index slot count sits in a header body.
    const N_AT: usize = 2 + 16 + 4 + 8 + 32 + 4;

    fn key() -> Result<Zeroizing<[u8; 32]>, String> {
        Ok(Zeroizing::new(KEK))
    }

    /// A backend over `dir/vault.img` with its own rollback state file
    /// (`state` names it) and, optionally, the counter.
    fn backend(dir: &Path, state: &str, c: Option<&Arc<FakeCounter>>) -> ImageBackend {
        let vs = Arc::new(VersionState::load(dir.join(state)).unwrap());
        let b = ImageBackend::new(dir.join("vault.img"), key, Some(vs)).with_create_mib(1);
        match c {
            Some(c) => b.with_counter(Arc::clone(c) as Arc<dyn EpochCounter>),
            None => b,
        }
    }

    fn anchor(b: &ImageBackend) -> Option<(u32, u64)> {
        b.with_read(|img, _| Ok(img.header.anchor))
            .unwrap()
            .unwrap()
    }

    /// The header body exactly as the v1 code (before T12.27) wrote it.
    fn v1_body(h: &Header) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&h.image_id);
        b.extend_from_slice(&h.slot_count.to_le_bytes());
        b.extend_from_slice(&h.epoch.to_le_bytes());
        b.extend_from_slice(&h.root);
        b.extend_from_slice(&h.index_len.to_le_bytes());
        b.extend_from_slice(&(h.index_slots.len() as u16).to_le_bytes());
        for s in &h.index_slots {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b.resize(BODY_LEN, 0);
        b
    }

    /// Rewrite the image's header as the v1 code wrote it.
    fn downgrade_to_v1(path: &Path) {
        let img = VaultImage::open(path, &KEK).unwrap();
        assert_eq!(img.header.anchor, None);
        let slot = seal_body(&img.keys(&KEK), img.salt(), &v1_body(&img.header)).unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.write_all_at(&slot[..], 0).unwrap();
    }

    /// `vault resize` builds a second image whose commits raise the same
    /// counter; the renamed copy must open under it, and so must a restart.
    #[test]
    fn a_resized_image_is_the_current_one_under_the_counter() {
        let d = tempfile::tempdir().unwrap();
        let c = Arc::new(FakeCounter::default());
        let b = backend(d.path(), "v.json", Some(&c));
        for i in 0..6 {
            b.encrypt(UID, &format!("K{i}"), format!("v{i}").as_bytes())
                .unwrap();
        }
        let before = c.get().unwrap();
        b.resize(2).unwrap();
        let after = c.get().unwrap();
        assert!(after > before, "the copy's commits raised the counter");
        assert_eq!(
            anchor(&b),
            Some((0x0180_0A12, after)),
            "the new header carries the counter's value"
        );
        assert_eq!(b.decrypt(UID, "K3").unwrap().as_str(), "v3");
        b.encrypt(UID, "AFTER", b"a").unwrap();
        // A restart: a new backend over the file and the same counter.
        let again = backend(d.path(), "v.json", Some(&c));
        assert_eq!(again.decrypt(UID, "AFTER").unwrap().as_str(), "a");
        assert_eq!(again.decrypt(UID, "K0").unwrap().as_str(), "v0");
        // And the state file alone (a fresh one) does not matter to it.
        let fresh_state = backend(d.path(), "other-state.json", Some(&c));
        assert_eq!(fresh_state.decrypt(UID, "K5").unwrap().as_str(), "v5");
    }

    #[test]
    fn v1_headers_still_decode_and_v2_round_trips_the_anchor() {
        let v1 = Header {
            image_id: [3; 16],
            slot_count: 1024,
            epoch: 9,
            root: [4; 32],
            index_len: 100,
            index_slots: (2..258).collect(),
            anchor: None,
        };
        let body = v1_body(&v1);
        assert_eq!(body.len(), BODY_LEN);
        assert_eq!(Header::decode(&body), Ok(v1.clone()), "256 slots in v1");
        assert!(v1.encode().is_err(), "256 slots don't fit a v2 body");
        let v2 = Header {
            index_slots: (2..2 + MAX_INDEX_SLOTS as u32).collect(),
            anchor: Some((0x0180_0A12, 77)),
            ..v1.clone()
        };
        let enc = v2.encode().unwrap();
        assert_eq!(enc.len(), BODY_LEN);
        assert_eq!(&enc[..2], &2u16.to_le_bytes());
        let tail = &enc[BODY_LEN - 12..];
        assert_eq!(&tail[..4], &0x0180_0A12u32.to_le_bytes());
        assert_eq!(&tail[4..], &77u64.to_le_bytes());
        assert_eq!(Header::decode(&enc), Ok(v2.clone()));
        let none = Header {
            anchor: None,
            ..v2.clone()
        };
        assert_eq!(Header::decode(&none.encode().unwrap()), Ok(none));
        // A v2 body claiming 254 index slots is malformed.
        let mut forged = enc.clone();
        forged[N_AT..N_AT + 2].copy_from_slice(&254u16.to_le_bytes());
        assert!(Header::decode(&forged).is_err());
        // Index 0 means "no anchor", so it can't be one.
        let zero = Header {
            anchor: Some((0, 5)),
            ..v2
        };
        assert!(zero.encode().is_err());
        let mut v3 = enc;
        v3[..2].copy_from_slice(&3u16.to_le_bytes());
        assert!(Header::decode(&v3).unwrap_err().contains("version"));
    }

    #[test]
    fn a_rolled_back_copy_is_refused_without_the_state_file() {
        let d = tempfile::tempdir().unwrap();
        let c = Arc::new(FakeCounter::default());
        let b = backend(d.path(), "v.json", Some(&c));
        b.encrypt(UID, "A", b"first").unwrap();
        let copy = std::fs::read(b.path()).unwrap();
        b.encrypt(UID, "B", b"second").unwrap();
        b.delete(UID, "A").unwrap();
        assert_eq!(anchor(&b).map(|a| a.1), c.get());
        std::fs::write(b.path(), &copy).unwrap();
        // The state file can be rolled back (or deleted) with the image:
        // without the counter the copy opens and A comes back.
        let plain = backend(d.path(), "fresh-a.json", None);
        assert_eq!(plain.decrypt(UID, "A").unwrap().as_str(), "first");
        let restarted = backend(d.path(), "fresh-b.json", Some(&c));
        let err = restarted.decrypt(UID, "A").unwrap_err();
        assert!(
            err.contains("older than the anti-rollback counter"),
            "{err}"
        );
        assert!(restarted.encrypt(UID, "C", b"x").is_err());
    }

    #[test]
    fn a_crash_before_the_increment_catches_up() {
        let d = tempfile::tempdir().unwrap();
        let c = Arc::new(FakeCounter::default());
        let b = backend(d.path(), "v.json", Some(&c));
        b.encrypt(UID, "A", b"a").unwrap();
        c.fail_next.store(true, Ordering::SeqCst);
        b.encrypt(UID, "B", b"b").unwrap();
        let (_, want) = anchor(&b).unwrap();
        assert_eq!(c.get(), Some(want - 1));
        let reopened = backend(d.path(), "v.json", Some(&c));
        assert_eq!(reopened.decrypt(UID, "B").unwrap().as_str(), "b");
        assert_eq!(c.get(), Some(want));
    }

    #[test]
    fn an_unanchored_image_is_refused_once_the_counter_exists() {
        let d = tempfile::tempdir().unwrap();
        let plain = backend(d.path(), "v.json", None);
        plain.encrypt(UID, "A", b"a").unwrap();
        let c = Arc::new(FakeCounter::at(Some(5)));
        let b = backend(d.path(), "v.json", Some(&c));
        let err = b.decrypt(UID, "A").unwrap_err();
        assert!(err.contains("predates the anti-rollback counter"), "{err}");
        assert!(b.encrypt(UID, "B", b"b").unwrap_err().contains("predates"));
        assert_eq!(c.get(), Some(5), "nothing counted");
    }

    #[test]
    fn an_unanchored_image_is_adopted_while_the_counter_is_new() {
        let d = tempfile::tempdir().unwrap();
        let plain = backend(d.path(), "v.json", None);
        plain.encrypt(UID, "A", b"a").unwrap();
        drop(plain);
        // As the code before T12.27 left it: a v1 header.
        downgrade_to_v1(&d.path().join("vault.img"));
        let c = Arc::new(FakeCounter::default());
        let b = backend(d.path(), "v.json", Some(&c));
        assert_eq!(b.decrypt(UID, "A").unwrap().as_str(), "a");
        assert_eq!(c.get(), None, "a read anchors nothing");
        b.encrypt(UID, "B", b"b").unwrap();
        let (index, value) = anchor(&b).unwrap();
        assert_eq!((index, Some(value)), (0x0180_0A12, c.get()));
        // Defined at 1000, then the anchoring commit and B's commit.
        assert_eq!(value, 1002);
        let reopened = backend(d.path(), "v.json", Some(&c));
        assert_eq!(reopened.decrypt(UID, "A").unwrap().as_str(), "a");
        assert_eq!(reopened.decrypt(UID, "B").unwrap().as_str(), "b");
        assert!(reopened.check().unwrap().is_some());
    }

    #[test]
    fn a_v1_image_without_a_counter_keeps_working() {
        let d = tempfile::tempdir().unwrap();
        let plain = backend(d.path(), "v.json", None);
        plain.encrypt(UID, "A", b"a").unwrap();
        drop(plain);
        downgrade_to_v1(&d.path().join("vault.img"));
        let b = backend(d.path(), "v.json", None);
        assert_eq!(b.decrypt(UID, "A").unwrap().as_str(), "a");
        b.encrypt(UID, "B", b"b").unwrap();
        assert_eq!(anchor(&b), None, "no counter, no anchor");
        let again = backend(d.path(), "v.json", None);
        assert_eq!(again.decrypt(UID, "A").unwrap().as_str(), "a");
        assert_eq!(again.decrypt(UID, "B").unwrap().as_str(), "b");
        assert_eq!(again.check().unwrap(), Some((2, 3)));
    }

    #[test]
    fn a_failed_first_write_still_leaves_the_image_anchored() {
        let d = tempfile::tempdir().unwrap();
        let plain = backend(d.path(), "v.json", None);
        plain.encrypt(UID, "A", b"a").unwrap();
        drop(plain);
        let c = Arc::new(FakeCounter::default());
        let b = backend(d.path(), "v.json", Some(&c));
        // Bigger than the 1 MiB image: the write fails after anchoring.
        let big = vec![b'x'; 2 << 20];
        let err = b.encrypt(UID, "BIG", &big).unwrap_err();
        assert!(err.contains("full"), "{err}");
        let reopened = backend(d.path(), "v.json", Some(&c));
        assert_eq!(reopened.decrypt(UID, "A").unwrap().as_str(), "a");
        assert_eq!(anchor(&reopened).map(|a| a.1), c.get());
    }

    #[test]
    fn a_new_image_is_anchored_at_once() {
        let d = tempfile::tempdir().unwrap();
        let c = Arc::new(FakeCounter::at(Some(41)));
        backend(d.path(), "v.json", Some(&c)).create(1).unwrap();
        let img = VaultImage::open(&d.path().join("vault.img"), &KEK).unwrap();
        let want = (0, Some((0x0180_0A12, 41)));
        assert_eq!((img.header.epoch, img.header.anchor), want);
        let b = backend(d.path(), "v.json", Some(&c));
        assert_eq!(b.check().unwrap(), Some((0, 0)));
        assert_eq!(c.get(), Some(41), "opening counts nothing");
        // An undefined counter is defined for the new image.
        let d = tempfile::tempdir().unwrap();
        let c = Arc::new(FakeCounter::default());
        backend(d.path(), "v.json", Some(&c)).create(1).unwrap();
        assert_eq!(c.get(), Some(1000));
        assert!(backend(d.path(), "v.json", Some(&c)).check().is_ok());
    }

    struct Broken(u32);
    impl EpochCounter for Broken {
        fn index(&self) -> u32 {
            self.0
        }
        fn read(&self) -> Result<Option<u64>, String> {
            Err("cannot use the TPM2 anti-rollback counter".into())
        }
        fn increment(&self) -> Result<u64, String> {
            Err("cannot use the TPM2 anti-rollback counter".into())
        }
    }

    #[test]
    fn a_counter_that_fails_or_differs_keeps_the_image_closed() {
        let d = tempfile::tempdir().unwrap();
        let c = Arc::new(FakeCounter::default());
        let b = backend(d.path(), "v.json", Some(&c));
        b.encrypt(UID, "A", b"a").unwrap();
        drop(b);
        let broken = backend(d.path(), "v.json", None).with_counter(Arc::new(Broken(0x0180_0A12)));
        assert!(broken.decrypt(UID, "A").unwrap_err().contains("refused"));
        // A counter at another index.
        let other = Reindexed(Arc::new(FakeCounter::at(c.get())), 0x0180_0A13);
        let b = backend(d.path(), "v.json", None).with_counter(Arc::new(other));
        assert!(b.decrypt(UID, "A").unwrap_err().contains("another"));
        // A counter that disappeared (a cleared TPM).
        let gone = Arc::new(FakeCounter::default());
        let err = backend(d.path(), "v.json", Some(&gone))
            .decrypt(UID, "A")
            .unwrap_err();
        assert!(err.contains("not defined"), "{err}");
        // A new image isn't left behind when the counter can't be used.
        let d = tempfile::tempdir().unwrap();
        let b = backend(d.path(), "v.json", None).with_counter(Arc::new(Broken(0x0180_0A12)));
        assert!(b.create(1).is_err());
        assert!(b.encrypt(UID, "A", b"a").is_err());
        assert!(!d.path().join("vault.img").exists());
    }

    struct Reindexed(Arc<FakeCounter>, u32);
    impl EpochCounter for Reindexed {
        fn index(&self) -> u32 {
            self.1
        }
        fn read(&self) -> Result<Option<u64>, String> {
            self.0.read()
        }
        fn increment(&self) -> Result<u64, String> {
            self.0.increment()
        }
    }

    #[test]
    fn v2_index_is_capped_at_253_slots() {
        let mut img = VaultImage::format(MemIo::new(4 << 20), 1024, &KEK).unwrap();
        let keys = img.keys(&KEK);
        // 4 + n × 108 bytes: 9520 entries need 253 pages, 9521 need 254.
        let index = |n: u32| Index {
            entries: (0..n)
                .map(|i| {
                    let e = Entry {
                        record_id: [1; 16],
                        wrapped_key: [2; 60],
                        epoch: 1,
                        updated: 1,
                        value_len: 0,
                        has_value: false,
                        pages: Vec::new(),
                    };
                    (format!("R{i:06}"), e)
                })
                .collect(),
        };
        let old = Index::default();
        let alloc = img.allocator(&old);
        let err = img
            .commit_index(&keys, &old, index(9521), alloc, Vec::new())
            .unwrap_err();
        assert!(err.contains("vault index is full"), "{err}");
        let alloc = img.allocator(&old);
        img.commit_index(&keys, &old, index(9520), alloc, Vec::new())
            .unwrap();
        assert_eq!(img.header.index_slots.len(), MAX_INDEX_SLOTS);
        assert_eq!(img.load_index(&keys).unwrap().entries.len(), 9520);
    }
}
