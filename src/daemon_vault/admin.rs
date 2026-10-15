// daemon_vault/admin.rs — image-level operations behind `kepr vault`
// (T4.07): create an image of a chosen size, check all of it, and report
// how full it is. Each takes the backend's lock, so none of them can
// interleave with a credential write.

use super::backend::{ImageBackend, Open};
use super::image::{FIRST_DATA_SLOT, SLOTS_PER_MIB};

/// How full the image is.
#[derive(Debug, PartialEq, Eq)]
pub struct Usage {
    pub size_mib: u32,
    /// Slots holding records or the index (the header and the journal
    /// slot are not counted).
    pub used_slots: u64,
    pub data_slots: u64,
    pub epoch: u64,
}

impl ImageBackend {
    /// Create the image at `size_mib`; never over an existing one.
    pub fn create(&self, size_mib: u32) -> Result<(), String> {
        let mut st = self.lock();
        let kek = self.key(&mut st)?;
        if self.path().exists() {
            return Err("a vault image already exists".into());
        }
        let img = self.create_image(size_mib, &kek)?;
        self.record_epoch(&img);
        *st = Some(Open { img, index: None });
        Ok(())
    }

    /// Re-read the image from disk and check the index, every record
    /// page and the Merkle root: (records, slots checked). `Ok(None)`:
    /// there is no image.
    pub fn check(&self) -> Result<Option<(usize, usize)>, String> {
        let mut st = self.lock();
        let kek = self.key(&mut st)?;
        if !self.path().exists() {
            return Ok(None);
        }
        // A fresh open, so the header on disk is what gets checked.
        *st = None;
        let open = self.open(&kek)?;
        let keys = open.img.keys(&kek);
        let r = open.img.verify_records(&keys)?;
        *st = Some(open);
        Ok(Some(r))
    }

    /// `Ok(None)`: there is no image.
    pub fn usage(&self) -> Result<Option<Usage>, String> {
        self.with_index(|img, _, ix| {
            let h = &img.header;
            Ok(Usage {
                size_mib: h.slot_count / SLOTS_PER_MIB,
                used_slots: (ix.record_slots().count() + h.index_slots.len()) as u64,
                data_slots: u64::from(h.slot_count - FIRST_DATA_SLOT),
                epoch: h.epoch,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Backend;
    use crate::daemon_vault::image::SLOT;
    use crate::store;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    const UID: u32 = 4242;

    fn key() -> Result<Zeroizing<[u8; 32]>, String> {
        Ok(Zeroizing::new([0x5A; 32]))
    }
    fn locked() -> Result<Zeroizing<[u8; 32]>, String> {
        Err("credential store is locked".into())
    }

    fn fresh() -> (ImageBackend, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let vs = crate::version_state::VersionState::load(dir.path().join("v.json")).unwrap();
        let b = ImageBackend::new(dir.path().join("vault.img"), key, Some(Arc::new(vs)))
            .with_create_mib(2);
        (b, dir)
    }

    fn flip(path: &std::path::Path, at: u64) {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut b = [0u8; 1];
        f.seek(SeekFrom::Start(at)).unwrap();
        f.read_exact(&mut b).unwrap();
        f.seek(SeekFrom::Start(at)).unwrap();
        f.write_all(&[b[0] ^ 0x08]).unwrap();
    }

    #[test]
    fn create_sizes_the_image_and_never_overwrites_one() {
        let (b, _d) = fresh();
        assert_eq!(b.usage().unwrap(), None, "no image yet");
        b.create(2).unwrap();
        assert_eq!(std::fs::metadata(b.path()).unwrap().len(), 2 << 20);
        let u = b.usage().unwrap().unwrap();
        assert_eq!((u.size_mib, u.used_slots, u.epoch), (2, 0, 0));
        assert_eq!(u.data_slots, 2 * 256 - 2);
        let err = b.create(2).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        assert!(b.create(0).is_err());
    }

    #[test]
    fn create_and_check_fail_while_locked() {
        let d = tempfile::tempdir().unwrap();
        let b = ImageBackend::new(d.path().join("vault.img"), locked, None);
        assert!(b.create(1).is_err());
        assert!(!d.path().join("vault.img").exists());
        assert!(b.check().is_err());
    }

    #[test]
    fn usage_counts_record_and_index_slots() {
        let (b, _d) = fresh();
        b.encrypt(UID, "SMALL", b"v").unwrap();
        b.encrypt(UID, "BIG", &[b'x'; 9000]).unwrap();
        let u = b.usage().unwrap().unwrap();
        // 1 + 3 record pages and one index page.
        assert_eq!(u.used_slots, 5);
        assert_eq!(u.size_mib, 2, "with_create_mib sized the first write");
        assert_eq!(u.epoch, 2);
    }

    #[test]
    fn check_passes_a_clean_image_and_names_a_damaged_slot() {
        let (b, _d) = fresh();
        assert_eq!(b.check().unwrap(), None, "no image: nothing to check");
        b.encrypt(UID, "ALPHA", b"alpha").unwrap();
        b.encrypt(UID, "BETA", b"beta").unwrap();
        assert_eq!(b.check().unwrap(), Some((2, 3)));

        let name = store::to_cred_name(UID, "BETA");
        let slot = b
            .with_index(|_, _, ix| Ok(ix.entries[&name].pages[0].0))
            .unwrap()
            .unwrap();
        flip(b.path(), u64::from(slot) * SLOT as u64 + 1000);
        let err = b.check().unwrap_err();
        assert!(err.contains(&format!("slot {slot}")), "{err}");
        // ALPHA is untouched and still reads; BETA fails closed.
        assert_eq!(b.decrypt(UID, "ALPHA").unwrap().as_str(), "alpha");
        assert!(b.decrypt(UID, "BETA").is_err());
    }
}
