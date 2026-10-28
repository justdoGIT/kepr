// daemon_vault/resize.rs — `kepr vault resize` and `kepr vault to-files`
// (T13.11).
//
// resize: a new image of the asked size is built beside the old one
// (`vault.img.resize`), every record copied through the normal commit path
// (a fresh record key and fresh placement each, the write time kept), the
// copy checked record by record and by the Merkle root, and only then
// renamed over the old image. Any failure before the rename removes the
// copy and leaves the old image as it was. Growing is always allowed;
// shrinking only when the used slots fit with 25 % spare. With a rollback
// counter the copy's commits advance it, so after a failed rename the copy
// is the current image: the error says where it is.
//
// to-files: `migrate` backwards. Each record is written as a per-file
// credential (and `.meta`), read back and compared, and only then removed
// from the image. A record whose file already exists with another value is
// left. Restart the daemon without KEPR_STORE=image afterwards.

use std::path::Path;

use super::backend::ImageBackend;
use super::image::{FIRST_DATA_SLOT, SLOTS_PER_MIB};
use crate::crypto::Backend;

/// What a resize did.
#[derive(Debug, PartialEq, Eq)]
pub struct Resized {
    pub old_mib: u32,
    pub new_mib: u32,
    pub records: usize,
}

/// Whether `used` slots fit a `new_mib` image with a quarter spare.
pub fn fits(used: u64, new_mib: u32) -> bool {
    let data = u64::from(new_mib) * u64::from(SLOTS_PER_MIB) - u64::from(FIRST_DATA_SLOT);
    used * 5 <= data * 4
}

impl ImageBackend {
    pub fn resize(&self, new_mib: u32) -> Result<Resized, String> {
        if !(1..=4096).contains(&new_mib) {
            return Err("size: 1 to 4096 MiB".into());
        }
        let mut st = self.lock();
        let kek = self.key(&mut st)?;
        if !self.path().exists() {
            return Err("there is no vault image (kepr vault init)".into());
        }
        // A fresh open: what is on disk is what gets copied.
        *st = None;
        let open = self.open(&kek)?;
        let keys = open.img.keys(&kek);
        let index = open.img.load_index(&keys)?;
        let h = &open.img.header;
        let old_mib = h.slot_count / SLOTS_PER_MIB;
        if new_mib == old_mib {
            return Err(format!("the image is already {old_mib} MiB"));
        }
        let used = (index.record_slots().count() + h.index_slots.len()) as u64;
        if new_mib < old_mib && !fits(used, new_mib) {
            return Err(format!(
                "{used} slots are in use: too full for {new_mib} MiB (a shrink keeps 25 % spare)"
            ));
        }
        let copy_path = self.path().with_extension("img.resize");
        let _ = std::fs::remove_file(&copy_path);
        let copy = self.sibling(copy_path.clone());
        let built = copy_records(&open, &keys, &index, &copy, new_mib);
        if let Err(e) = built {
            let _ = std::fs::remove_file(&copy_path);
            return Err(format!("resize failed, the image is unchanged: {e}"));
        }
        drop(copy);
        std::fs::rename(&copy_path, self.path()).map_err(|e| {
            format!(
                "resized image is at {} but could not replace the old one: {e}",
                copy_path.display()
            )
        })?;
        if let Ok(d) = std::fs::File::open(self.path().parent().unwrap_or(Path::new("/"))) {
            let _ = d.sync_all();
        }
        // The next call opens the new file.
        *st = None;
        Ok(Resized {
            old_mib,
            new_mib,
            records: index.entries.len(),
        })
    }

    /// Move every record into per-file credentials in `dir`; (moved, left).
    pub fn to_files(&self, files: &dyn Backend, dir: &Path) -> Result<(usize, usize), String> {
        let (mut moved, mut left) = (0, 0);
        for (key, _) in self.records()? {
            let Some((uid, name)) = crate::daemon_store::files::parse_file_name(&key) else {
                left += 1;
                continue;
            };
            let _lock = crate::daemon_credlock::lock(uid, name.split('~').next().unwrap_or(&name));
            let r = self.record_to_file(files, dir, (&key, uid, &name));
            crate::daemon_cache::invalidate(uid);
            match r {
                Ok(true) => moved += 1,
                Ok(false) => left += 1,
                Err(e) => return Err(format!("{e} ({moved} moved before this)")),
            }
        }
        Ok((moved, left))
    }

    fn record_to_file(
        &self,
        files: &dyn Backend,
        dir: &Path,
        (key, uid, name): (&str, u32, &str),
    ) -> Result<bool, String> {
        let Some(rec) = self.record(key)? else {
            return Ok(false);
        };
        let meta_path = dir.join(format!("{key}.meta"));
        if let Some(v) = &rec.value {
            // A file already there with another value is not ours to replace.
            if let Ok(have) = files.decrypt(uid, name) {
                if have.as_bytes() != v.as_slice() {
                    return Ok(false);
                }
            } else {
                files.encrypt(uid, name, v)?;
            }
            let back = files.decrypt(uid, name)?;
            if back.as_bytes() != v.as_slice() {
                return Err("vault to-files: a credential did not read back".into());
            }
        }
        if let Some(m) = &rec.meta {
            crate::atomic_file::write(&meta_path, m, 0o600)
                .map_err(|e| format!("write meta: {e}"))?;
            if std::fs::read(&meta_path).map_err(|e| e.to_string())? != *m {
                return Err("vault to-files: a .meta did not read back".into());
            }
        }
        self.with_write(|img, keys| img.remove_record(keys, key))?;
        Ok(true)
    }
}

/// Create `copy` at `new_mib` and put every record of `src` into it, then
/// check it. Values are held one record at a time.
fn copy_records(
    src: &super::backend::Open,
    keys: &super::keys::Keys,
    index: &super::index::Index,
    copy: &ImageBackend,
    new_mib: u32,
) -> Result<(), String> {
    copy.create(new_mib)?;
    for (name, entry) in &index.entries {
        let rec = src
            .img
            .read_record(keys, index, name)?
            .ok_or("a record listed in the index did not read")?;
        let (value, meta) = (rec.value.as_deref().map(Vec::as_slice), rec.meta.as_deref());
        copy.with_write(|img, k| img.put_record_at(k, name, (value, meta), Some(entry.updated)))?;
        let got = copy.record(name)?.ok_or("a record did not read back")?;
        if got.value.as_deref().map(Vec::as_slice) != value || got.meta.as_deref() != meta {
            return Err("a record did not read back the same".into());
        }
    }
    match copy.check()? {
        Some((n, _)) if n == index.entries.len() => Ok(()),
        _ => Err("the copy did not verify".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_inproc::InProcBackend;
    use crate::expiry::{CredMeta, MetaStore};
    use crate::store;
    use crate::version_state::VersionState;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    const UID: u32 = 4711;
    const KEY: [u8; 32] = [0x6D; 32];

    fn key() -> Result<Zeroizing<[u8; 32]>, String> {
        Ok(Zeroizing::new(KEY))
    }

    struct Fx {
        dir: tempfile::TempDir,
        image: ImageBackend,
        files: InProcBackend,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let store_dir = dir.path().join("store");
        std::fs::create_dir(&store_dir).unwrap();
        let vs = Arc::new(VersionState::load(dir.path().join("v.json")).unwrap());
        let files = InProcBackend::with_store_dir(&KEY, store_dir.clone(), Arc::clone(&vs));
        let image =
            ImageBackend::new(store_dir.join("vault.img"), key, Some(vs)).with_create_mib(2);
        Fx { dir, image, files }
    }

    impl Fx {
        fn meta(&self, name: &str) -> std::path::PathBuf {
            self.dir
                .path()
                .join("store")
                .join(format!("{}.meta", store::to_cred_name(UID, name)))
        }
        fn fill(&self) {
            self.image.encrypt(UID, "ALPHA", b"alpha-value").unwrap();
            self.image.encrypt(UID, "BIG", &vec![b'x'; 9000]).unwrap();
            self.image.encrypt(UID, "ALPHA~0", b"older").unwrap();
            let m = CredMeta {
                expires_at_unix: Some(4_000_000_000),
                ..Default::default()
            };
            self.image.write_meta(&self.meta("ALPHA"), &m).unwrap();
            let alias = CredMeta {
                alias_of: Some("ALPHA".into()),
                ..Default::default()
            };
            self.image.write_meta(&self.meta("LINK"), &alias).unwrap();
        }
    }

    #[test]
    fn growing_keeps_every_record_meta_and_age() {
        let f = fx();
        f.fill();
        let ages: Vec<_> = f
            .image
            .records()
            .unwrap()
            .iter()
            .map(|(k, _)| (k.clone(), f.image.updated(k).unwrap()))
            .collect();
        let r = f.image.resize(4).unwrap();
        assert_eq!((r.old_mib, r.new_mib, r.records), (2, 4, 4));
        assert_eq!(std::fs::metadata(f.image.path()).unwrap().len(), 4 << 20);
        assert_eq!(
            f.image.decrypt(UID, "ALPHA").unwrap().as_str(),
            "alpha-value"
        );
        assert_eq!(f.image.decrypt(UID, "BIG").unwrap().len(), 9000);
        assert_eq!(f.image.decrypt(UID, "ALPHA~0").unwrap().as_str(), "older");
        assert_eq!(
            f.image
                .read_meta(&f.meta("ALPHA"))
                .unwrap()
                .unwrap()
                .expires_at_unix,
            Some(4_000_000_000)
        );
        assert!(f
            .image
            .read_meta(&f.meta("LINK"))
            .unwrap()
            .unwrap()
            .alias_of
            .is_some());
        for (k, t) in ages {
            assert_eq!(f.image.updated(&k), Some(t), "{k}");
        }
        assert_eq!(f.image.check().unwrap().unwrap().0, 4);
        assert!(!f.image.path().with_extension("img.resize").exists());
        // Writes work on the new image.
        f.image.encrypt(UID, "NEW", b"n").unwrap();
        assert_eq!(f.image.decrypt(UID, "NEW").unwrap().as_str(), "n");
    }

    #[test]
    fn the_same_size_and_bad_sizes_are_refused() {
        let f = fx();
        f.fill();
        assert!(f.image.resize(2).unwrap_err().contains("already 2 MiB"));
        assert!(f.image.resize(0).is_err());
        assert!(f.image.resize(5000).is_err());
        assert_eq!(
            f.image.decrypt(UID, "ALPHA").unwrap().as_str(),
            "alpha-value"
        );
    }

    #[test]
    fn a_shrink_that_does_not_fit_is_refused_and_one_that_fits_works() {
        let f = fx();
        f.image.resize(1).unwrap_err(); // no image yet
        f.fill();
        f.image.resize(8).unwrap();
        f.image.encrypt(UID, "HUGE", &vec![b'y'; 600_000]).unwrap();
        let e = f.image.resize(1).unwrap_err();
        assert!(e.contains("too full for 1 MiB"), "{e}");
        assert_eq!(f.image.decrypt(UID, "HUGE").unwrap().len(), 600_000);
        f.image.delete(UID, "HUGE").unwrap();
        let r = f.image.resize(2).unwrap();
        assert_eq!((r.old_mib, r.new_mib), (8, 2));
        assert_eq!(f.image.decrypt(UID, "BIG").unwrap().len(), 9000);
    }

    #[test]
    fn a_failed_copy_leaves_the_old_image_usable() {
        let f = fx();
        f.fill();
        // The copy's path is taken by a directory: creating it fails.
        std::fs::create_dir(f.image.path().with_extension("img.resize")).unwrap();
        let e = f.image.resize(4).unwrap_err();
        assert!(e.contains("the image is unchanged"), "{e}");
        assert_eq!(std::fs::metadata(f.image.path()).unwrap().len(), 2 << 20);
        assert_eq!(
            f.image.decrypt(UID, "ALPHA").unwrap().as_str(),
            "alpha-value"
        );
        assert_eq!(f.image.check().unwrap().unwrap().0, 4);
    }

    #[test]
    fn fits_keeps_a_quarter_spare() {
        // 1 MiB = 256 slots, 254 data; 80 % of that is 203.
        assert!(fits(203, 1));
        assert!(!fits(204, 1));
    }

    #[test]
    fn to_files_writes_values_and_meta_then_empties_the_image() {
        let f = fx();
        f.fill();
        let dir = f.dir.path().join("store");
        let (moved, left) = f.image.to_files(&f.files, &dir).unwrap();
        assert_eq!((moved, left), (4, 0));
        assert_eq!(
            f.files.decrypt(UID, "ALPHA").unwrap().as_str(),
            "alpha-value"
        );
        assert_eq!(f.files.decrypt(UID, "ALPHA~0").unwrap().as_str(), "older");
        assert_eq!(f.files.decrypt(UID, "BIG").unwrap().len(), 9000);
        let meta = crate::expiry::read_meta_file(&f.meta("ALPHA"))
            .unwrap()
            .unwrap();
        assert_eq!(meta.expires_at_unix, Some(4_000_000_000));
        let alias = crate::expiry::read_meta_file(&f.meta("LINK"))
            .unwrap()
            .unwrap();
        assert!(alias.alias_of.is_some());
        assert!(f.image.records().unwrap().is_empty(), "the image is empty");
        // Nothing left to do.
        assert_eq!(f.image.to_files(&f.files, &dir), Ok((0, 0)));
    }

    #[test]
    fn to_files_leaves_a_record_whose_file_holds_another_value() {
        let f = fx();
        f.image.encrypt(UID, "BOTH", b"image-value").unwrap();
        f.image.encrypt(UID, "ONLY", b"only").unwrap();
        f.files.encrypt(UID, "BOTH", b"file-value").unwrap();
        let dir = f.dir.path().join("store");
        assert_eq!(f.image.to_files(&f.files, &dir), Ok((1, 1)));
        assert_eq!(f.files.decrypt(UID, "BOTH").unwrap().as_str(), "file-value");
        assert_eq!(
            f.image.decrypt(UID, "BOTH").unwrap().as_str(),
            "image-value"
        );
        assert_eq!(f.files.decrypt(UID, "ONLY").unwrap().as_str(), "only");
    }
}
