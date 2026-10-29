// daemon_vault/backend.rs — the image as a credential backend (T4.06).
//
// `KEPR_STORE=image` makes the daemon keep credentials, their `.meta`
// and their history slots (`NAME~N`) as records in one image instead of
// one file each. The seam is narrow: `crypto::Backend` for values, the
// `expiry::MetaStore` trait for `.meta`, and list / exists / stat for
// `store.rs`. Records are keyed by the per-file store's file name,
// `kepr-<uid>-<name>`, so the uid is part of the AAD-bound name and
// listing by uid prefix works as before.
//
// Each operation fetches the master key (failing while the store is
// locked), derives the image keys, and drops them when done. One mutex
// serialises the image; it caches the open file and the decrypted index
// (names and wrapped keys only, never a value), and drops both after a
// failed write so the next call re-opens and recovers. The newest epoch
// is recorded in the rollback state, so an older copy of the image is
// refused; with a counter (rollback.rs, T12.27) a copy is refused even
// when the state file was rolled back with it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use kepr_core::generate::ZeroString;
use zeroize::Zeroizing;

use super::image::VaultImage;
use super::index::{Index, Record};
use super::keys::Keys;
use super::rollback::EpochCounter;
use crate::crypto::Backend;
use crate::expiry::{CredMeta, MetaStore};
use crate::store;
use crate::version_state::VersionState;

pub type KeySource = fn() -> Result<Zeroizing<[u8; 32]>, String>;

pub(super) struct Open {
    pub(super) img: VaultImage,
    pub(super) index: Option<Index>,
}

pub struct ImageBackend {
    path: PathBuf,
    kek: KeySource,
    versions: Option<Arc<VersionState>>,
    /// Size of the image the first write creates (MiB).
    create_mib: u32,
    /// The off-disk counter the header is anchored to (T12.27).
    counter: Option<Arc<dyn EpochCounter>>,
    state: Mutex<Option<Open>>,
}

impl ImageBackend {
    pub fn new(path: PathBuf, kek: KeySource, versions: Option<Arc<VersionState>>) -> Self {
        Self {
            path,
            kek,
            versions,
            create_mib: kepr_core::protocol_vault::DEFAULT_IMAGE_MIB,
            counter: None,
            state: Mutex::new(None),
        }
    }

    /// Bind the image to an anti-rollback counter kept off the disk.
    pub fn with_counter(mut self, c: Arc<dyn EpochCounter>) -> Self {
        self.counter = Some(c);
        self
    }

    /// A backend over another file with the same key source, rollback
    /// state and counter (the copy `resize` builds).
    pub(super) fn sibling(&self, path: PathBuf) -> Self {
        let b = Self::new(path, self.kek, self.versions.clone());
        match &self.counter {
            Some(c) => b.with_counter(Arc::clone(c)),
            None => b,
        }
    }

    pub(super) fn counter(&self) -> Option<&dyn EpochCounter> {
        self.counter.as_deref()
    }

    /// Tests: a small first-write image instead of 64 MiB of noise each.
    #[cfg(test)]
    pub(crate) fn with_create_mib(mut self, mib: u32) -> Self {
        self.create_mib = mib;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new("/"))
    }

    pub(super) fn lock(&self) -> MutexGuard<'_, Option<Open>> {
        // A panic mid-operation leaves at worst a stale cache: drop it.
        self.state.lock().unwrap_or_else(|p| {
            let mut g = p.into_inner();
            *g = None;
            g
        })
    }

    pub(super) fn key(&self, st: &mut Option<Open>) -> Result<Zeroizing<[u8; 32]>, String> {
        (self.kek)().inspect_err(|_| *st = None)
    }

    pub(super) fn open(&self, kek: &[u8; 32]) -> Result<Open, String> {
        let img = VaultImage::open(&self.path, kek)?;
        self.check_counter(&img.header)?;
        if let Some(v) = &self.versions {
            v.verify(&epoch_key(&img.header.image_id), img.header.epoch)
                .map_err(|e| format!("vault image refused: {e}"))?;
        }
        self.record_epoch(&img);
        Ok(Open { img, index: None })
    }

    pub(super) fn record_epoch(&self, img: &VaultImage) {
        if let Some(v) = &self.versions {
            if let Err(e) = v.raise(&epoch_key(&img.header.image_id), img.header.epoch) {
                eprintln!("[kepr-daemon] vault: cannot record the image epoch: {e}");
            }
        }
    }

    /// Run `f` on the image and its (cached) index. `Ok(None)`: there is
    /// no image yet, which reads as an empty store.
    pub(super) fn with_index<T>(
        &self,
        f: impl FnOnce(&VaultImage, &Keys, &Index) -> Result<T, String>,
    ) -> Result<Option<T>, String> {
        let mut st = self.lock();
        let kek = self.key(&mut st)?;
        if st.is_none() {
            if !self.path.exists() {
                return Ok(None);
            }
            *st = Some(self.open(&kek)?);
        }
        let open = st.as_mut().expect("opened above");
        let keys = open.img.keys(&kek);
        if open.index.is_none() {
            open.index = Some(open.img.load_index(&keys)?);
        }
        let ix = open.index.as_ref().expect("loaded above");
        f(&open.img, &keys, ix).map(Some)
    }

    #[cfg(test)]
    pub(super) fn with_read<T>(
        &self,
        f: impl FnOnce(&VaultImage, &Keys) -> Result<T, String>,
    ) -> Result<Option<T>, String> {
        self.with_index(|img, keys, _| f(img, keys))
    }

    /// Run a write on the image, creating it on first use. Any error
    /// drops the cache, so the next call re-opens (and recovers).
    pub(super) fn with_write<T>(
        &self,
        f: impl FnOnce(&mut VaultImage, &Keys) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut st = self.lock();
        let kek = self.key(&mut st)?;
        if st.is_none() {
            *st = Some(if self.path.exists() {
                self.open(&kek)?
            } else {
                Open {
                    img: self.create_image(self.create_mib, &kek)?,
                    index: None,
                }
            });
        }
        let open = st.as_mut().expect("opened above");
        open.index = None;
        let keys = open.img.keys(&kek);
        let r = self
            .anchor_first(&mut open.img, &keys)
            .and_then(|()| f(&mut open.img, &keys));
        match &r {
            Ok(_) => {
                self.record_epoch(&open.img);
                self.count_commit(&open.img.header);
            }
            Err(_) => *st = None,
        }
        r
    }

    pub(super) fn record(&self, key: &str) -> Result<Option<Record>, String> {
        Ok(self
            .with_index(|img, keys, ix| img.read_record(keys, ix, key))?
            .flatten())
    }

    /// The caller's credentials (not history slots or meta-only records),
    /// sorted, with the path the per-file store would use. Empty while
    /// the store is locked.
    pub fn list(&self, uid: u32) -> Vec<(String, PathBuf)> {
        let prefix = format!("{}-{uid}-", store::CRED_PREFIX);
        let dir = self.dir().to_path_buf();
        self.with_index(|_, _, ix| {
            Ok(ix
                .entries
                .iter()
                .filter(|(k, e)| e.has_value && k.starts_with(&prefix))
                .filter_map(|(k, _)| store::from_cred_name(k).map(|(_, n)| (n, dir.join(k))))
                .collect())
        })
        .ok()
        .flatten()
        .unwrap_or_default()
    }

    pub fn exists(&self, uid: u32, name: &str) -> bool {
        let key = store::to_cred_name(uid, name);
        self.with_index(|_, _, ix| Ok(ix.entries.get(&key).is_some_and(|e| e.has_value)))
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// (size as the per-file store would report it, last write time).
    pub fn stat(&self, record: &str) -> Option<(u64, u64)> {
        self.with_index(|_, _, ix| {
            Ok(ix
                .entries
                .get(record)
                .filter(|e| e.has_value)
                .map(|e| (u64::from(e.value_len) + FILE_OVERHEAD, e.updated)))
        })
        .ok()
        .flatten()
        .flatten()
    }
}

/// magic (8) + nonce (12) + counter (8) + tag (16) in a per-file cred.
const FILE_OVERHEAD: u64 = 44;

fn epoch_key(image_id: &[u8; 16]) -> String {
    format!("kepr-vault-{}", hex::encode(image_id))
}

fn not_found(name: &str) -> String {
    format!("credential not found: {name}")
}

impl Backend for ImageBackend {
    fn encrypt(&self, uid: u32, name: &str, value: &[u8]) -> Result<(), String> {
        let key = store::to_cred_name(uid, name);
        self.with_write(|img, keys| {
            let ix = img.load_index(keys)?;
            let meta = img.read_record(keys, &ix, &key)?.and_then(|r| r.meta);
            img.put_record(keys, &key, Some(value), meta.as_deref())
        })
    }

    fn decrypt(&self, uid: u32, name: &str) -> Result<ZeroString, String> {
        let rec = self.record(&store::to_cred_name(uid, name))?;
        let value = rec.and_then(|r| r.value).ok_or_else(|| not_found(name))?;
        let s = std::str::from_utf8(&value)
            .map_err(|_| "credential contains invalid UTF-8".to_string())?;
        Ok(ZeroString::from_string(
            s.trim_end_matches('\n').to_string(),
        ))
    }

    /// Crypto-shreds the whole record, `.meta` included.
    fn delete(&self, uid: u32, name: &str) -> Result<(), String> {
        let key = store::to_cred_name(uid, name);
        if !self.exists(uid, name) {
            return Err(not_found(name));
        }
        self.with_write(|img, keys| img.remove_record(keys, &key).map(drop))
    }

    /// One commit: the record (value and meta) re-keyed under `to`.
    fn rename(&self, uid: u32, from: &str, to: &str) -> Result<(), String> {
        if self.exists(uid, to) {
            return Err(format!("{to} already holds a value"));
        }
        if !self.exists(uid, from) {
            return Err(not_found(from));
        }
        let (f, t) = (store::to_cred_name(uid, from), store::to_cred_name(uid, to));
        self.with_write(|img, keys| img.rename_record(keys, &f, &t))?
            .then_some(())
            .ok_or_else(|| not_found(from))
    }
}

/// `kepr-<uid>-<name>.meta` → `kepr-<uid>-<name>`.
fn record_of(meta_path: &Path) -> Option<String> {
    let f = meta_path.file_name()?.to_str()?;
    f.strip_suffix(".meta").map(str::to_string)
}

impl MetaStore for ImageBackend {
    fn read_meta(&self, meta_path: &Path) -> Option<Result<CredMeta, String>> {
        let key = record_of(meta_path)?;
        match self.record(&key) {
            Ok(rec) => rec?
                .meta
                .map(|m| serde_json::from_slice(&m).map_err(|e| format!("parse meta: {e}"))),
            Err(e) => Some(Err(e)),
        }
    }

    fn write_meta(&self, meta_path: &Path, meta: &CredMeta) -> Result<(), String> {
        let key = record_of(meta_path).ok_or("invalid meta path")?;
        let json = serde_json::to_vec(meta).map_err(|e| format!("serialise meta: {e}"))?;
        self.with_write(|img, keys| {
            let ix = img.load_index(keys)?;
            let value = img.read_record(keys, &ix, &key)?.and_then(|r| r.value);
            img.put_record(keys, &key, value.as_deref().map(Vec::as_slice), Some(&json))
        })
    }

    fn delete_meta(&self, meta_path: &Path) {
        let Some(key) = record_of(meta_path) else {
            return;
        };
        if !matches!(self.record(&key), Ok(Some(Record { meta: Some(_), .. }))) {
            return;
        }
        let r = self.with_write(|img, keys| {
            let ix = img.load_index(keys)?;
            match img.read_record(keys, &ix, &key)?.and_then(|r| r.value) {
                Some(v) => img.put_record(keys, &key, Some(&v), None),
                None => img.remove_record(keys, &key).map(drop),
            }
        });
        if let Err(e) = r {
            eprintln!("[kepr-daemon] vault: meta delete failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: u32 = 999_999;

    fn key() -> Result<Zeroizing<[u8; 32]>, String> {
        Ok(Zeroizing::new([0xAB; 32]))
    }
    fn locked() -> Result<Zeroizing<[u8; 32]>, String> {
        Err("credential store is locked".into())
    }

    fn fresh() -> (ImageBackend, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let vs = Arc::new(VersionState::load(dir.path().join("v.json")).unwrap());
        let b = ImageBackend::new(dir.path().join("vault.img"), key, Some(vs)).with_create_mib(2);
        (b, dir)
    }

    fn meta_path(dir: &Path, uid: u32, name: &str) -> PathBuf {
        dir.join(format!("{}.meta", store::to_cred_name(uid, name)))
    }

    /// Move an index entry to another name, as an attacker with the
    /// keys' help could, and re-commit it.
    fn rename_entry(b: &ImageBackend, from: &str, to: &str) {
        b.with_write(|img, keys| {
            let old = img.load_index(keys)?;
            let mut ix = old.clone();
            let e = ix.entries.remove(from).unwrap();
            ix.entries.insert(to.to_string(), e);
            let alloc = img.allocator(&old);
            img.commit_index(keys, &old, ix, alloc, Vec::new())
        })
        .unwrap();
    }

    #[test]
    fn round_trip_succeeds() {
        let (b, _d) = fresh();
        b.encrypt(UID, "ROUND_TRIP", b"hunter2\n").unwrap();
        assert_eq!(b.decrypt(UID, "ROUND_TRIP").unwrap().as_str(), "hunter2");
        b.encrypt(UID, "ROUND_TRIP", b"second").unwrap();
        assert_eq!(b.decrypt(UID, "ROUND_TRIP").unwrap().as_str(), "second");
    }

    #[test]
    fn decrypt_with_wrong_uid_fails() {
        let (b, _d) = fresh();
        b.encrypt(UID, "WRONG_UID", b"hunter2").unwrap();
        assert!(b
            .decrypt(UID + 1, "WRONG_UID")
            .unwrap_err()
            .contains("not found"));
        rename_entry(
            &b,
            &store::to_cred_name(UID, "WRONG_UID"),
            &store::to_cred_name(UID + 1, "WRONG_UID"),
        );
        let err = b.decrypt(UID + 1, "WRONG_UID").err().unwrap();
        assert!(err.contains("authentication"), "got: {err}");
    }

    #[test]
    fn decrypt_with_wrong_name_fails() {
        let (b, _d) = fresh();
        b.encrypt(UID, "NAME_A", b"hunter2").unwrap();
        rename_entry(
            &b,
            &store::to_cred_name(UID, "NAME_A"),
            &store::to_cred_name(UID, "NAME_B"),
        );
        let err = b.decrypt(UID, "NAME_B").err().unwrap();
        assert!(err.contains("authentication"), "got: {err}");
    }

    #[test]
    fn missing_and_deleted_credentials_are_not_found() {
        let (b, _d) = fresh();
        assert!(b
            .decrypt(UID, "MISSING")
            .unwrap_err()
            .contains("credential not found"));
        assert!(b
            .delete(UID, "MISSING")
            .unwrap_err()
            .contains("credential not found"));
        b.encrypt(UID, "DELETE", b"x").unwrap();
        b.delete(UID, "DELETE").unwrap();
        assert!(!b.exists(UID, "DELETE"));
        assert!(b
            .delete(UID, "DELETE")
            .unwrap_err()
            .contains("credential not found"));
    }

    #[test]
    fn list_is_per_uid_sorted_and_hides_history_slots() {
        let (b, d) = fresh();
        b.encrypt(UID, "B_KEY", b"b").unwrap();
        b.encrypt(UID, "A_KEY", b"a").unwrap();
        b.encrypt(UID, "A_KEY~1", b"old a").unwrap();
        b.encrypt(UID + 1, "OTHER", b"o").unwrap();
        let names: Vec<String> = b.list(UID).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["A_KEY", "B_KEY"]);
        assert_eq!(b.list(UID)[0].1.parent(), Some(d.path()));
        assert!(b.exists(UID, "A_KEY~1"));
        assert_eq!(b.decrypt(UID, "A_KEY~1").unwrap().as_str(), "old a");
        b.delete(UID, "A_KEY~1").unwrap();
        assert!(!b.exists(UID, "A_KEY~1"));
        let (size, updated) = b.stat(&store::to_cred_name(UID, "B_KEY")).unwrap();
        assert_eq!(size, 1 + 44);
        assert!(updated > 1_700_000_000);
    }

    #[test]
    fn meta_lives_with_the_value() {
        let (b, d) = fresh();
        let mp = meta_path(d.path(), UID, "M");
        let meta = CredMeta {
            sealed: Some(true),
            ..Default::default()
        };
        // Meta first (the sealed path): not yet a credential.
        b.write_meta(&mp, &meta).unwrap();
        assert!(!b.exists(UID, "M"));
        assert!(b.list(UID).is_empty());
        b.encrypt(UID, "M", b"v").unwrap();
        assert_eq!(b.read_meta(&mp).unwrap().unwrap(), meta);
        // Rewriting the value keeps the meta; dropping the meta keeps the value.
        b.encrypt(UID, "M", b"w").unwrap();
        assert_eq!(b.read_meta(&mp).unwrap().unwrap(), meta);
        b.delete_meta(&mp);
        assert!(b.read_meta(&mp).is_none());
        assert_eq!(b.decrypt(UID, "M").unwrap().as_str(), "w");
        // Deleting the credential takes the meta with it.
        b.write_meta(&mp, &meta).unwrap();
        b.delete(UID, "M").unwrap();
        assert!(b.read_meta(&mp).is_none());
        // A meta-only record goes away with its meta.
        b.write_meta(&mp, &meta).unwrap();
        b.delete_meta(&mp);
        assert!(b
            .with_read(|img, keys| img.load_index(keys))
            .unwrap()
            .unwrap()
            .entries
            .is_empty());
    }

    #[test]
    fn rename_moves_the_record_with_its_meta() {
        let (b, d) = fresh();
        let meta = CredMeta {
            sealed: Some(true),
            ..Default::default()
        };
        b.write_meta(&meta_path(d.path(), UID, "OLD"), &meta)
            .unwrap();
        b.encrypt(UID, "OLD", b"v").unwrap();
        b.encrypt(UID, "TAKEN", b"t").unwrap();
        let err = b.rename(UID, "OLD", "TAKEN").unwrap_err();
        assert!(err.contains("already holds"), "{err}");
        assert!(b
            .rename(UID, "NONE", "NEW")
            .unwrap_err()
            .contains("not found"));
        b.rename(UID, "OLD", "NEW~t5").unwrap();
        assert!(!b.exists(UID, "OLD"));
        assert!(b.read_meta(&meta_path(d.path(), UID, "OLD")).is_none());
        assert_eq!(b.decrypt(UID, "NEW~t5").unwrap().as_str(), "v");
        let moved = b.read_meta(&meta_path(d.path(), UID, "NEW~t5"));
        assert_eq!(moved, Some(Ok(meta)));
        assert_eq!(b.decrypt(UID, "TAKEN").unwrap().as_str(), "t");
    }

    #[test]
    fn a_locked_store_fails_closed_and_reads_no_meta() {
        let (b, d) = fresh();
        b.encrypt(UID, "K", b"v").unwrap();
        let locked = ImageBackend::new(b.path().to_path_buf(), locked, None);
        assert!(locked.decrypt(UID, "K").unwrap_err().contains("locked"));
        assert!(locked
            .encrypt(UID, "K", b"x")
            .unwrap_err()
            .contains("locked"));
        assert!(locked
            .read_meta(&meta_path(d.path(), UID, "K"))
            .unwrap()
            .is_err());
    }

    #[test]
    fn no_image_reads_as_empty_and_the_first_write_creates_it() {
        let (b, _d) = fresh();
        assert!(b.list(UID).is_empty());
        assert!(!b.path().exists());
        b.encrypt(UID, "FIRST", b"v").unwrap();
        let md = std::fs::metadata(b.path()).unwrap();
        assert_eq!(md.len(), 2 << 20);
    }

    #[test]
    fn new_backend_creates_64_mib_images() {
        let d = tempfile::tempdir().unwrap();
        let b = ImageBackend::new(d.path().join("vault.img"), key, None);
        assert_eq!(b.create_mib, 64);
        assert_eq!(b.create_mib, kepr_core::protocol_vault::DEFAULT_IMAGE_MIB);
        assert!(!b.path().exists(), "nothing is written up front");
    }

    #[test]
    fn with_create_mib_sizes_the_first_write_image() {
        let d = tempfile::tempdir().unwrap();
        let b = ImageBackend::new(d.path().join("vault.img"), key, None).with_create_mib(1);
        b.encrypt(UID, "FIRST", b"v").unwrap();
        assert_eq!(std::fs::metadata(b.path()).unwrap().len(), 1 << 20);
        assert_eq!(b.decrypt(UID, "FIRST").unwrap().as_str(), "v");
    }

    #[test]
    fn an_older_copy_of_the_image_is_refused() {
        let (b, d) = fresh();
        b.encrypt(UID, "K", b"one").unwrap();
        let old = std::fs::read(b.path()).unwrap();
        b.encrypt(UID, "K", b"two").unwrap();
        std::fs::write(b.path(), &old).unwrap();
        let vs = Arc::new(VersionState::load(d.path().join("v.json")).unwrap());
        let restarted = ImageBackend::new(b.path().to_path_buf(), key, Some(vs));
        let err = restarted.decrypt(UID, "K").err().unwrap();
        assert!(err.contains("rollback"), "{err}");
    }
}
