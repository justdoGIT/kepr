// daemon_vault/migrate.rs — `kepr vault migrate` (T4.07): move every
// per-file credential (value, `.meta`, history slots `NAME~N`, and since
// T4.14 trash entries `NAME~t<unix>[~N]`, attachment chunks `NAME~a<k>~<n>`
// and aliases, which are `.meta` only) into the vault image, one record at
// a time.
//
// Each move runs under the credential's lock: decrypt the file, write
// value + meta as one record (a journaled, fsynced commit), read the
// record back and compare, and only then delete the file (which
// tombstones its rollback counter, so the old file can't be replayed)
// and its `.meta`. If the image already holds a different record under
// that name, the image's is newer (it is the live store): the file
// stays. If it holds the same one, an earlier run stopped before the
// removals, and this one finishes them. A failure stops the run; what
// moved stays moved and the rest stays in files, so running it again
// picks up where it left off. Values are compared in memory and never
// leave the daemon.

use std::path::Path;

use super::backend::ImageBackend;
use super::index::Record;
use crate::crypto::Backend;

/// One per-file credential: (file name, uid, NAME or NAME~N).
pub type FileCred = (String, u32, String);

/// `kepr-<uid>-<name>`, history slots `kepr-<uid>-<name>~<n>` and trash
/// entries `…~t<unix>[~<n>]` in `dir` (sidecars and temp files excluded),
/// sorted; only `uid`'s when given.
pub fn legacy_files(dir: &Path, only_uid: Option<u32>) -> Vec<FileCred> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<FileCred> = entries
        .flatten()
        .filter_map(|e| {
            let f = e.file_name().to_str()?.to_string();
            let (uid, name) = parse(&f)?;
            only_uid.is_none_or(|u| u == uid).then_some((f, uid, name))
        })
        .collect();
    out.sort();
    out
}

/// `kepr-<uid>-<name>[~…]` → (uid, NAME[~…]); `None` for anything
/// else, sidecars and temp files included.
fn parse(file: &str) -> Option<(u32, String)> {
    crate::daemon_store::files::parse_file_name(file)
}

/// Move what's in `dir` into `image`: (moved, left in files). The caller
/// runs one at a time (a second run would find files half gone).
pub fn migrate_from(
    image: &ImageBackend,
    files: &dyn Backend,
    dir: &Path,
) -> Result<(usize, usize), String> {
    let (mut moved, mut left) = (0, 0);
    for (file, uid, name) in legacy_files(dir, None) {
        let _lock = crate::daemon_credlock::lock(uid, base_name(&name));
        let r = move_one(image, files, dir, (&file, uid, &name));
        crate::daemon_cache::invalidate(uid);
        match r {
            Ok(true) => moved += 1,
            Ok(false) => left += 1,
            Err(e) => return Err(format!("{e} ({moved} moved before this)")),
        }
    }
    let aliases = finish_meta(image, dir)?;
    Ok((moved + aliases, left))
}

/// NAME of NAME~N: the credential lock covers its history slots.
fn base_name(name: &str) -> &str {
    name.split('~').next().unwrap_or(name)
}

/// Ok(false): left in its file (the image holds another value under its
/// name, or the file doesn't read).
fn move_one(
    image: &ImageBackend,
    files: &dyn Backend,
    dir: &Path,
    (file, uid, name): (&str, u32, &str),
) -> Result<bool, String> {
    let Ok(value) = files.decrypt(uid, name) else {
        return Ok(false);
    };
    let meta_path = dir.join(format!("{file}.meta"));
    let meta = match std::fs::read(&meta_path) {
        Ok(m) if serde_json::from_slice::<crate::expiry::CredMeta>(&m).is_ok() => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        _ => return Ok(false),
    };
    // Value and meta byte for byte (sealed / ssh policy included).
    let same = |r: &Option<Record>| {
        r.as_ref().is_some_and(|r| {
            r.value.as_deref().map(Vec::as_slice) == Some(value.as_bytes()) && r.meta == meta
        })
    };
    let held = image.record(file)?;
    if held.is_some() && !same(&held) {
        // The image is the live store: what it holds is newer.
        return Ok(false);
    }
    // Held and the same: a run stopped before removing the files.
    if held.is_none() {
        image.with_write(|img, keys| {
            img.put_record(keys, file, Some(value.as_bytes()), meta.as_deref())
        })?;
        if !same(&image.record(file)?) {
            image.with_write(|img, keys| img.remove_record(keys, file))?;
            return Err("vault migrate: a record did not read back".into());
        }
    }
    // The file first: a stop between the two leaves only the `.meta`,
    // which `remove_moved_meta` clears on the next run.
    files.delete(uid, name)?;
    if meta.is_some() {
        std::fs::remove_file(&meta_path).map_err(|e| format!("remove meta: {e}"))?;
    }
    Ok(true)
}

/// `.meta` files whose credential file is gone: an alias the image has
/// no record for moves in as a meta-only record (T4.14); one the image
/// holds byte for byte (a moved alias, or what a run stopped mid-removal
/// leaves) is removed. Any other `.meta` stays. Returns aliases moved.
fn finish_meta(image: &ImageBackend, dir: &Path) -> Result<usize, String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(0);
    };
    let mut moved = 0;
    for e in entries.flatten() {
        let f = e.file_name();
        let Some(file) = f.to_str().and_then(|f| f.strip_suffix(".meta")) else {
            continue;
        };
        let Some((uid, name)) = parse(file) else {
            continue;
        };
        let _lock = crate::daemon_credlock::lock(uid, base_name(&name));
        if dir.join(file).exists() {
            continue;
        }
        let Ok(bytes) = std::fs::read(e.path()) else {
            continue;
        };
        let same = |r: &Option<Record>| {
            r.as_ref()
                .is_some_and(|r| r.meta.as_deref() == Some(&bytes[..]))
        };
        let mut rec = image.record(file)?;
        if rec.is_none() && is_alias(&bytes) {
            image.with_write(|img, keys| img.put_record(keys, file, None, Some(&bytes)))?;
            rec = image.record(file)?;
            if !same(&rec) {
                return Err("vault migrate: a record did not read back".into());
            }
            moved += 1;
        }
        if same(&rec) {
            std::fs::remove_file(e.path()).map_err(|e| format!("remove meta: {e}"))?;
        }
    }
    Ok(moved)
}

fn is_alias(meta: &[u8]) -> bool {
    serde_json::from_slice::<crate::expiry::CredMeta>(meta).is_ok_and(|m| m.alias_of.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_inproc::InProcBackend;
    use crate::expiry::{self, CredMeta, MetaStore};
    use crate::store;
    use crate::version_state::VersionState;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    const UID: u32 = 31337;
    const KEY: [u8; 32] = [0x3C; 32];

    fn key() -> Result<Zeroizing<[u8; 32]>, String> {
        Ok(Zeroizing::new(KEY))
    }

    struct Fixture {
        dir: tempfile::TempDir,
        files: InProcBackend,
        image: ImageBackend,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir(&store).unwrap();
        let vs = Arc::new(VersionState::load(dir.path().join("v.json")).unwrap());
        let files = InProcBackend::with_store_dir(&KEY, store.clone(), Arc::clone(&vs));
        let image = ImageBackend::new(store.join("vault.img"), key, Some(vs));
        Fixture { dir, files, image }
    }

    impl Fixture {
        fn store(&self) -> std::path::PathBuf {
            self.dir.path().join("store")
        }
        fn meta_path(&self, name: &str) -> std::path::PathBuf {
            self.store()
                .join(format!("{}.meta", store::to_cred_name(UID, name)))
        }
        fn kepr_files(&self) -> Vec<String> {
            let mut v: Vec<String> = std::fs::read_dir(self.store())
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("kepr-"))
                .collect();
            v.sort();
            v
        }
    }

    #[test]
    fn legacy_files_lists_credentials_and_history_slots_only() {
        let d = tempfile::tempdir().unwrap();
        for f in [
            "kepr-1000-plain",
            "kepr-1000-plain.meta",
            "kepr-1000-plain~0",
            "kepr-1000-plain~t17",
            "kepr-1000-plain~t17~2",
            "kepr-1000-plain~a3~1",
            "kepr-1000-plain~x",
            "kepr-1000-plain.tmp.12.3",
            "kepr-1000-bad..name",
            "kepr-1001-other-name",
            "vault.img",
            "kepr-abc-plain",
        ] {
            std::fs::write(d.path().join(f), b"x").unwrap();
        }
        let all = legacy_files(d.path(), None);
        let want = |f: &str, u: u32, n: &str| (f.to_string(), u, n.to_string());
        assert_eq!(
            all,
            vec![
                want("kepr-1000-plain", 1000, "PLAIN"),
                want("kepr-1000-plain~0", 1000, "PLAIN~0"),
                want("kepr-1000-plain~a3~1", 1000, "PLAIN~a3~1"),
                want("kepr-1000-plain~t17", 1000, "PLAIN~t17"),
                want("kepr-1000-plain~t17~2", 1000, "PLAIN~t17~2"),
                want("kepr-1001-other-name", 1001, "OTHER_NAME"),
            ]
        );
        assert_eq!(legacy_files(d.path(), Some(1001)).len(), 1);
        assert!(legacy_files(&d.path().join("missing"), None).is_empty());
    }

    #[test]
    fn migrate_moves_values_meta_and_history_then_removes_the_files() {
        let f = fixture();
        f.files.encrypt(UID, "PLAIN", b"plain-value").unwrap();
        f.files.encrypt(UID, "TTL", b"ttl-value").unwrap();
        f.files.encrypt(UID, "TTL~0", b"kh2:0:1:-:older").unwrap();
        let meta = CredMeta {
            expires_at_unix: Some(4_000_000_000),
            ..Default::default()
        };
        expiry::write_meta_file(&f.meta_path("TTL"), &meta).unwrap();

        assert_eq!(migrate_from(&f.image, &f.files, &f.store()), Ok((3, 0)));
        assert_eq!(f.kepr_files(), Vec::<String>::new(), "files are gone");
        assert_eq!(
            f.image.decrypt(UID, "PLAIN").unwrap().as_str(),
            "plain-value"
        );
        assert_eq!(f.image.decrypt(UID, "TTL").unwrap().as_str(), "ttl-value");
        assert_eq!(
            f.image.decrypt(UID, "TTL~0").unwrap().as_str(),
            "kh2:0:1:-:older"
        );
        assert_eq!(f.image.read_meta(&f.meta_path("TTL")), Some(Ok(meta)));
        assert_eq!(f.image.read_meta(&f.meta_path("PLAIN")), None);
        // The old files can't come back: their counters are tombstoned.
        assert!(f.files.decrypt(UID, "PLAIN").is_err());
        // Nothing left to do.
        assert_eq!(migrate_from(&f.image, &f.files, &f.store()), Ok((0, 0)));
    }

    #[test]
    fn migrate_leaves_what_the_image_already_has_and_unreadable_files() {
        let f = fixture();
        f.files.encrypt(UID, "BOTH", b"old-file-value").unwrap();
        f.image.encrypt(UID, "BOTH", b"newer-image-value").unwrap();
        f.files.encrypt(UID, "GOOD", b"good").unwrap();
        std::fs::write(f.store().join(store::to_cred_name(UID, "JUNK")), b"junk").unwrap();
        std::fs::write(f.meta_path("BAD_META"), b"{not json").unwrap();
        f.files.encrypt(UID, "BAD_META", b"v").unwrap();

        assert_eq!(migrate_from(&f.image, &f.files, &f.store()), Ok((1, 3)));
        assert_eq!(
            f.image.decrypt(UID, "BOTH").unwrap().as_str(),
            "newer-image-value"
        );
        assert_eq!(f.image.decrypt(UID, "GOOD").unwrap().as_str(), "good");
        assert!(f.image.decrypt(UID, "JUNK").is_err());
        assert!(f.image.decrypt(UID, "BAD_META").is_err());
        let left = f.kepr_files();
        assert!(left.contains(&store::to_cred_name(UID, "BOTH")), "{left:?}");
        assert!(left.contains(&store::to_cred_name(UID, "JUNK")), "{left:?}");
        assert_eq!(left.len(), 4, "{left:?}");
    }

    /// What a run stopped between the image commit and the file
    /// removals leaves behind: the record in the image, the files too.
    fn copy_only(f: &Fixture, name: &str) {
        let file = store::to_cred_name(UID, name);
        let value = f.files.decrypt(UID, name).unwrap();
        let meta = std::fs::read(f.meta_path(name)).ok();
        f.image
            .with_write(|img, keys| {
                img.put_record(keys, &file, Some(value.as_bytes()), meta.as_deref())
            })
            .unwrap();
    }

    #[test]
    fn a_run_stopped_after_the_copy_is_finished_by_the_next_one() {
        let f = fixture();
        f.files.encrypt(UID, "HALF", b"half-value").unwrap();
        f.files
            .encrypt(UID, "HALF~1", b"kh2:1:5:abc:older")
            .unwrap();
        let meta = CredMeta {
            sealed: Some(true),
            ..Default::default()
        };
        expiry::write_meta_file(&f.meta_path("HALF"), &meta).unwrap();
        copy_only(&f, "HALF");
        copy_only(&f, "HALF~1");

        assert_eq!(migrate_from(&f.image, &f.files, &f.store()), Ok((2, 0)));
        assert_eq!(f.kepr_files(), Vec::<String>::new(), "files are gone");
        assert_eq!(f.image.decrypt(UID, "HALF").unwrap().as_str(), "half-value");
        assert_eq!(
            f.image.decrypt(UID, "HALF~1").unwrap().as_str(),
            "kh2:1:5:abc:older"
        );
        assert_eq!(f.image.read_meta(&f.meta_path("HALF")), Some(Ok(meta)));
    }

    #[test]
    fn a_meta_file_left_behind_goes_once_the_image_holds_it() {
        let f = fixture();
        f.files.encrypt(UID, "GONE", b"v").unwrap();
        let meta = CredMeta {
            expires_at_unix: Some(4_000_000_000),
            ..Default::default()
        };
        expiry::write_meta_file(&f.meta_path("GONE"), &meta).unwrap();
        assert_eq!(migrate_from(&f.image, &f.files, &f.store()), Ok((1, 0)));
        // A run stopped between removing the file and its `.meta`.
        expiry::write_meta_file(&f.meta_path("GONE"), &meta).unwrap();
        // A `.meta` the image doesn't hold is not ours to remove.
        let stray = CredMeta {
            expires_at_unix: Some(1),
            ..Default::default()
        };
        expiry::write_meta_file(&f.meta_path("STRAY"), &stray).unwrap();
        expiry::write_meta_file(&f.meta_path("GONE~0"), &stray).unwrap();

        assert_eq!(migrate_from(&f.image, &f.files, &f.store()), Ok((0, 0)));
        let stray_file = |n: &str| format!("{}.meta", store::to_cred_name(UID, n));
        assert_eq!(f.kepr_files(), [stray_file("GONE~0"), stray_file("STRAY")]);
        assert_eq!(f.image.read_meta(&f.meta_path("GONE")), Some(Ok(meta)));
    }

    /// T4.14: the trash and aliases come along.
    #[test]
    fn migrate_moves_trash_entries_and_aliases() {
        let f = fixture();
        f.files.encrypt(UID, "PLAIN", b"plain").unwrap();
        f.files.encrypt(UID, "OLD~t17", b"trashed").unwrap();
        f.files.encrypt(UID, "OLD~t17~0", b"kh2:0:1:-:x").unwrap();
        let trashed = CredMeta {
            sealed: Some(true),
            trashed_at: Some(17),
            ..Default::default()
        };
        expiry::write_meta_file(&f.meta_path("OLD~t17"), &trashed).unwrap();
        let alias = CredMeta {
            alias_of: Some("PLAIN".into()),
            tags: Some(vec!["x".into()]),
            ..Default::default()
        };
        expiry::write_meta_file(&f.meta_path("SHORT"), &alias).unwrap();
        let stray = CredMeta {
            expires_at_unix: Some(1),
            ..Default::default()
        };
        expiry::write_meta_file(&f.meta_path("STRAY"), &stray).unwrap();

        assert_eq!(migrate_from(&f.image, &f.files, &f.store()), Ok((4, 0)));
        let stray_file = format!("{}.meta", store::to_cred_name(UID, "STRAY"));
        assert_eq!(f.kepr_files(), [stray_file], "only the stray meta stays");
        assert_eq!(f.image.decrypt(UID, "OLD~t17").unwrap().as_str(), "trashed");
        assert!(f.image.exists(UID, "OLD~t17~0"));
        let read = |n: &str| f.image.read_meta(&f.meta_path(n));
        assert_eq!(read("OLD~t17"), Some(Ok(trashed)));
        assert_eq!(read("SHORT"), Some(Ok(alias)));
        assert!(!f.image.exists(UID, "SHORT"), "an alias holds no value");
        assert_eq!(migrate_from(&f.image, &f.files, &f.store()), Ok((0, 0)));
    }

    #[test]
    fn migrate_stops_at_the_first_write_failure_and_keeps_the_file() {
        let f = fixture();
        f.image.create(1).unwrap();
        // 1 MiB = 254 data slots; this value needs more than that.
        let big = vec![b'z'; 300 * 4064];
        f.files
            .encrypt(UID, "HUGE", std::str::from_utf8(&big).unwrap().as_bytes())
            .unwrap();
        let err = migrate_from(&f.image, &f.files, &f.store()).unwrap_err();
        assert!(err.contains("full"), "{err}");
        assert_eq!(f.kepr_files(), [store::to_cred_name(UID, "HUGE")]);
        assert_eq!(f.files.decrypt(UID, "HUGE").unwrap().len(), big.len());
    }
}
