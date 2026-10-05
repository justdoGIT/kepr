// atomic_file.rs — the one durable "replace this file" helper for every
// daemon-owned file (credentials, .meta sidecars, the rollback counters,
// master-key envelopes, FIDO2 registrations, share state).
//
//   1. a temp file next to the target with an unpredictable name,
//      created O_EXCL at `mode` (never wider, not even briefly);
//   2. write + fsync the data;
//   3. rename over the target (atomic on one filesystem);
//   4. fsync the directory so the rename itself survives a crash.
//
// Without (2) a crash after the rename can leave a zero-length file on
// ext4 (no auto_da_alloc), xfs or btrfs; without (4) the old name can
// come back. Any failure removes the temp file.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

fn tmp_name(path: &Path) -> Result<std::path::PathBuf, String> {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let name = path
        .file_name()
        .ok_or("invalid path (no file name)")?
        .to_string_lossy();
    Ok(path.with_file_name(format!(".{name}.tmp.{}", hex::encode(rnd))))
}

/// fsync a directory (makes a rename or unlink inside it durable).
pub fn sync_dir(dir: &Path) -> Result<(), String> {
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("{}: fsync: {e}", dir.display()))
}

/// Durably replace `path` with `bytes`, created at `mode`.
pub fn write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let dir = path.parent().ok_or("invalid path (no parent)")?;
    let tmp = tmp_name(path)?;
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        drop(f);
        fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    sync_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn replaces_with_mode_and_leaves_no_temp_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("cred");
        write(&p, b"one", 0o600).unwrap();
        write(&p, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_failed_write_cleans_up() {
        let d = tempfile::tempdir().unwrap();
        // Renaming a file over a non-empty directory fails.
        let target = d.path().join("dir");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("x"), b"x").unwrap();
        assert!(write(&target, b"data", 0o600).is_err());
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }
}
