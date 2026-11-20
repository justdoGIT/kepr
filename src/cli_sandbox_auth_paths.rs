//! Metadata-only resolution of credential names, symlink targets and SQLite sidecars.
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub(super) fn validate(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().contains(&0)
        || path.components().any(|part| matches!(part, Component::ParentDir))
    {
        return Err("credential cache paths must be absolute and contain no parent traversal or NUL".into());
    }
    Ok(())
}

fn resolve(path: &Path) -> Result<Option<PathBuf>, String> {
    validate(path)?;
    // Check every existing prefix: ENOENT must not silently hide a dangling
    // symlink, and permission/loop/type errors must stop the launch.
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part);
        match std::fs::symlink_metadata(&prefix) {
            Ok(meta) if meta.file_type().is_symlink() => {
                std::fs::canonicalize(&prefix)
                    .map_err(|_| "cannot resolve credential cache symlink")?;
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("cannot inspect credential cache path".into()),
        }
    }
    let real = std::fs::canonicalize(path).map_err(|_| "cannot resolve credential cache")?;
    let meta = std::fs::metadata(&real).map_err(|_| "cannot inspect credential cache target")?;
    if !meta.is_file() {
        return Err("credential cache must be a regular file".into());
    }
    if meta.nlink() != 1 {
        return Err("credential cache has hard-link aliases that cannot be isolated".into());
    }
    Ok(Some(real))
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

pub(super) fn append(path: &Path, sqlite: bool, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let real = resolve(path)?;
    if let Some(real) = real.as_ref() {
        out.push(path.to_path_buf());
        out.push(real.clone());
    }
    if sqlite {
        for suffix in ["-wal", "-shm", "-journal"] {
            append(&sidecar(path, suffix), false, out)?;
            if let Some(real) = real.as_ref().filter(|real| real.as_path() != path) {
                append(&sidecar(real, suffix), false, out)?;
            }
        }
    }
    Ok(())
}
