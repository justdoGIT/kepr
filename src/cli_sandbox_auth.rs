// Mask Codex credential caches by path and symlink target, without reading them.

use std::ffi::CString;
use std::path::PathBuf;

pub fn hidden_cstrings(
    env: &[(String, String)],
    hidden_dirs: &[PathBuf],
) -> Result<Vec<CString>, String> {
    let mut out = crate::cli_sandbox_bus::hidden_cstrings();
    for path in files(env)? {
        if !hidden_dirs.iter().any(|dir| path.starts_with(dir)) {
            out.push(
                CString::new(path.as_os_str().as_encoded_bytes())
                    .map_err(|_| "bad credential cache path")?,
            );
        }
    }
    Ok(out)
}

pub fn files(env: &[(String, String)]) -> Result<Vec<PathBuf>, String> {
    let get = |key: &str| {
        env.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| PathBuf::from(v))
    };
    let mut paths = Vec::new();
    if let Some(base) = get("CODEX_HOME") {
        paths.push(base.join("auth.json"));
    }
    if let Some(home) = get("HOME") {
        paths.push(home.join(".codex/auth.json"));
        paths.push(
            get("XDG_CONFIG_HOME")
                .unwrap_or_else(|| home.join(".config"))
                .join("codex/auth.json"),
        );
    }
    let mut out = Vec::new();
    for path in paths {
        let real = match std::fs::canonicalize(&path) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err("cannot inspect Codex credential cache".into()),
        };
        if !real.is_file() {
            return Err("Codex credential cache must be a regular file".into());
        }
        out.push(real);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn redirected_cache_masks_the_target_and_does_not_require_read_permission() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("codex");
        std::fs::create_dir(&home).unwrap();
        let target = dir.path().join("cached-auth");
        std::fs::write(&target, "synthetic-sentinel").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o0)).unwrap();
        symlink(&target, home.join("auth.json")).unwrap();
        let env = vec![("CODEX_HOME".into(), home.display().to_string())];
        assert_eq!(files(&env).unwrap(), [target]);
        assert!(files(&[]).unwrap().is_empty());
    }
}
