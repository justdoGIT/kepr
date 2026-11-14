//! Pin only trusted system runtime paths before entering the user namespace.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(crate) struct RuntimeMount {
    pub source: File,
    pub target: &'static str,
    pub directory: bool,
}

const ROOTS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64"];
const OPTIONAL: &[&str] = &["/etc/ld.so.cache", "/etc/ssl/certs", "/etc/localtime"];
pub(crate) const SEARCH_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin";

fn approved(path: &Path) -> bool {
    ROOTS.iter().any(|p| path.starts_with(p)) || OPTIONAL.iter().any(|p| path == Path::new(p))
}

fn trusted(path: &Path) -> Result<(), &'static str> {
    if !approved(path) {
        return Err("private workspace runtime must stay under trusted system paths");
    }
    for ancestor in path.ancestors() {
        let m = std::fs::symlink_metadata(ancestor)
            .map_err(|_| "private workspace runtime unavailable")?;
        if m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(
                "private workspace runtime must be root-owned and not writable by other users",
            );
        }
    }
    Ok(())
}

pub(crate) fn mounts() -> Result<Vec<RuntimeMount>, &'static str> {
    let mut mounts = Vec::new();
    for &target in ROOTS.iter().chain(OPTIONAL) {
        let canonical = match std::fs::canonicalize(target) {
            Ok(path) => path,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && target != "/usr" => continue,
            Err(_) => return Err("private workspace runtime unavailable"),
        };
        trusted(&canonical)?;
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&canonical)
            .map_err(|_| "private workspace runtime cannot be pinned")?;
        let m = source
            .metadata()
            .map_err(|_| "private workspace runtime unavailable")?;
        if !m.is_dir() && !m.is_file() {
            return Err("private workspace runtime has an unsupported file type");
        }
        mounts.push(RuntimeMount {
            source,
            target,
            directory: m.is_dir(),
        });
    }
    Ok(mounts)
}

pub(crate) fn program(argv: &[String]) -> Result<Vec<String>, &'static str> {
    let command = argv
        .first()
        .ok_or("private workspace requires a harness command")?;
    let paths: Vec<PathBuf> = if command.contains('/') {
        vec![PathBuf::from(command)]
    } else {
        SEARCH_PATH
            .split(':')
            .map(|p| Path::new(p).join(command))
            .collect()
    };
    for path in paths {
        let Ok(path) = std::fs::canonicalize(path) else {
            continue;
        };
        if trusted(&path).is_err() {
            continue;
        }
        let m = std::fs::metadata(&path).map_err(|_| "private workspace harness unavailable")?;
        if !m.is_file() || m.mode() & 0o111 == 0 || m.mode() & 0o7000 != 0 {
            continue;
        }
        let mut out = argv.to_vec();
        out[0] = path
            .to_str()
            .ok_or("private workspace harness path must be UTF-8")?
            .into();
        return Ok(out);
    }
    Err("private workspace requires a system-installed harness runtime; user-home runtimes are unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_relative_and_user_writable_harnesses_are_refused() {
        assert!(program(&["./omp".into()]).is_err());
        assert!(program(&["/home/agent/bin/omp".into()]).is_err());
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("omp");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        assert!(program(&[path.to_string_lossy().into_owned()]).is_err());
    }

    #[test]
    fn system_program_resolution_preserves_arguments_or_refuses_unmapped_ownership() {
        if std::fs::metadata("/usr").unwrap().uid() != 0 {
            assert!(program(&["sh".into()]).is_err());
            return;
        }
        let argv = program(&["sh".into(), "-c".into(), "exit 0".into()]).unwrap();
        assert!(Path::new(&argv[0]).is_absolute());
        assert_eq!(&argv[1..], &["-c", "exit 0"]);
    }
}
