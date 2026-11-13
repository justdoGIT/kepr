//! Owner-only, bounded policy persistence. Diagnostics never include originals.

use kepr_core::privacy::{Policy, Preset};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(super) const MAX_POLICY_BYTES: usize = 64 * 1024;
const FILE_ERROR: &str = "privacy policy file must be an owner-only regular file without links";

fn path() -> Result<PathBuf, &'static str> {
    let root = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(root) if !root.is_empty() => PathBuf::from(root),
        _ => {
            PathBuf::from(std::env::var_os("HOME").ok_or("privacy configuration home unavailable")?)
                .join(".config")
        }
    };
    if !root.is_absolute() {
        return Err("privacy configuration root must be absolute");
    }
    let profile =
        kepr_core::profile::current().map_err(|_| "invalid privacy configuration profile")?;
    Ok(kepr_core::profile::nest_for(root.join("kepr"), &Ok(profile)).join("privacy.json"))
}

fn private_parent(parent: &Path) -> Result<(), &'static str> {
    // SAFETY: geteuid has no arguments and no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    for ancestor in parent.ancestors() {
        let m =
            fs::symlink_metadata(ancestor).map_err(|_| "privacy policy directory unavailable")?;
        // System ancestors may have unmapped ownership in a user namespace.
        // The kernel still enforces sticky-directory ownership on their entries.
        let sticky = m.mode() & 0o1000 != 0;
        if !m.is_dir()
            || (ancestor == parent && (m.uid() != uid || m.mode() & 0o022 != 0))
            || (m.mode() & 0o022 != 0 && !sticky)
        {
            return Err("privacy policy directory must be trusted and without symbolic links");
        }
    }
    Ok(())
}

fn private_file(m: &fs::Metadata) -> Result<(), &'static str> {
    // SAFETY: geteuid has no arguments and no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    if !m.is_file() || m.uid() != uid || m.mode() & 0o077 != 0 || m.nlink() != 1 {
        return Err(FILE_ERROR);
    }
    Ok(())
}

pub(super) fn read_bytes(
    reader: impl Read,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "privacy input could not be read")?;
    if bytes.len() > limit {
        return Err("privacy input too large");
    }
    Ok(bytes)
}

pub(super) fn parse(bytes: &[u8]) -> Result<Policy, &'static str> {
    let policy: Policy =
        serde_json::from_slice(bytes).map_err(|_| "invalid privacy policy JSON")?;
    policy.validate()?;
    Ok(policy)
}

fn load_path(path: &Path) -> Result<Option<Policy>, &'static str> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(FILE_ERROR),
        Ok(_) => {}
    }
    private_parent(path.parent().ok_or(FILE_ERROR)?)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| FILE_ERROR)?;
    private_file(&file.metadata().map_err(|_| FILE_ERROR)?)?;
    parse(&read_bytes(file, MAX_POLICY_BYTES)?).map(Some)
}

pub(super) fn load() -> Result<Option<Policy>, &'static str> {
    load_path(&path()?)
}

fn write_path(path: &Path, policy: &Policy, replace: bool) -> Result<(), &'static str> {
    policy.validate()?;
    let parent = path.parent().ok_or(FILE_ERROR)?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|_| "privacy policy directory could not be created")?;
    private_parent(parent)?;
    match fs::symlink_metadata(path) {
        Ok(m) if replace => private_file(&m)?,
        Ok(_) => {
            return Err("privacy policy already exists; use privacy configure --stdin to update it")
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(FILE_ERROR),
    }
    let encoded = Zeroizing::new(
        serde_json::to_vec_pretty(policy).map_err(|_| "privacy policy could not be encoded")?,
    );
    if encoded.len() > MAX_POLICY_BYTES {
        return Err("encoded privacy policy too large");
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "privacy policy clock unavailable")?
        .as_nanos();
    let temporary = parent.join(format!(".privacy-{}-{stamp}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| "privacy policy staging failed")?;
    let result = (|| {
        file.write_all(&encoded)
            .and_then(|_| file.sync_all())
            .map_err(|_| "privacy policy write failed")?;
        if replace {
            fs::rename(&temporary, path).map_err(|_| "privacy policy replacement failed")?;
        } else {
            // link publishes the complete file atomically without overwriting a concurrent init.
            fs::hard_link(&temporary, path).map_err(|_| "privacy policy creation failed")?;
            fs::remove_file(&temporary).map_err(|_| "privacy policy staging cleanup failed")?;
        }
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| "privacy policy durability check failed")
    })();
    let _ = fs::remove_file(&temporary);
    result
}

pub(super) fn write(policy: &Policy, replace: bool) -> Result<(), &'static str> {
    write_path(&path()?, policy, replace)
}

pub(crate) fn for_launch(
    mode: crate::cli_agent_run::SandboxMode,
) -> Result<Option<Policy>, &'static str> {
    effective_for_launch(load()?, mode)
}

fn effective_for_launch(
    configured: Option<Policy>,
    mode: crate::cli_agent_run::SandboxMode,
) -> Result<Option<Policy>, &'static str> {
    let policy = configured.unwrap_or_default();
    if policy.preset == Preset::LocalOnly {
        return Err("local-only launch unavailable: local inference routing is not implemented");
    }
    Ok((mode == crate::cli_agent_run::SandboxMode::Required).then_some(policy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_agent_run::SandboxMode;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn persisted_identifiers_reach_the_gate_policy_and_local_only_never_downgrades() {
        let policy = Policy {
            identifiers: vec!["Acme Lichen".into()],
            ..Policy::default()
        };
        assert_eq!(
            effective_for_launch(Some(policy.clone()), SandboxMode::Required).unwrap(),
            Some(policy)
        );
        for mode in [SandboxMode::Required, SandboxMode::Auto, SandboxMode::Off] {
            assert!(effective_for_launch(
                Some(Policy {
                    preset: Preset::LocalOnly,
                    ..Policy::default()
                }),
                mode
            )
            .is_err());
        }
        assert!(effective_for_launch(None, SandboxMode::Required)
            .unwrap()
            .is_some());
        assert!(effective_for_launch(None, SandboxMode::Auto)
            .unwrap()
            .is_none());
    }

    #[test]
    fn owner_only_policy_is_replaced_atomically_and_hard_links_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("kepr/privacy.json");
        write_path(&path, &Policy::default(), false).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(write_path(&path, &Policy::default(), false).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        let updated = Policy {
            identifiers: vec!["Acme Lichen".into()],
            ..Policy::default()
        };
        write_path(&path, &updated, true).unwrap();
        assert_eq!(load_path(&path).unwrap(), Some(updated));
        fs::hard_link(&path, root.path().join("linked.json")).unwrap();
        assert!(load_path(&path).is_err());
    }

    #[test]
    fn unsafe_directories_and_oversize_input_are_rejected_without_originals() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(write_path(
            &root.path().join("kepr/privacy.json"),
            &Policy::default(),
            false
        )
        .is_err());
        assert!(read_bytes(&b"12345"[..], 4).is_err());
        assert_eq!(
            parse(br#"{"version":1,"preset":"private-cloud","secret":"alice@example.invalid"}"#)
                .err(),
            Some("invalid privacy policy JSON")
        );
    }
}
