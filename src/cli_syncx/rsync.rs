// cli_syncx/rsync.rs — rsync transport for T6.10 device bundles.
//
// `rsync:HOST:/PATH` uses rsync's single-colon remote-shell transport
// (normally SSH); an absolute/local directory works for local setups too.
// Daemon URLs (`rsync://` and `HOST::MODULE`) are intentionally refused:
// they use a different, potentially unencrypted protocol.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use kepr_core::protocol_syncx::MAX_BUNDLE_BYTES;

use super::transport::{bundle_name, Remote};

pub(super) fn check_target(target: &str) -> Result<(), String> {
    if target.is_empty() || target.starts_with('-') || target.contains('\0') {
        return Err("rsync target must be a local path or SSH-style HOST:/PATH".into());
    }
    if target.starts_with("//") || target.contains("::") {
        return Err(
            "rsync daemon URLs are unsupported; use a local path or HOST:/PATH over SSH".into(),
        );
    }
    Ok(())
}

pub(super) struct Rsync {
    target: String,
}

impl Rsync {
    pub(super) fn open(target: &str) -> Result<Self, String> {
        check_target(target)?;
        Ok(Self {
            target: target.to_string(),
        })
    }

    fn directory_arg(&self) -> String {
        let trimmed = self.target.trim_end_matches('/');
        if trimmed.is_empty() {
            "/".to_string()
        } else {
            format!("{trimmed}/")
        }
    }

    fn item_arg(&self, name: &str) -> String {
        let trimmed = self.target.trim_end_matches('/');
        if trimmed.is_empty() {
            format!("/{name}")
        } else {
            format!("{trimmed}/{name}")
        }
    }
}

fn run(mut command: Command) -> Result<Output, String> {
    let output = command
        .output()
        .map_err(|e| format!("rsync: {e}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        if detail.is_empty() {
            Err(format!("rsync exited with {}", output.status))
        } else {
            Err(format!("rsync failed: {detail}"))
        }
    }
}

struct StageDir(PathBuf);

impl StageDir {
    fn new() -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir();
        for _ in 0..128 {
            let path = root.join(format!(
                "kepr-rsync-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("create rsync staging directory: {e}")),
            }
        }
        Err("could not allocate a unique rsync staging directory".into())
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for StageDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn read_capped(path: &Path) -> Result<Vec<u8>, String> {
    let len = fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
    if len > MAX_BUNDLE_BYTES as u64 {
        return Err(format!("{}: over 16 MiB", path.display()));
    }
    fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

impl Remote for Rsync {
    fn list(&self) -> Result<Vec<String>, String> {
        let mut command = Command::new("rsync");
        command.args(["--list-only", "--"]).arg(self.directory_arg());
        let output = run(command)?;
        // `--list-only` uses an ls-like display, not `--out-format`.
        // Bundle names have a fixed ASCII shape with no whitespace, so
        // taking the final field and validating it avoids parsing sizes,
        // timestamps, or locale-specific formatting.
        let mut names: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.split_whitespace().last())
            .filter(|name| bundle_name(name))
            .map(str::to_string)
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn get(&self, name: &str) -> Result<Vec<u8>, String> {
        if !bundle_name(name) {
            return Err(format!("invalid device bundle name {name:?}"));
        }
        let stage = StageDir::new()?;
        let path = stage.file(name);
        let mut command = Command::new("rsync");
        command
            .args(["--quiet", "--max-size=16777216", "--"])
            .arg(self.item_arg(name))
            .arg(&path);
        run(command)?;
        read_capped(&path)
    }

    fn put(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        if !bundle_name(name) {
            return Err(format!("invalid device bundle name {name:?}"));
        }
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err("device bundle is over 16 MiB".into());
        }
        let stage = StageDir::new()?;
        let path = stage.file(name);
        write_private(&path, bytes)?;
        let mut command = Command::new("rsync");
        command
            .args(["--quiet", "--"])
            .arg(&path)
            .arg(self.item_arg(name));
        run(command)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_rsync_remote_round_trips_only_bundle_files() {
        if Command::new("rsync").arg("--version").output().is_err() {
            eprintln!("rsync not installed; skipping local rsync transport test");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut remote = Rsync::open(dir.path().to_str().unwrap()).unwrap();
        remote.put("0a1b2c3d.bundle", b"encrypted bundle").unwrap();
        fs::write(dir.path().join("notes.txt"), b"not a device bundle").unwrap();
        assert_eq!(remote.list().unwrap(), ["0a1b2c3d.bundle"]);
        assert_eq!(remote.get("0a1b2c3d.bundle").unwrap(), b"encrypted bundle");
        assert!(remote.get("../notes.txt").is_err());
    }
}
