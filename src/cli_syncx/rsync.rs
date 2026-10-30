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
        // The remote controls stderr: strip control bytes (ANSI/OSC
        // escapes) and bound it before it reaches a terminal or journal.
        let detail: String = String::from_utf8_lossy(&output.stderr)
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        let detail = detail.trim();
        if detail.is_empty() {
            Err(format!("rsync exited with {}", output.status))
        } else {
            Err(format!("rsync failed: {detail}"))
        }
    }
}

/// Stop the child writing more than one bundle to disk, whatever the peer
/// streams: `--max-size` is the sender's rule, and a hostile peer ignores it.
fn cap_file_size(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    let cap = MAX_BUNDLE_BYTES as libc::rlim_t;
    // SAFETY: the closure only calls setrlimit, which is async-signal-safe,
    // and captures a plain integer, so it is sound between fork and exec.
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: cap,
                rlim_max: cap,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
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
            // Only a regular file (`-rw-…`) can be a bundle: a directory,
            // symlink or fifo planted in the remote would be listed, then
            // skipped by `get`, silently dropping that device's merge.
            .filter(|line| line.starts_with('-'))
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
        // `--max-size` is enforced by the peer, which can ignore it.
        cap_file_size(&mut command);
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

    #[test]
    fn only_regular_files_are_listed_as_bundles() {
        if Command::new("rsync").arg("--version").output().is_err() {
            eprintln!("rsync not installed; skipping local rsync transport test");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("0a1b2c3d.bundle")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("1a2b3c4d.bundle")).unwrap();
        let mut remote = Rsync::open(dir.path().to_str().unwrap()).unwrap();
        remote.put("2a3b4c5d.bundle", b"encrypted bundle").unwrap();
        assert_eq!(remote.list().unwrap(), ["2a3b4c5d.bundle"]);
    }

    #[test]
    fn rsync_stderr_cannot_carry_terminal_escapes() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            r"printf '\033]52;c;AAAA\007\033[2Jfake ok' >&2; exit 1",
        ]);
        let err = run(command).unwrap_err();
        assert!(!err.chars().any(|c| c.is_control()), "{err:?}");
        assert!(err.contains("fake ok"));
    }

    #[test]
    fn a_peer_cannot_stream_past_the_bundle_cap() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("big");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(format!("head -c {} /dev/zero > '{}'", MAX_BUNDLE_BYTES + 4096, out.display()));
        cap_file_size(&mut command);
        assert!(run(command).is_err());
        assert!(fs::metadata(&out).unwrap().len() <= MAX_BUNDLE_BYTES as u64);
    }
}
