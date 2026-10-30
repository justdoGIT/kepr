// cli_syncx/transport.rs — T6.10 where sync bundles live: one file per
// device, `<device id>.bundle`, each written only by its own device.

//   dir:PATH              a directory (a network drive, a synced folder)
//   git:URL               a git repository, through the `git` CLI
//   s3:BUCKET[/PREFIX]    an S3 bucket (s3.rs)
//   rsync:DEST            a local directory or HOST:/PATH over SSH

// The bundles are encrypted to the enrolled devices; a remote only ever
// holds ciphertext. Transport is CLI-side: the daemon never touches the
// network or files outside its store.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kepr_core::protocol_syncx::MAX_BUNDLE_BYTES;
use sha2::{Digest, Sha256};

use super::rsync::Rsync;

pub trait Remote {
    /// The bundle files on the remote (`<8 hex>.bundle`).
    fn list(&self) -> Result<Vec<String>, String>;
    fn get(&self, name: &str) -> Result<Vec<u8>, String>;
    fn put(&mut self, name: &str, bytes: &[u8]) -> Result<(), String>;
}

/// `<8 lowercase hex>.bundle`: a device id, nothing that walks paths.
pub fn bundle_name(n: &str) -> bool {
    n.strip_suffix(".bundle").is_some_and(|id| {
        id.len() == 8
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

const SCHEMES: &str = "dir:PATH, git:URL, s3:BUCKET[/PREFIX] or rsync:PATH or rsync:HOST:/PATH";

/// Check a remote's form without touching it.
pub fn check(url: &str) -> Result<(), String> {
    match url.split_once(':') {
        Some(("dir", p)) if !p.is_empty() => Ok(()),
        Some(("git", u)) if !u.is_empty() && !u.starts_with('-') => Ok(()),
        Some(("s3", b)) => super::s3::S3::parse(b).map(drop),
        Some(("rsync", target)) => super::rsync::check_target(target),
        _ => Err(format!("unsupported remote {url:?}: use {SCHEMES}")),
    }
}

pub fn open(url: &str) -> Result<Box<dyn Remote>, String> {
    check(url)?;
    match url.split_once(':') {
        Some(("dir", p)) => Dir::open(Path::new(p)).map(|d| Box::new(d) as Box<dyn Remote>),
        Some(("git", u)) => Git::open(u, &cache_root()).map(|g| Box::new(g) as Box<dyn Remote>),
        Some(("s3", b)) => super::s3::S3::from_env(b).map(|s| Box::new(s) as Box<dyn Remote>),
        Some(("rsync", target)) => Rsync::open(target).map(|r| Box::new(r) as Box<dyn Remote>),
        _ => Err(format!("unsupported remote {url:?}: use {SCHEMES}")),
    }
}

/// A bundle file read whole, refusing anything over the bundle cap.
fn read_capped(path: &Path) -> Result<Vec<u8>, String> {
    let shown = path.display();
    let len = std::fs::metadata(path)
        .map_err(|e| format!("{shown}: {e}"))?
        .len();
    if len > MAX_BUNDLE_BYTES as u64 {
        return Err(format!("{shown}: over 16 MiB"));
    }
    std::fs::read(path).map_err(|e| format!("{shown}: {e}"))
}

fn list_dir(dir: &Path) -> Result<Vec<String>, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut out: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| bundle_name(n))
        .collect();
    out.sort();
    Ok(out)
}

pub struct Dir(PathBuf);

impl Dir {
    pub fn open(path: &Path) -> Result<Self, String> {
        if !path.is_dir() {
            return Err(format!("{}: not a directory", path.display()));
        }
        Ok(Self(path.to_path_buf()))
    }
}

impl Remote for Dir {
    fn list(&self) -> Result<Vec<String>, String> {
        list_dir(&self.0)
    }

    fn get(&self, name: &str) -> Result<Vec<u8>, String> {
        read_capped(&self.0.join(name))
    }

    fn put(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        super::atomic_file::write(&self.0.join(name), bytes, 0o600)
    }
}

pub struct Git {
    dir: PathBuf,
}

/// `git -C DIR ARGS…`, never running a transport that executes commands.
fn git(dir: Option<&Path>, args: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new("git");
    cmd.args(["-c", "protocol.ext.allow=never"]);
    if let Some(d) = dir {
        cmd.arg("-C").arg(d);
    }
    let st = cmd
        .args(args)
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("git: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("git {} failed", args.first().unwrap_or(&"")))
    }
}

fn cache_root() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache")
        })
        .join("kepr/sync")
}

impl Git {
    /// The clone of `url` under `cache` (cloned or pulled now).
    pub fn open(url: &str, cache: &Path) -> Result<Self, String> {
        let id = hex::encode(&Sha256::digest(url.as_bytes())[..8]);
        let dir = cache.join(id);
        if !dir.join(".git").is_dir() {
            std::fs::create_dir_all(cache).map_err(|e| format!("git cache: {e}"))?;
            let d = dir.to_string_lossy().into_owned();
            git(None, &["clone", "--quiet", "--", url, &d])?;
        } else if git(Some(&dir), &["rev-parse", "--quiet", "--verify", "@{u}"]).is_ok() {
            git(Some(&dir), &["pull", "--quiet", "--rebase"])?;
        }
        Ok(Self { dir })
    }
}

impl Remote for Git {
    fn list(&self) -> Result<Vec<String>, String> {
        list_dir(&self.dir)
    }

    fn get(&self, name: &str) -> Result<Vec<u8>, String> {
        read_capped(&self.dir.join(name))
    }

    fn put(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        super::atomic_file::write(&self.dir.join(name), bytes, 0o600)?;
        let d = Some(self.dir.as_path());
        git(d, &["add", "--", name])?;
        if git(d, &["diff", "--cached", "--quiet"]).is_ok() {
            return Ok(()); // nothing changed since the last push
        }
        let msg = format!("kepr sync: {name}");
        git(
            d,
            &[
                "-c",
                "user.name=kepr",
                "-c",
                "user.email=kepr@localhost",
                "commit",
                "--quiet",
                "-m",
                &msg,
            ],
        )?;
        // Another device may have pushed meanwhile: rebase once and retry.
        if git(d, &["push", "--quiet", "-u", "origin", "HEAD"]).is_err() {
            git(d, &["pull", "--quiet", "--rebase", "origin", "HEAD"])?;
            git(d, &["push", "--quiet", "-u", "origin", "HEAD"])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_device_bundle_names_count() {
        assert!(bundle_name("0a1b2c3d.bundle"));
        for bad in [
            "0A1B2C3D.bundle",
            "0a1b2c3.bundle",
            "../x.bundle",
            "0a1b2c3d.json",
            ".bundle",
        ] {
            assert!(!bundle_name(bad), "{bad}");
        }
        assert!(check("dir:/x").is_ok() && check("git:https://h/r.git").is_ok());
        assert!(check("rsync:/tmp/kepr").is_ok());
        assert!(check("rsync:user@host:/srv/kepr").is_ok());
        for bad in [
            "dir:",
            "git:",
            "git:--upload-pack=x",
            "rsync:",
            "rsync:-e",
            "rsync://host/module",
            "rsync:host::module",
            "ftp:x",
            "nothing",
        ] {
            assert!(check(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_directory_remote_round_trips() {
        let d = tempfile::tempdir().unwrap();
        let mut r = Dir::open(d.path()).unwrap();
        r.put("0a1b2c3d.bundle", b"one").unwrap();
        std::fs::write(d.path().join("notes.txt"), "x").unwrap();
        assert_eq!(r.list().unwrap(), ["0a1b2c3d.bundle"]);
        assert_eq!(r.get("0a1b2c3d.bundle").unwrap(), b"one");
        assert!(Dir::open(&d.path().join("missing")).is_err());
    }

    #[test]
    fn a_git_remote_carries_bundles_between_clones() {
        let t = tempfile::tempdir().unwrap();
        let bare = t.path().join("remote.git");
        let b = bare.to_string_lossy().into_owned();
        git(None, &["init", "--quiet", "--bare", &b]).unwrap();
        let url = format!("file://{b}");
        // Two devices = two cache roots.
        let device = |n: &str| Git::open(&url, &t.path().join(n)).unwrap();
        let mut a = device("a");
        a.put("aaaaaaaa.bundle", b"from a").unwrap();
        let mut b2 = device("b");
        assert_eq!(b2.get("aaaaaaaa.bundle").unwrap(), b"from a");
        b2.put("bbbbbbbb.bundle", b"from b").unwrap();
        let a = device("a"); // pulls
        assert_eq!(a.list().unwrap(), ["aaaaaaaa.bundle", "bbbbbbbb.bundle"]);
    }
}
