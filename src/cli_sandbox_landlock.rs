// cli_sandbox_landlock.rs — Landlock rules for the agent sandbox (T1.23),
// defence in depth under the hiding mounts: if one of those empty tmpfs
// mounts were ever undone, the harness still could not open the
// credential store, the daemon state or the socket directory.
//
// Landlock is allow-only and its rules follow inodes. Read+exec on `/`,
// read+write on $HOME, /tmp, /dev, /proc, $XDG_RUNTIME_DIR and $PWD; an
// allowed directory with a hidden path somewhere below it is opened one
// level at a time instead: every child gets the rule except the one on
// the way to the hidden path, which is split the same way. The
// directories on the way (`/`, $HOME, ~/.local, ~/.local/share, …) get
// no rule of their own, so inside the sandbox they can't be listed and
// nothing new can be created directly in them; their existing files and
// directories keep working (a file replaced by a rename loses its rule).
//
// That cost is fine for `/` but not for $HOME, where harnesses create
// files and replace them by rename (Claude Code's ~/.claude.json). So by
// default hidden paths under $HOME (the user-mode store and state) are
// left to their hiding mounts and $HOME gets one rule;
// KEPR_LANDLOCK=strict fences them too, at that cost. KEPR_LANDLOCK=0
// turns the rules off.
//
// Limits: Landlock doesn't mediate connect() on a Unix socket path, so
// the daemon socket stays covered by its hiding mount alone; network
// rules are out of scope (the net namespace handles those). Kernels
// without Landlock get a warning, and the mounts still apply.

//
// The syscall layer (ABI probe, rights, rulesets) is kepr_core::landlock,
// shared with kepr-gate sessions (T12.04); the policy stays here.

use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[cfg(test)]
use kepr_core::landlock::TRUNCATE;
use kepr_core::landlock::{abi, ruleset_attr_for_abi, Ruleset, EXECUTE, READ_DIR, READ_FILE};

#[derive(Debug, PartialEq, Eq)]
pub enum LandlockStatus {
    Enforced { abi: i32, rules: usize },
    Unsupported,
}

/// The entries of `dir`, without the ones in `deny`, sorted.
pub fn children_except(dir: &Path, deny: &[PathBuf]) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| !deny.contains(p))
        .collect();
    v.sort();
    v
}

/// The rules granting `access` on `root` without reaching any path in
/// `deny` (all canonical). Symlinks get no rule: what they point to is
/// allowed or not where it really lives, as under one rule on `root`.
pub fn grants(root: &Path, access: u64, deny: &[PathBuf], out: &mut Vec<(PathBuf, u64)>) {
    if deny.iter().any(|d| root.starts_with(d)) {
        return;
    }
    if !deny.iter().any(|d| d.starts_with(root)) {
        out.push((root.to_path_buf(), access));
        return;
    }
    for child in children_except(root, deny) {
        let link = std::fs::symlink_metadata(&child).map_or(true, |m| m.file_type().is_symlink());
        if !link {
            grants(&child, access, deny, out);
        }
    }
}

fn roots(ro: u64, rw: u64) -> Vec<(PathBuf, u64)> {
    let mut v = vec![(PathBuf::from("/"), ro)];
    v.extend(["/tmp", "/dev", "/proc"].map(|p| (PathBuf::from(p), rw)));
    for var in ["HOME", "XDG_RUNTIME_DIR"] {
        if let Some(p) = std::env::var_os(var) {
            v.push((PathBuf::from(p), rw));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        v.push((cwd, rw));
    }
    v
}

/// Restrict the calling thread (and what it execs) to the rule set
/// above, with every path in `deny` left out. Sets no_new_privs.
pub fn restrict(deny: &[PathBuf]) -> Result<LandlockStatus, String> {
    let abi = abi();
    let handled = ruleset_attr_for_abi(abi).handled_access_fs;
    let Some(mut ruleset) = Ruleset::create(handled)? else {
        return Ok(LandlockStatus::Unsupported);
    };
    let deny: Vec<PathBuf> = deny
        .iter()
        .map(|d| d.canonicalize().unwrap_or_else(|_| d.clone()))
        .collect();
    let mut rules = Vec::new();
    for (root, access) in roots(handled & (EXECUTE | READ_FILE | READ_DIR), handled) {
        if let Ok(root) = root.canonicalize() {
            grants(&root, access, &deny, &mut rules);
        }
    }
    // A path that vanished or turned into a symlink is skipped (one rule
    // fewer only ever means less access).
    for (path, access) in &rules {
        ruleset.allow(path, *access)?;
    }
    let rules = ruleset.rules();
    ruleset.restrict_self()?;
    Ok(LandlockStatus::Enforced { abi, rules })
}

/// The hidden paths Landlock fences as well (all canonical): without
/// `strict`, those under `home` stay with their mounts (header).
pub fn fenced(hidden: &[PathBuf], home: Option<&Path>, strict: bool) -> Vec<PathBuf> {
    let home = home.filter(|h| h.parent().is_some()); // never `/`
    hidden
        .iter()
        .filter(|d| strict || !home.is_some_and(|h| d.starts_with(h)))
        .cloned()
        .collect()
}

/// The sandbox's call (in the harness child, before exec): `hidden` are
/// the hiding mounts' paths. On unless KEPR_LANDLOCK=0 (`strict`: also
/// under $HOME); a kernel without Landlock only gets a warning.
pub fn enforce(hidden: &[CString]) -> Result<(), String> {
    let mode = std::env::var("KEPR_LANDLOCK").unwrap_or_default();
    if mode == "0" {
        return Ok(());
    }
    let canon = |p: PathBuf| p.canonicalize().unwrap_or(p);
    let hidden: Vec<PathBuf> = hidden
        .iter()
        .map(|c| canon(PathBuf::from(OsStr::from_bytes(c.as_bytes()))))
        .collect();
    let home = std::env::var_os("HOME").map(|h| canon(PathBuf::from(h)));
    let deny = fenced(&hidden, home.as_deref(), mode == "strict");
    if restrict(&deny)? == LandlockStatus::Unsupported {
        eprintln!("kepr: sandbox: this kernel has no Landlock; the vault is hidden by mounts only");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_attr_has_the_documented_masks() {
        let m = |abi| ruleset_attr_for_abi(abi).handled_access_fs;
        assert_eq!((m(-1), m(0)), (0, 0));
        assert_eq!(m(1), 0x1FFF, "ABI 1: execute .. make_sym");
        assert_eq!(m(2), 0x1FFF | 1 << 13, "ABI 2 adds refer");
        assert_eq!(m(3), 0x3FFF | TRUNCATE, "ABI 3 adds truncate");
        assert_eq!(m(4), m(3), "ABI 4 only adds network rights");
        assert_eq!((m(5), m(7)), (0xFFFF, 0xFFFF), "ABI 5 adds ioctl_dev");
    }

    #[test]
    fn children_except_leaves_out_the_denied_entry() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for name in ["a", "kepr", "z"] {
            std::fs::create_dir(d.join(name)).unwrap();
        }
        std::fs::write(d.join("f"), "x").unwrap();
        assert_eq!(
            children_except(d, &[d.join("kepr")]),
            [d.join("a"), d.join("f"), d.join("z")]
        );
        assert!(children_except(&d.join("missing"), &[]).is_empty());
    }

    #[test]
    fn grants_split_around_denied_paths_and_skip_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().canonicalize().unwrap();
        for p in ["share/kepr/x", "share/app", "state/kepr", "work"] {
            std::fs::create_dir_all(d.join(p)).unwrap();
        }
        std::fs::write(d.join(".rc"), "x").unwrap();
        std::os::unix::fs::symlink(d.join("share"), d.join("link")).unwrap();
        let deny = [d.join("share/kepr"), d.join("state/kepr")];
        let mut out = Vec::new();
        grants(&d, 7, &deny, &mut out);
        let paths: Vec<_> = out.iter().map(|(p, a)| (p.clone(), *a)).collect();
        assert_eq!(
            paths,
            [
                (d.join(".rc"), 7),
                (d.join("share/app"), 7),
                (d.join("work"), 7)
            ]
        );
        out.clear();
        grants(&d.join("share/kepr/x"), 7, &deny, &mut out);
        assert!(out.is_empty(), "nothing inside a denied path");
        grants(&d.join("work"), 7, &deny, &mut out);
        assert_eq!(out, [(d.join("work"), 7)], "no split without a denied path");
    }

    #[test]
    fn hidden_paths_under_home_are_fenced_only_when_strict() {
        let home = Path::new("/home/u");
        let hidden = [
            PathBuf::from("/home/u/.local/share/kepr"),
            PathBuf::from("/run/kepr"),
        ];
        assert_eq!(
            fenced(&hidden, Some(home), false),
            [PathBuf::from("/run/kepr")]
        );
        assert_eq!(fenced(&hidden, Some(home), true), hidden);
        assert_eq!(fenced(&hidden, None, false), hidden);
        assert_eq!(
            fenced(&hidden, Some(Path::new("/")), false),
            hidden,
            "HOME=/"
        );
    }

    #[test]
    fn restrict_makes_a_denied_file_unreadable() {
        if ruleset_attr_for_abi(abi()).handled_access_fs == 0 {
            eprintln!("skip: this kernel has no Landlock");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (vault, open) = (dir.path().join("vault"), dir.path().join("open.txt"));
        std::fs::create_dir(&vault).unwrap();
        std::fs::write(vault.join("secret"), "s").unwrap();
        std::fs::write(&open, "o").unwrap();
        // Landlock binds the calling thread (and what it starts), so a
        // thread of its own stands in for the forked harness.
        let (status, secret, listed, other) = std::thread::spawn(move || {
            let status = restrict(std::slice::from_ref(&vault)).unwrap();
            let errno = |r: std::io::Result<()>| r.map_err(|e| e.raw_os_error());
            (
                status,
                errno(std::fs::read(vault.join("secret")).map(drop)),
                errno(std::fs::read_dir(&vault).map(drop)),
                std::fs::read_to_string(&open).ok(),
            )
        })
        .join()
        .unwrap();
        assert!(matches!(status, LandlockStatus::Enforced { rules, .. } if rules > 0));
        assert_eq!(secret, Err(Some(libc::EACCES)));
        assert_eq!(listed, Err(Some(libc::EACCES)));
        assert_eq!(other.as_deref(), Some("o"), "a sibling stays readable");
        assert!(
            std::fs::read(dir.path().join("vault/secret")).is_ok(),
            "other threads unaffected"
        );
    }
}
