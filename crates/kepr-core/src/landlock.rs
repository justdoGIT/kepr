//! Landlock's syscall layer, shared by the agent sandbox (T1.23,
//! `src/cli_sandbox_landlock.rs`, which keeps its own policy) and
//! kepr-gate sessions (T12.04, `restrict_read_only`).
//!
//! Landlock is allow-only and its rules follow inodes: a ruleset names
//! the rights it handles, rules grant some of them beneath a path, and
//! after `restrict_self` the calling thread (and the threads and
//! programs it starts later) has only what a rule grants. Raw syscalls,
//! ABI 1–5; network rules (ABI 4) are out of scope.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const CREATE_RULESET_VERSION: libc::c_uint = 1;
const RULE_PATH_BENEATH: libc::c_int = 1;

pub const EXECUTE: u64 = 1 << 0;
pub const WRITE_FILE: u64 = 1 << 1;
pub const READ_FILE: u64 = 1 << 2;
pub const READ_DIR: u64 = 1 << 3;
// 1 << 4 ..= 1 << 12: remove dir / file, make char / dir / reg / sock /
// fifo / block / sym (directory rights).
pub const TRUNCATE: u64 = 1 << 14;
pub const IOCTL_DEV: u64 = 1 << 15;
/// The only rights a rule on a non-directory may carry.
const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;

/// `struct landlock_ruleset_attr`, filesystem part only (the kernel takes
/// any size from this field on; network rules are out of scope).
#[repr(C)]
pub struct RulesetAttr {
    pub handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr` (packed in the kernel's UAPI).
#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// Every filesystem right of a Landlock ABI: 13 in ABI 1, REFER from 2,
/// TRUNCATE from 3, IOCTL_DEV from 5 (4 only added network rights).
pub fn ruleset_attr_for_abi(abi: i32) -> RulesetAttr {
    let handled_access_fs = match abi {
        i32::MIN..=0 => 0,
        1 => 0x1FFF,
        2 => 0x3FFF,
        3 | 4 => 0x7FFF,
        _ => 0xFFFF,
    };
    RulesetAttr { handled_access_fs }
}

/// The running kernel's Landlock ABI; 0 when it has none (not built,
/// disabled at boot, or the call is filtered).
pub fn abi() -> i32 {
    // SAFETY: the version query takes no attribute (NULL, 0).
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    i32::try_from(r).unwrap_or(0).max(0)
}

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// A ruleset being built.
pub struct Ruleset {
    fd: OwnedFd,
    rules: usize,
}

impl Ruleset {
    /// A ruleset handling `handled` (cut to what the running ABI knows);
    /// `None` when the kernel has no Landlock.
    pub fn create(handled: u64) -> Result<Option<Self>, String> {
        let handled = handled & ruleset_attr_for_abi(abi()).handled_access_fs;
        if handled == 0 {
            return Ok(None);
        }
        let attr = RulesetAttr {
            handled_access_fs: handled,
        };
        // SAFETY: `attr` is valid for the size passed.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        };
        if fd < 0 {
            return Err(os_err("landlock_create_ruleset"));
        }
        // SAFETY: a new ruleset fd, owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
        Ok(Some(Ruleset { fd, rules: 0 }))
    }

    /// Grant `access` beneath `path` (a non-directory keeps only its file
    /// rights). A path that is missing or is a symlink is skipped: one
    /// rule fewer only ever means less access.
    pub fn allow(&mut self, path: &Path, access: u64) -> Result<(), String> {
        let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
            return Ok(());
        };
        let flags = libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        // SAFETY: `c` is a valid NUL-terminated path.
        let fd = unsafe { libc::open(c.as_ptr(), flags) };
        if fd < 0 {
            return Ok(());
        }
        // SAFETY: `fd` was just opened and is owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: an all-zero `stat` is a valid value of this plain C struct.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat writes into the stack-local `st` it is given.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Ok(());
        }
        let allowed_access = match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => access,
            libc::S_IFLNK => 0,
            _ => access & FILE_RIGHTS,
        };
        if allowed_access == 0 {
            return Ok(());
        }
        let attr = PathBeneath {
            allowed_access,
            parent_fd: fd.as_raw_fd(),
        };
        // SAFETY: `attr` is a valid path-beneath attribute for the call.
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.fd.as_raw_fd(),
                RULE_PATH_BENEATH,
                &attr as *const PathBeneath,
                0u32,
            )
        };
        if r == 0 {
            self.rules += 1;
            return Ok(());
        }
        // EBADFD: a kernel-internal filesystem, which takes no rules.
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EBADFD) => Ok(()),
            _ => Err(format!("landlock rule for {}: {e}", path.display())),
        }
    }

    /// How many rules were added.
    pub fn rules(&self) -> usize {
        self.rules
    }

    /// Restrict the calling thread (and what it starts) to the rules.
    /// Sets no_new_privs.
    pub fn restrict_self(self) -> Result<(), String> {
        // SAFETY: constant prctl / landlock_restrict_self arguments.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(os_err("no_new_privs"));
            }
            if libc::syscall(libc::SYS_landlock_restrict_self, self.fd.as_raw_fd(), 0u32) != 0 {
                return Err(os_err("landlock_restrict_self"));
            }
        }
        Ok(())
    }
}

/// Handle every filesystem right of the running ABI and grant only
/// READ_FILE | READ_DIR beneath each of `paths` that exists: nothing
/// else can be opened and nothing can be written, created or run.
/// `Ok(false)` when the kernel has no Landlock.
pub fn restrict_read_only(paths: &[PathBuf]) -> Result<bool, String> {
    let Some(mut ruleset) = Ruleset::create(ruleset_attr_for_abi(abi()).handled_access_fs)? else {
        return Ok(false);
    };
    for p in paths {
        ruleset.allow(p, READ_FILE | READ_DIR)?;
    }
    ruleset.restrict_self()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_ruleset_denies_other_paths() {
        if ruleset_attr_for_abi(abi()).handled_access_fs == 0 {
            eprintln!("skip: this kernel has no Landlock");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("kepr-landlock-{}", std::process::id()));
        std::fs::write(&tmp, "x").unwrap();
        let tmp_c = CString::new(tmp.as_os_str().as_bytes()).unwrap();
        let usr = [PathBuf::from("/usr")];
        // SAFETY: the child restricts itself, opens two files and exits;
        // glibc keeps malloc usable in a forked child.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let code = match restrict_read_only(&usr) {
                Ok(true) => {
                    let env = std::fs::read("/usr/bin/env").is_ok();
                    // SAFETY: a valid NUL-terminated path.
                    let fd = unsafe { libc::open(tmp_c.as_ptr(), libc::O_RDONLY) };
                    let e = std::io::Error::last_os_error().raw_os_error();
                    let denied = fd < 0 && e == Some(libc::EACCES);
                    let written = std::fs::write("/usr/kepr-landlock-test", "x").is_ok();
                    i32::from(!(env && denied && !written))
                }
                Ok(false) => 3,
                Err(_) => 2,
            };
            // SAFETY: leaving the forked child without running the
            // parent's destructors.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting for the child forked above.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let _ = std::fs::remove_file(&tmp);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn a_ruleset_skips_missing_paths_and_symlinks() {
        let Some(mut r) = Ruleset::create(READ_FILE | READ_DIR).unwrap() else {
            eprintln!("skip: this kernel has no Landlock");
            return;
        };
        r.allow(Path::new("/nonexistent/kepr"), READ_FILE).unwrap();
        assert_eq!(r.rules(), 0);
        let link = std::env::temp_dir().join(format!("kepr-landlock-ln-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("/usr", &link).unwrap();
        r.allow(&link, READ_FILE | READ_DIR).unwrap();
        let _ = std::fs::remove_file(&link);
        assert_eq!(r.rules(), 0, "a symlink gets no rule");
        r.allow(Path::new("/usr"), READ_FILE | READ_DIR).unwrap();
        assert_eq!(r.rules(), 1);
    }
}
