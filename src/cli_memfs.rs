// cli_memfs.rs — memory-backed file systems (tmpfs, ramfs): is a file on
// one, and `kepr __private-tmp`, which runs a command with a tmpfs /tmp of
// its own. Rendered secrets (`kepr inject -o`, T12.45) and wl-copy's buffer
// (`kepr copy`, T12.46) may only land where they vanish with the machine's
// memory, never on a disk that outlives the process.

use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use kepr_core::protocol::Response;

const TMPFS_MAGIC: u32 = 0x0102_1994;
const RAMFS_MAGIC: u32 = 0x8584_58f6;

fn memory_type(s: &libc::statfs) -> bool {
    // f_type is i64 on x86_64 but i32 / u32 on other targets; the magics
    // are 32-bit, so compare the low 32 bits.
    #[allow(clippy::unnecessary_cast)]
    let fs_type = s.f_type as u32;
    fs_type == TMPFS_MAGIC || fs_type == RAMFS_MAGIC
}

/// The open file `f` lives on tmpfs or ramfs (`fstatfs` on its fd, so the
/// answer is about this very file, not a path that could be swapped).
pub fn on_memory_fs(f: &std::fs::File) -> bool {
    // SAFETY: fstatfs writes into a zeroed, stack-local struct; the fd is
    // owned by `f` and open for the whole call.
    unsafe {
        let mut s: libc::statfs = std::mem::zeroed();
        libc::fstatfs(f.as_raw_fd(), &mut s) == 0 && memory_type(&s)
    }
}

/// `p` (a file or directory) lives on tmpfs or ramfs. False when it does
/// not exist or cannot be checked.
pub fn path_on_memory_fs(p: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: statfs writes into a zeroed, stack-local struct; `c` is a
    // NUL-terminated path that outlives the call.
    unsafe {
        let mut s: libc::statfs = std::mem::zeroed();
        libc::statfs(c.as_ptr(), &mut s) == 0 && memory_type(&s)
    }
}

/// Exit status of `kepr __private-tmp` when it could not set up the
/// private /tmp (it then runs nothing).
pub const PRIVATE_TMP_UNAVAILABLE: i32 = 3;

/// `kepr __private-tmp -- PROG ARGS...` (internal, T12.46): run PROG with
/// a private tmpfs on /tmp. Exits 3 without running PROG when that cannot
/// be set up (no user namespaces).
pub fn cmd_private_tmp(args: &[String]) -> Response {
    let usage = || Response::fail("usage: kepr __private-tmp -- PROG ARGS...");
    let Some((sep, cmd)) = args.split_first() else {
        return usage();
    };
    let Some((prog, rest)) = cmd.split_first().filter(|_| sep == "--") else {
        return usage();
    };
    if let Err(e) = crate::cli_sandbox_sys::private_tmp() {
        eprintln!("kepr: private /tmp: {e}");
        std::process::exit(PRIVATE_TMP_UNAVAILABLE);
    }
    let e = Command::new(prog).args(rest).exec(); // returns only on failure
    Response::fail(format!("{prog}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// /dev/shm's file-system type from /proc/mounts, independent of the
    /// code under test.
    fn mount_type(dir: &str) -> Option<String> {
        let m = std::fs::read_to_string("/proc/mounts").ok()?;
        m.lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                (f.len() > 2 && f[1] == dir).then(|| f[2].to_string())
            })
            .next_back()
    }

    #[test]
    fn memory_fs_true_on_dev_shm() {
        if mount_type("/dev/shm").as_deref() != Some("tmpfs") {
            eprintln!("skip: /dev/shm is not tmpfs here");
            return;
        }
        assert!(path_on_memory_fs(Path::new("/dev/shm")));
        let p = format!("/dev/shm/kepr-memfs-test-{}", std::process::id());
        let f = std::fs::File::create(&p).unwrap();
        let on = on_memory_fs(&f);
        std::fs::remove_file(&p).unwrap();
        assert!(on);
    }

    #[test]
    fn private_tmp_needs_a_command() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(!cmd_private_tmp(&[]).is_success());
        assert!(!cmd_private_tmp(&v(&["--"])).is_success());
        assert!(!cmd_private_tmp(&v(&["sh", "-c", "true"])).is_success());
    }

    #[test]
    fn missing_path_is_not_memory() {
        assert!(!path_on_memory_fs(Path::new("/nonexistent/kepr/x")));
        assert!(!path_on_memory_fs(Path::new("a\0b")));
    }
}
