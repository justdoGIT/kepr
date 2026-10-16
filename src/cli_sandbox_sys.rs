// cli_sandbox_sys.rs — low-level Linux primitives for the agent sandbox
// (agent vault T1.18): user-namespace id maps, loopback bring-up, the
// hiding mounts, closing inherited fds, capability drop (fd passing lives
// in kepr_core::fdpass), and the private /tmp `kepr copy` gives wl-copy
// (T12.46).
// Every function here is safe to call in a single-threaded child
// between fork and exec.

use std::ffi::CString;
use std::io::Write;
use std::os::fd::RawFd;

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Map our own uid/gid into the new user namespace (the only mapping an
/// unprivileged process may write for itself).
pub fn write_id_maps(uid: u32, gid: u32) -> Result<(), String> {
    let w = |path: &str, data: String| -> Result<(), String> {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|mut f| f.write_all(data.as_bytes()))
            .map_err(|e| format!("{path}: {e}"))
    };
    w("/proc/self/setgroups", "deny".into())?;
    w("/proc/self/uid_map", format!("{uid} {uid} 1"))?;
    w("/proc/self/gid_map", format!("{gid} {gid} 1"))
}

#[repr(C)]
struct IfReqFlags {
    name: [u8; 16],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// Bring up `lo` in a fresh network namespace (it starts down).
pub fn loopback_up() -> Result<(), String> {
    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
    let mut req = IfReqFlags {
        name: [0; 16],
        flags: 0,
        _pad: [0; 22],
    };
    req.name[..2].copy_from_slice(b"lo");
    // SAFETY: plain socket/ioctl/close; `req` is a correctly sized,
    // stack-local struct ifreq (name + short flags, padded to 40 bytes).
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return Err(os_err("socket"));
        }
        let ok = libc::ioctl(s, SIOCGIFFLAGS as _, &mut req) == 0 && {
            req.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            libc::ioctl(s, SIOCSIFFLAGS as _, &mut req) == 0
        };
        let err = os_err("bring up loopback");
        libc::close(s);
        if !ok {
            return Err(err);
        }
    }
    Ok(())
}

fn mount(
    src: &str,
    target: &CString,
    fstype: &str,
    flags: libc::c_ulong,
    data: &str,
) -> Result<(), String> {
    let (src, fstype, data) = (
        CString::new(src).map_err(|_| "bad mount source")?,
        CString::new(fstype).map_err(|_| "bad fs type")?,
        CString::new(data).map_err(|_| "bad mount data")?,
    );
    // SAFETY: all pointers are valid NUL-terminated strings for the call.
    let r = unsafe {
        libc::mount(
            src.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            data.as_ptr() as *const _,
        )
    };
    if r != 0 {
        return Err(os_err(&format!("mount {}", target.to_string_lossy())));
    }
    Ok(())
}

/// Stop mount events crossing into or out of our new mount namespace.
fn make_mounts_private() -> Result<(), String> {
    let root = CString::new("/").expect("static path");
    // SAFETY: MS_REC|MS_PRIVATE on "/" with null source/type/data.
    let r = unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if r != 0 {
        return Err(os_err("make mounts private"));
    }
    Ok(())
}

/// A private, memory-backed /tmp for this process and what it execs
/// (`kepr __private-tmp`, T12.46): new user and mount namespaces, our own
/// uid/gid mapped, then a small tmpfs over /tmp. The host's /tmp is
/// untouched. Must run single-threaded (unshare refuses otherwise).
pub fn private_tmp() -> Result<(), String> {
    // SAFETY: getuid / getgid cannot fail. Read before unshare: inside the
    // new namespace they read as the overflow id until the maps exist.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // SAFETY: unshare with constant flags and no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
        return Err(os_err("unshare"));
    }
    write_id_maps(uid, gid)?;
    make_mounts_private()?;
    let tmp = CString::new("/tmp").expect("static path");
    mount(
        "kepr-tmp",
        &tmp,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        "size=1m,mode=0700",
    )
}

/// Make our mount tree private, cover each `hide` directory with an
/// empty read-only tmpfs, and mount a /proc for the new PID namespace
/// (so host processes, and their /proc/PID/root, are invisible).
pub fn setup_mounts(hide: &[CString]) -> Result<(), String> {
    make_mounts_private()?;
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY;
    for dir in hide {
        mount("kepr-hidden", dir, "tmpfs", flags, "size=4k,mode=0500")?;
    }
    let proc_ = CString::new("/proc").expect("static path");
    mount(
        "proc",
        &proc_,
        "proc",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )
}

/// Empty the capability bounding, inheritable, permitted and effective
/// sets so nothing the harness execs can regain privileges.
pub fn drop_all_caps() {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // SAFETY: prctl/capset with valid, stack-local arguments. Errors are
    // ignored for caps the kernel doesn't know (EINVAL past CAP_LAST_CAP).
    unsafe {
        for cap in 0..64 {
            libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
        }
        let h = Header {
            version: 0x2008_0522,
            pid: 0,
        };
        let d = [Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        libc::syscall(libc::SYS_capset, &h as *const Header, d.as_ptr());
    }
}

pub use kepr_core::fdpass::{recv_fd, send_fd};

/// T12.52: close every descriptor above stderr except `keep`, so nothing
/// the caller left open (`3<DIR`) reaches the sandbox: `close_range`
/// around the kept fds, or a `/proc/self/fd` walk where it fails. Any
/// other fd above 2 the process owns as an `OwnedFd` must be in `keep`.
pub fn close_inherited(keep: &[RawFd]) -> Result<(), String> {
    for (first, last) in gaps(keep) {
        // SAFETY: close_range takes three integers and only closes this
        // process's own descriptors.
        let r = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                libc::c_long::from(first),
                libc::c_long::from(last),
                0 as libc::c_long,
            )
        };
        if r != 0 {
            // ENOSYS before Linux 5.9, EPERM under some container filters.
            return close_by_walk(keep);
        }
    }
    Ok(())
}

/// The ranges from 3 up that hold no kept descriptor.
fn gaps(keep: &[RawFd]) -> Vec<(u32, u32)> {
    let mut kept: Vec<u32> = keep.iter().filter_map(|&f| u32::try_from(f).ok()).collect();
    kept.retain(|&f| f > 2);
    kept.sort_unstable();
    kept.dedup();
    let (mut out, mut from) = (Vec::new(), 3);
    for f in kept {
        if f > from {
            out.push((from, f - 1));
        }
        from = f + 1; // f fits an i32, so this can't overflow
    }
    out.push((from, u32::MAX));
    out
}

fn close_by_walk(keep: &[RawFd]) -> Result<(), String> {
    // The directory's own fd is closed again once the listing is read.
    let names = std::fs::read_dir("/proc/self/fd")
        .and_then(|d| {
            d.map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect::<Result<Vec<String>, _>>()
        })
        .map_err(|e| format!("list open descriptors: {e}"))?;
    for fd in to_close(&names, keep) {
        // SAFETY: close on a descriptor number; EBADF (the listing's
        // own, already closed) is harmless.
        unsafe { libc::close(fd) };
    }
    Ok(())
}

fn to_close(names: &[String], keep: &[RawFd]) -> Vec<RawFd> {
    names
        .iter()
        .filter_map(|n| n.parse().ok())
        .filter(|f| *f > 2 && !keep.contains(f))
        .collect()
}

/// The fields after mountinfo's ` - ` separator: (fstype, source).
fn fs_and_source(line: &str) -> Option<(&str, &str)> {
    let mut f = line.split(' ').skip(6).skip_while(|w| *w != "-").skip(1);
    Some((f.next()?, f.next()?))
}

/// mountinfo's `\ooo` escapes (space, tab, newline, backslash) decoded.
fn unescape(field: &str) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStringExt;
    let b = field.as_bytes();
    let (mut out, mut i) = (Vec::with_capacity(b.len()), 0);
    while i < b.len() {
        let oct = b
            .get(i + 1..i + 4)
            .filter(|o| o.iter().all(|c| (b'0'..=b'7').contains(c)));
        match (b[i], oct) {
            (b'\\', Some(o)) => {
                out.push(o.iter().fold(0u8, |v, c| v.wrapping_mul(8) + (c - b'0')));
                i += 4;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    std::ffi::OsString::from_vec(out).into()
}

/// T12.20: the mount points of `kepr mount` file systems (fstype
/// `fuse.kepr`) in a /proc/PID/mountinfo text, octal escapes decoded.
/// Not for the forked child (it allocates): `hide_dirs` runs before.
pub fn fuse_kepr_mounts(mountinfo: &str) -> Vec<std::path::PathBuf> {
    mountinfo
        .lines()
        .filter(|l| fs_and_source(l).is_some_and(|(fs, _)| fs == "fuse.kepr"))
        .filter_map(|l| l.split(' ').nth(4).map(unescape))
        .collect()
}

/// T12.20: does this mountinfo belong to a process inside a `kepr agent
/// run` sandbox (a mount whose source is `setup_mounts`' `kepr-hidden`)?
pub fn in_kepr_sandbox(mountinfo: &str) -> bool {
    mountinfo
        .lines()
        .any(|l| fs_and_source(l).is_some_and(|(_, src)| src == "kepr-hidden"))
}

/// T12.20: is an ancestor of `pid` inside a sandbox? A harness can hide
/// its own sandbox mounts (mountinfo leaves out what lies outside a
/// chroot, and a nested user namespace allows one), not its parents'.
/// `read(pid, file)` reads /proc/PID/FILE. The walk ends at pid 1 or at
/// an ancestor it can't read (another user's process under hidepid).
pub fn sandboxed_ancestor(
    pid: u32,
    read: &dyn Fn(u32, &str) -> Option<String>,
) -> Result<bool, String> {
    let ppid = |p: u32| {
        let stat = read(p, "stat")?;
        let (_, rest) = stat.rsplit_once(") ")?;
        rest.split_whitespace().nth(1)?.parse::<u32>().ok()
    };
    let mut p = ppid(pid).ok_or("its parent is unknown")?;
    for _ in 0..64 {
        if p <= 1 {
            return Ok(false);
        }
        match read(p, "mountinfo") {
            Some(mi) if in_kepr_sandbox(&mi) => return Ok(true),
            Some(_) => {}
            None => return Ok(false),
        }
        p = match ppid(p) {
            Some(next) => next,
            None => return Ok(false),
        };
    }
    Err("its process tree is too deep".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const HOST: &str = "\
22 1 0:20 / / rw,relatime shared:1 - ext4 /dev/vda rw
40 22 0:35 / /home/u/my\\040secrets rw,nosuid,nodev,relatime shared:20 - fuse.kepr kepr ro,user_id=1000,group_id=1000,default_permissions
41 22 0:36 / /home/u/remote rw,nosuid,nodev,relatime shared:21 - fuse.sshfs u@h: rw,user_id=1000
42 22 0:37 / /mnt/t\\011n\\012b\\134x rw master:3 propagate_from:2 - fuse.kepr kepr ro
43 22 0:38 / /mnt/fuse.kepr rw - tmpfs fuse.kepr rw
";

    #[test]
    fn finds_kepr_fuse_mounts_and_decodes_escapes() {
        assert_eq!(
            fuse_kepr_mounts(HOST),
            [
                PathBuf::from("/home/u/my secrets"),
                PathBuf::from("/mnt/t\tn\nb\\x")
            ]
        );
        assert!(fuse_kepr_mounts("").is_empty());
        assert!(fuse_kepr_mounts("garbage\n1 2 3\n").is_empty());
    }

    #[test]
    fn a_kepr_hidden_tmpfs_marks_a_sandbox() {
        assert!(!in_kepr_sandbox(HOST));
        let sandbox = format!(
            "{HOST}50 40 0:40 / /home/u/.local/share/kepr ro,nosuid,nodev,noexec - tmpfs \
             kepr-hidden ro,size=4k,mode=500\n"
        );
        assert!(in_kepr_sandbox(&sandbox));
        assert!(!in_kepr_sandbox(
            "50 40 0:40 / /kepr-hidden rw - tmpfs tmpfs rw\n"
        ));
    }

    /// A fake /proc: pid -> (ppid, mountinfo).
    fn proc_of<'a>(
        procs: &'a [(u32, u32, &'static str)],
    ) -> impl Fn(u32, &str) -> Option<String> + 'a {
        move |pid, file| {
            let &(_, ppid, mi) = procs.iter().find(|p| p.0 == pid)?;
            match file {
                "stat" => Some(format!("{pid} (a b) c) S {ppid} 1 1 0 -1")),
                "mountinfo" => Some(mi.to_string()),
                _ => None,
            }
        }
    }

    #[test]
    fn a_sandboxed_ancestor_gives_away_a_chrooted_opener() {
        // A chroot in a nested user namespace drops the sandbox's mounts
        // from the opener's own mountinfo, but not from its parents'.
        let sb = "2 1 0:40 / /h/.local/share/kepr ro - tmpfs kepr-hidden ro\n";
        let chrooted = "9 8 0:50 / / rw - tmpfs none rw\n";
        let tree = [
            (1, 0, HOST),
            (50, 1, HOST),
            (60, 50, sb),
            (70, 60, chrooted),
        ];
        let read = proc_of(&tree);
        assert_eq!(sandboxed_ancestor(70, &read), Ok(true));
        assert_eq!(
            sandboxed_ancestor(60, &read),
            Ok(false),
            "its own table is checked apart"
        );
        assert_eq!(sandboxed_ancestor(50, &read), Ok(false));
        // An ancestor we can't see (another user's, hidepid) ends the walk.
        let hidden = [(70, 66, chrooted)];
        assert_eq!(sandboxed_ancestor(70, &proc_of(&hidden)), Ok(false));
        assert!(
            sandboxed_ancestor(99, &read).is_err(),
            "the opener's parent must be known"
        );
        let deep: Vec<(u32, u32, &'static str)> = (2..100).map(|p| (p, p + 1, HOST)).collect();
        assert!(sandboxed_ancestor(2, &proc_of(&deep)).is_err());
    }

    #[test]
    fn close_ranges_go_around_the_kept_descriptors() {
        let max = u32::MAX;
        assert_eq!(gaps(&[]), [(3, max)]);
        assert_eq!(gaps(&[0, 1, 2]), [(3, max)], "stdio is never closed");
        assert_eq!(gaps(&[3]), [(4, max)]);
        assert_eq!(gaps(&[9, 5, 5, 6]), [(3, 4), (7, 8), (10, max)]);
    }

    #[test]
    fn the_walk_closes_numbered_entries_above_stderr_only() {
        let names = ["0", "1", "2", "3", "7", "12", ".", "x"].map(String::from);
        assert_eq!(to_close(&names, &[7]), [3, 12]);
    }

    /// Run `close` with one kept descriptor in a forked child that also
    /// holds an inherited pipe at a high fd (as `3<DIR` would); returns
    /// the child's open descriptors per `/proc/self/fd`, the kept fd and
    /// the high fd.
    fn open_after(close: fn(&[RawFd]) -> Result<(), String>) -> (Vec<RawFd>, RawFd, RawFd) {
        let (mut report, mut inherited) = ([0; 2], [0; 2]);
        // SAFETY: pipe2/pipe/fcntl write two fds into stack arrays.
        let high = unsafe {
            assert_eq!(libc::pipe2(report.as_mut_ptr(), libc::O_CLOEXEC), 0);
            assert_eq!(libc::pipe2(inherited.as_mut_ptr(), libc::O_CLOEXEC), 0);
            libc::fcntl(inherited[0], libc::F_DUPFD, 500) // no close-on-exec
        };
        assert!(high >= 500);
        let (rd, wr) = (report[0], report[1]);
        // SAFETY: the child only lists /proc/self/fd, writes and _exits.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let code = i32::from(close(&[wr]).is_err());
            let listed: Vec<RawFd> = std::fs::read_dir("/proc/self/fd")
                .map(|d| d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()))
                .into_iter()
                .flatten()
                .collect();
            // The listing's own descriptor is closed again by now.
            // SAFETY: F_GETFD only reads a descriptor's flags.
            let open: Vec<String> = listed
                .into_iter()
                .filter(|&f| unsafe { libc::fcntl(f, libc::F_GETFD) } != -1)
                .map(|f| f.to_string())
                .collect();
            let msg = open.join(" ");
            // SAFETY: write from a live buffer, then _exit after fork.
            unsafe {
                libc::write(wr, msg.as_ptr().cast(), msg.len());
                libc::_exit(code)
            }
        }
        assert!(pid > 0);
        // SAFETY: closing our own descriptors; reading into a live buffer.
        let out = unsafe {
            for fd in [wr, high, inherited[0], inherited[1]] {
                libc::close(fd);
            }
            let mut buf = [0u8; 4096];
            let mut out = Vec::new();
            loop {
                let n = libc::read(rd, buf.as_mut_ptr().cast(), buf.len());
                if n <= 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n as usize]);
            }
            libc::close(rd);
            out
        };
        let mut status = 0;
        // SAFETY: waitpid on our own child with a valid status pointer.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        let open = String::from_utf8(out).unwrap();
        let open = open.split(' ').filter_map(|f| f.parse().ok()).collect();
        (open, wr, high)
    }

    #[test]
    fn close_inherited_leaves_stdio_and_the_kept_fd() {
        for close in [close_inherited, close_by_walk] {
            let (open, kept, high) = open_after(close);
            assert!(open.contains(&kept), "kept fd {kept} closed: {open:?}");
            assert!(!open.contains(&high), "inherited fd {high} open: {open:?}");
            let extra: Vec<_> = open.iter().filter(|&&f| f > 2 && f != kept).collect();
            assert!(extra.is_empty(), "left open: {extra:?}");
            // SAFETY: F_GETFD only reads a descriptor's flags.
            for f in (0..=2).filter(|&f| unsafe { libc::fcntl(f, libc::F_GETFD) } != -1) {
                assert!(open.contains(&f), "stdio fd {f} closed: {open:?}");
            }
        }
    }
}
