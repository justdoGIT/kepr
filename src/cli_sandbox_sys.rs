// cli_sandbox_sys.rs — low-level Linux primitives for the agent sandbox
// (agent vault T1.18): user-namespace id maps, loopback bring-up, the
// hiding mounts, capability drop (fd passing lives in kepr_core::fdpass).
// Every function here is safe to call in a single-threaded child
// between fork and exec.

use std::ffi::CString;
use std::io::Write;

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

/// Make our mount tree private, cover each `hide` directory with an
/// empty read-only tmpfs, and mount a /proc for the new PID namespace
/// (so host processes, and their /proc/PID/root, are invisible).
pub fn setup_mounts(hide: &[CString]) -> Result<(), String> {
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
}
