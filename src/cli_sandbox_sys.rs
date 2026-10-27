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
