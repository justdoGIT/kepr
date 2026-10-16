// cli_platform/mount_os.rs — `kepr mount` (T10.01): the device, the mount,
// the request loop and the per-open checks.
//
//   kepr mount DIR --file NAME=KEY1,KEY2 [--file ...] [--exe PATH]... [--consent]
//
// Speaks the FUSE protocol on /dev/fuse itself (no libfuse, no crate). As
// root it mounts with mount(2); otherwise the setuid `fusermount3` mounts
// and hands the device back over a socket (SCM_RIGHTS, `_FUSE_COMMFD`).
// Without `allow_other` the kernel lets only the mounting user in; every
// open is checked again here (uid, then the opener's executable against
// --exe, then a polkit prompt with --consent) before any value is fetched.
// Runs in the foreground; Ctrl-C (or `fusermount3 -u DIR`) unmounts.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use kepr_core::exe_digest;
use kepr_core::protocol::Response;
use zeroize::Zeroizing;

use super::args;
use super::mount::{parse_spec, Fs, Gate};

const USAGE: &str =
    "usage: kepr mount DIR --file NAME=KEY1,KEY2 [--file ...] [--exe PATH]... [--consent]";
const FUSERMOUNT: &[&str] = &[
    "/usr/bin/fusermount3",
    "/bin/fusermount3",
    "/usr/local/bin/fusermount3",
];
const PKCHECK: &str = "/usr/bin/pkcheck";
const ACTION_ID: &str = "io.kepr.read-credential";

/// Signals received (SIGINT / SIGTERM / SIGHUP).
static STOPS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_signal(_: libc::c_int) {
    STOPS.fetch_add(1, Ordering::SeqCst);
}

/// Per-open policy for processes of the mount owner.
pub struct OpenerGate {
    pub exe: Vec<String>,
    pub consent: bool,
}

impl Gate for OpenerGate {
    fn check(&self, _uid: u32, pid: u32) -> Result<(), String> {
        if pid == 0 {
            return Err("the caller is outside this PID namespace".into());
        }
        let mounts = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")).ok();
        self.check_with(pid, mounts.as_deref())
    }
}

impl OpenerGate {
    /// T12.20: an agent sandbox's harness has our uid and a copy of this
    /// mount, but must not read it (that would bypass the hidden daemon
    /// socket): its mount table gives it away. Then --exe and --consent.
    fn check_with(&self, pid: u32, mountinfo: Option<&str>) -> Result<(), String> {
        let mountinfo = mountinfo.ok_or("its mount table is unreadable")?;
        if crate::cli_sandbox_sys::in_kepr_sandbox(mountinfo) {
            return Err("the caller is inside a kepr agent sandbox".into());
        }
        if !self.exe.is_empty() {
            exe_allowed(pid, &self.exe)?;
        }
        if self.consent && !consent(pid) {
            return Err("consent refused or timed out".into());
        }
        Ok(())
    }
}

fn exe_allowed(pid: u32, allowed: &[String]) -> Result<(), String> {
    let path = format!("/proc/{pid}/exe");
    let link = std::fs::read_link(&path).map_err(|_| "its program is unreadable".to_string())?;
    let shown = link.display().to_string();
    if shown.ends_with(" (deleted)") {
        return Err(format!("{shown}: its program was deleted"));
    }
    let f = File::open(&path).map_err(|_| "its program is unreadable".to_string())?;
    if exe_digest::matches(allowed, exe_digest::verity_of(&f), || {
        exe_digest::sha256_of(&f)
    }) {
        Ok(())
    } else {
        Err(format!("{shown} is not an allowed program (--exe)"))
    }
}

/// polkit `io.kepr.read-credential` for the opener (pid + start time, so a
/// recycled pid cannot answer); 60 s to decide, fail closed.
fn consent(pid: u32) -> bool {
    let start = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            s.rsplit_once(") ")
                .and_then(|(_, r)| r.split_whitespace().nth(19).map(str::to_string))
        });
    let Some(start) = start else { return false };
    let child = Command::new(PKCHECK)
        .args([
            "--action-id",
            ACTION_ID,
            "--allow-user-interaction",
            "--process",
        ])
        .arg(format!("{pid},{start}"))
        .spawn();
    let Ok(mut child) = child else { return false };
    let t = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s.success(),
            Ok(None) if t.elapsed() < Duration::from_secs(60) => {
                std::thread::sleep(Duration::from_millis(100))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

enum How {
    Syscall,
    Fusermount(PathBuf),
}

fn cstr(s: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| "path contains a NUL byte".to_string())
}

fn mount(dir: &Path, (uid, gid): (u32, u32)) -> Result<(File, How), String> {
    let d = dir.display().to_string();
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        let dev = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/fuse")
            .map_err(|e| format!("/dev/fuse: {e}"))?;
        let opts = format!(
            "fd={},rootmode=40000,user_id={uid},group_id={gid},default_permissions",
            dev.as_raw_fd()
        );
        let (src, target, fstype, data) =
            (cstr("kepr")?, cstr(&d)?, cstr("fuse.kepr")?, cstr(&opts)?);
        let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_RDONLY;
        // SAFETY: all pointers are valid NUL-terminated strings for the call.
        let r = unsafe {
            libc::mount(
                src.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                flags,
                data.as_ptr().cast(),
            )
        };
        if r != 0 {
            return Err(format!("mount {d}: {}", std::io::Error::last_os_error()));
        }
        return Ok((dev, How::Syscall));
    }
    let fm = FUSERMOUNT
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .ok_or("kepr mount needs fusermount3 (package fuse3), or run it as root")?;
    let (ours, theirs) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    // SAFETY: clears FD_CLOEXEC on our own socket so fusermount3 inherits it.
    unsafe { libc::fcntl(theirs.as_raw_fd(), libc::F_SETFD, 0) };
    let status = Command::new(&fm)
        .args([
            "-o",
            "ro,nosuid,nodev,default_permissions,fsname=kepr,subtype=kepr",
            "--",
            &d,
        ])
        .env("_FUSE_COMMFD", theirs.as_raw_fd().to_string())
        .status()
        .map_err(|e| format!("{}: {e}", fm.display()))?;
    drop(theirs);
    if !status.success() {
        return Err(format!("fusermount3 could not mount {d}"));
    }
    let fd = kepr_core::fdpass::recv_fd(&ours)?.ok_or("fusermount3 sent no device")?;
    // SAFETY: a fresh fd received over SCM_RIGHTS, owned from here on.
    Ok((unsafe { File::from_raw_fd(fd) }, How::Fusermount(fm)))
}

/// Unmount on a helper thread: the loop keeps answering meanwhile.
fn unmount(dir: &Path, how: &How) -> std::thread::JoinHandle<()> {
    let d = dir.to_path_buf();
    let fm = match how {
        How::Syscall => None,
        How::Fusermount(p) => Some(p.clone()),
    };
    std::thread::spawn(move || match fm {
        Some(fm) => {
            let _ = Command::new(fm)
                .arg("-u")
                .arg("-z")
                .arg("--")
                .arg(&d)
                .status();
        }
        None => {
            if let Ok(c) = cstr(&d.display().to_string()) {
                // SAFETY: valid path string; lazy unmount of our own mount.
                unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
            }
        }
    })
}

fn catch_signals() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: a plain handler that only bumps an atomic; no SA_RESTART,
        // so a blocked read on /dev/fuse returns EINTR.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

fn serve(dev: &mut File, fs: &mut Fs<'_>, dir: &Path, how: &How) -> Result<(), String> {
    let mut buf = vec![0u8; super::fuse::MAX_WRITE as usize + 64 * 1024];
    let mut stops_seen = 0;
    loop {
        let stops = STOPS.load(Ordering::SeqCst);
        if stops > stops_seen {
            if stops_seen > 0 {
                return Ok(()); // second signal: exit; closing the device aborts the mount
            }
            stops_seen = stops;
            drop(unmount(dir, how));
        }
        match dev.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                if let Some(rep) = fs.handle(&buf[..n]).map(Zeroizing::new) {
                    // ENOENT: the request was interrupted; nothing to do.
                    let _ = dev.write(&rep);
                }
                if fs.done {
                    return Ok(());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) if e.raw_os_error() == Some(libc::ENODEV) => return Ok(()),
            Err(e) => return Err(format!("/dev/fuse: {e}")),
        }
    }
}

pub fn cmd_mount(argv: &[String]) -> Response {
    run(argv).unwrap_or_else(Response::fail)
}

fn run(argv: &[String]) -> Result<Response, String> {
    let a = args::parse(argv, &["--file", "--exe"], &["--consent"])?;
    let ([dir], false) = (a.positional.as_slice(), a.values("--file").is_empty()) else {
        return Err(USAGE.into());
    };
    let files = a
        .values("--file")
        .into_iter()
        .map(parse_spec)
        .collect::<Result<Vec<_>, _>>()?;
    for (i, f) in files.iter().enumerate() {
        if files[..i].iter().any(|g| g.file == f.file) {
            return Err(format!("--file {} given twice", f.file));
        }
    }
    let exe = match a.values("--exe") {
        v if v.is_empty() => Vec::new(),
        v => super::exe::identities_of(&v)?,
    };
    let dir = std::fs::canonicalize(dir).map_err(|e| format!("{dir}: {e}"))?;
    if !dir.is_dir() {
        return Err(format!("{}: not a directory", dir.display()));
    }
    let gate = OpenerGate {
        exe,
        consent: a.has("--consent"),
    };
    // SAFETY: getuid/getgid have no preconditions.
    let owner = unsafe { (libc::getuid(), libc::getgid()) };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let names: Vec<String> = files.iter().map(|f| f.file.clone()).collect();
    let fetch = crate::cli_exec::DaemonFetcher;
    let mut fs = Fs::new(files, &gate, &fetch, owner, now);
    catch_signals();
    let (mut dev, how) = mount(&dir, owner)?;
    eprintln!(
        "kepr mount: {} at {} (Ctrl-C to unmount)",
        names.join(", "),
        dir.display()
    );
    let r = serve(&mut dev, &mut fs, &dir, &how);
    if STOPS.load(Ordering::SeqCst) == 0 {
        let _ = unmount(&dir, &how).join(); // after an error, or unmounted elsewhere
    }
    r.map(|_| Response::Pong)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: &str = "22 1 0:20 / / rw,relatime shared:1 - ext4 /dev/vda rw\n\
        40 22 0:35 / /home/u/mnt ro,nosuid shared:20 - fuse.kepr kepr ro\n";
    const SANDBOX: &str = "1 0 0:20 / / rw - ext4 /dev/vda rw\n\
        2 1 0:40 / /home/u/.local/share/kepr ro,nosuid,nodev,noexec - tmpfs kepr-hidden ro\n\
        3 1 0:41 / /home/u/mnt ro,nosuid,nodev,noexec - tmpfs kepr-hidden ro\n";

    #[test]
    fn sandboxed_or_unknown_openers_are_refused() {
        let gate = OpenerGate {
            exe: Vec::new(),
            consent: false,
        };
        let pid = std::process::id();
        assert_eq!(
            gate.check_with(pid, None).unwrap_err(),
            "its mount table is unreadable"
        );
        assert_eq!(
            gate.check_with(pid, Some(SANDBOX)).unwrap_err(),
            "the caller is inside a kepr agent sandbox"
        );
        assert!(gate.check_with(pid, Some(PLAIN)).is_ok());
        // The real check reads this process's own mount table.
        let own = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let sandboxed = crate::cli_sandbox_sys::in_kepr_sandbox(&own);
        assert_eq!(gate.check(0, pid).is_ok(), !sandboxed);
        assert!(gate.check(0, 0).is_err());
    }

    #[test]
    fn the_sandbox_check_comes_before_exe() {
        let gate = OpenerGate {
            exe: vec!["sha256:00".into()],
            consent: false,
        };
        let pid = std::process::id();
        assert_eq!(
            gate.check_with(pid, Some(SANDBOX)).unwrap_err(),
            "the caller is inside a kepr agent sandbox"
        );
        assert!(
            gate.check_with(pid, Some(PLAIN)).is_err(),
            "--exe still applies"
        );
    }
}
