//! Harden kepr-gate, read its session config, watch the owner, then serve.

use kepr_core::gate_protocol::{ReadyLine, SessionConfig};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::placeholder;
use crate::proxy::{self, Route, State};
use crate::vault::{Cache, FdResolver, DEFAULT_TTL};
use kepr_core::secmem::SplitKey;

#[path = "session_run.rs"]
mod runner;
pub use runner::run;
const MAX_CONFIG: u64 = 64 * 1024;

/// Non-dumpable (blocks same-uid ptrace and makes /proc/PID/mem
/// root-owned) and no core files. Must run before any secret exists.
pub fn harden() -> Result<(), String> {
    // SAFETY: prctl/setrlimit with constant arguments; no pointers
    // other than a valid stack-local rlimit struct.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err("cannot make process non-dumpable".into());
        }
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            return Err("cannot disable core dumps".into());
        }
    }
    Ok(())
}

pub fn parse_owner_pid(args: &[String]) -> Result<i32, String> {
    match args {
        [flag, pid] if flag == "--owner-pid" => pid
            .parse::<i32>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| "invalid --owner-pid".to_string()),
        _ => Err("usage: kepr-gate --owner-pid PID (started by kepr-daemon)".into()),
    }
}

pub fn decode_key(hex_key: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let bytes = Zeroizing::new(hex::decode(hex_key).map_err(|_| "session key is not hex")?);
    let mut key = Zeroizing::new([0u8; 32]);
    if bytes.len() != 32 {
        return Err("session key must be 32 bytes".into());
    }
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn validate_config(cfg: &SessionConfig) -> Result<(), String> {
    if cfg.session_id.len() != 16 || !cfg.session_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("session id must be 16 hex chars".into());
    }
    kepr_core::gate_protocol::validate_routes(&cfg.routes)?;
    if let Some(policy) = &cfg.privacy {
        policy.validate_routes(&cfg.routes, cfg.tunnel)?;
    }
    Ok(())
}

pub(crate) fn pidfd_open(pid: i32) -> Result<OwnedFd, String> {
    // SAFETY: pidfd_open takes a pid and flags; it returns a new fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err("owner process is not running".into());
    }
    // SAFETY: the syscall just returned this fd to us; we own it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Confine before spawning threads: restrictions cover this thread and its children.
/// Not called by `service::serve`, which starts session gates.
pub(crate) fn confine() -> Result<(), String> {
    use kepr_core::{landlock, seccomp};
    fn failed(e: impl std::fmt::Display) -> String {
        format!("cannot harden the gate: {e}")
    }
    if !landlock::restrict_read_only(&gate_read_paths()).map_err(failed)? {
        eprintln!("kepr-gate: this kernel has no Landlock; file access is not fenced");
    }
    seccomp::install(&seccomp::gate_program()).map_err(failed)
}

const READ_DIRS: [&str; 7] = [
    "/etc",
    "/usr",
    "/lib",
    "/lib64",
    "/nix/store",
    "/proc",
    "/sys",
];

/// Read-only libraries, NSS/resolver files, /proc and /sys: existing canonical
/// paths only, never at, above or under a path in `never_paths`.
pub(crate) fn gate_read_paths() -> Vec<PathBuf> {
    let never = never_paths();
    let mut v: Vec<PathBuf> = READ_DIRS
        .iter()
        .filter_map(|d| std::fs::canonicalize(d).ok())
        .collect();
    if let Ok(conf) = std::fs::canonicalize("/etc/resolv.conf") {
        v.push(resolver_path(&conf, &never));
    }
    v.retain(|p| !reaches(p, &never));
    v.sort();
    v.dedup();
    v
}

/// The directory holding the resolver file (/run/systemd/resolve for
/// systemd-resolved), or the file alone when that directory is `/` or
/// reaches a path in `never` (/run, which holds /run/user).
fn resolver_path(conf: &Path, never: &[PathBuf]) -> PathBuf {
    match conf.parent() {
        Some(dir) if dir.parent().is_some() && !reaches(dir, never) => dir.to_path_buf(),
        _ => conf.to_path_buf(),
    }
}

/// `p` is at, above or under one of `never`.
fn reaches(p: &Path, never: &[PathBuf]) -> bool {
    never.iter().any(|n| p.starts_with(n) || n.starts_with(p))
}

/// Home directories, /run/user and the daemon's state. The daemon starts
/// a session with a cleared environment, so this user's home also comes
/// from the passwd entry; `/` (a DynamicUser's home) is left out.
fn never_paths() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = ["/root", "/home", "/run/user", "/var/lib/kepr"]
        .iter()
        .map(PathBuf::from)
        .collect();
    v.extend(std::env::var_os("HOME").map(PathBuf::from));
    v.extend(passwd_home());
    let canonical: Vec<PathBuf> = v.iter().filter_map(|p| p.canonicalize().ok()).collect();
    v.extend(canonical);
    v.retain(|p| p.is_absolute() && p.parent().is_some());
    v
}

fn passwd_home() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: an all-zero passwd is a valid value of this plain C struct.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwuid_r fills `pw` and `buf`, both valid for the sizes
    // given, and sets `out` to `&pw` or NULL.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir points to a NUL-terminated string inside `buf`.
    let dir = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

fn fd3_is_open() -> bool {
    // SAFETY: F_GETFD only reads the descriptor flags.
    unsafe { libc::fcntl(3, libc::F_GETFD) >= 0 }
}

async fn bind_gate(port: u16) -> Result<tokio::net::TcpListener, String> {
    tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("cannot listen on 127.0.0.1:{port}: {e}"))
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
