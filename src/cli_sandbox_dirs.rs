//! Directories hidden from sandboxed agent harnesses via empty tmpfs mounts.
use std::path::PathBuf;

use crate::cli_sandbox_sys as sys;

fn base(var: &str, default_rel: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(default_rel)))
}

/// Directories the agent must not see: credential store, daemon state
/// (master key, audit log), the daemon socket, the system-mode paths,
/// and every `kepr mount` directory (T12.20).
pub fn hide_dirs() -> Vec<PathBuf> {
    hide_dirs_with(&std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default())
}

pub fn hide_dirs_with(mountinfo: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [
        base("XDG_DATA_HOME", ".local/share"),
        base("XDG_STATE_HOME", ".local/state"),
    ]
    .into_iter()
    .flatten()
    .map(|b| b.join("kepr"))
    .collect();
    v.push(kepr_core::protocol::socket_dir());
    v.push(kepr_core::protocol::runtime_root()); // T11.16: every profile's socket
    v.extend(["/etc/credstore.encrypted", "/var/lib/kepr", "/run/kepr"].map(PathBuf::from));
    v.extend(sys::fuse_kepr_mounts(mountinfo));
    v.extend(crate::cli_sandbox_bus::hidden_dirs()); // T13.28: keyring sockets
    outermost(v.into_iter().filter(|p| p.is_dir()).collect())
}

/// Sorted, without any path inside another: a directory under one
/// already covered by an empty tmpfs no longer exists to be mounted on.
pub fn outermost(mut v: Vec<PathBuf>) -> Vec<PathBuf> {
    v.sort();
    v.dedup();
    let all = v.clone();
    v.retain(|p| !all.iter().any(|q| q != p && p.starts_with(q)));
    v
}
