// cli_sandbox_bus.rs — keep a sandboxed agent off the desktop's secret
// services (T13.28). The session bus carries the Secret Service
// (org.freedesktop.secrets: kepr's, GNOME Keyring's or KWallet's), and a
// program that can open its socket can ask for every password in it. Inside
// `kepr agent run`'s sandbox the socket file is covered with /dev/null, and
// the sockets GNOME Keyring / gcr keep in the runtime directory are hidden
// with the other directories. `KEPR_SANDBOX_DBUS=allow` leaves the bus
// reachable. A bus on an abstract socket (X11 `dbus-launch`) is not a file:
// only `--isolate-net` separates it.

use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use crate::cli_desktop::dbus::addr::{self, Endpoint};

pub const ALLOW_VAR: &str = "KEPR_SANDBOX_DBUS";

pub fn allowed() -> bool {
    std::env::var(ALLOW_VAR).is_ok_and(|v| v == "allow")
}

/// Runtime-directory entries (under `$XDG_RUNTIME_DIR`) that hold keyring
/// sockets of other programs.
pub fn keyring_dirs(runtime: Option<&Path>) -> Vec<PathBuf> {
    runtime
        .map(|r| vec![r.join("keyring"), r.join("gcr")])
        .unwrap_or_default()
}

/// The session bus's socket files: the ones the address names and the
/// default `$XDG_RUNTIME_DIR/bus`; only sockets that exist.
pub fn bus_files(runtime: Option<&Path>, address: Option<&str>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = address
        .filter(|a| !a.is_empty())
        .and_then(|a| addr::parse(a, runtime.and_then(Path::to_str)).ok())
        .into_iter()
        .flatten()
        .filter_map(|e| match e {
            Endpoint::Path(p) => Some(p),
            Endpoint::Abstract(_) => None,
        })
        .collect();
    if let Some(r) = runtime {
        v.push(r.join("bus"));
    }
    v.retain(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_socket()));
    v.sort();
    v.dedup();
    v
}

/// What the sandbox masks, from the environment.
pub fn hidden_files() -> Vec<PathBuf> {
    if allowed() {
        return Vec::new();
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    bus_files(
        runtime.as_deref(),
        std::env::var("DBUS_SESSION_BUS_ADDRESS").ok().as_deref(),
    )
}

/// `hidden_files` as C strings, ready for the forked child (which must not
/// allocate).
pub fn hidden_cstrings() -> Vec<std::ffi::CString> {
    hidden_files()
        .into_iter()
        .filter_map(|p| std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).ok())
        .collect()
}

pub fn hidden_dirs() -> Vec<PathBuf> {
    if allowed() {
        return Vec::new();
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    keyring_dirs(runtime.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn only_existing_sockets_are_named_once() {
        let dir = std::env::temp_dir().join(format!("kepr-sbx-bus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bus = dir.join("bus");
        let other = dir.join("other-bus");
        let _l1 = UnixListener::bind(&bus).unwrap();
        let _l2 = UnixListener::bind(&other).unwrap();
        std::fs::write(dir.join("plain"), "x").unwrap();
        let address = format!(
            "unix:path={},guid=abc;unix:path={};unix:abstract=/tmp/dbus-X;unix:path={}",
            other.display(),
            dir.join("plain").display(),
            dir.join("missing").display()
        );
        let got = bus_files(Some(&dir), Some(&address));
        assert_eq!(got, vec![bus.clone(), other.clone()]);
        assert_eq!(
            bus_files(Some(&dir), None),
            vec![bus.clone()],
            "the default socket without an address"
        );
        assert!(
            bus_files(None, Some("unix:abstract=/tmp/dbus-X")).is_empty(),
            "an abstract socket is not a file"
        );
        assert_eq!(
            keyring_dirs(Some(Path::new("/run/user/1"))),
            vec![
                PathBuf::from("/run/user/1/keyring"),
                PathBuf::from("/run/user/1/gcr")
            ]
        );
        assert!(keyring_dirs(None).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
