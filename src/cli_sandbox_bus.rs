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
use std::path::PathBuf;

use crate::cli_desktop::dbus::addr::{self, Endpoint};

pub const ALLOW_VAR: &str = "KEPR_SANDBOX_DBUS";

pub fn allowed() -> bool {
    std::env::var(ALLOW_VAR).is_ok_and(|v| v == "allow")
}

/// The runtime directories a session bus and keyring sockets may live in:
/// `$XDG_RUNTIME_DIR` and systemd's `/run/user/UID`, so a bus is found even
/// where the variable is unset or points elsewhere.
pub fn runtime_dirs() -> Vec<PathBuf> {
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut v: Vec<PathBuf> = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .into_iter()
        .collect();
    v.push(PathBuf::from(format!("/run/user/{uid}")));
    v.dedup();
    v
}

/// Runtime-directory entries that hold keyring sockets of other programs.
pub fn keyring_dirs(runtimes: &[PathBuf]) -> Vec<PathBuf> {
    runtimes
        .iter()
        .flat_map(|r| [r.join("keyring"), r.join("gcr")])
        .collect()
}

/// The session bus's socket files: the ones the address names and the
/// default `bus` in each runtime directory; only sockets that exist.
pub fn bus_files(runtimes: &[PathBuf], address: Option<&str>) -> Vec<PathBuf> {
    let first = runtimes.first().and_then(|p| p.to_str());
    let mut v: Vec<PathBuf> = address
        .filter(|a| !a.is_empty())
        .and_then(|a| addr::parse(a, first).ok())
        .into_iter()
        .flatten()
        .filter_map(|e| match e {
            Endpoint::Path(p) => Some(p),
            Endpoint::Abstract(_) => None,
        })
        .collect();
    v.extend(runtimes.iter().map(|r| r.join("bus")));
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
    bus_files(
        &runtime_dirs(),
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
    keyring_dirs(&runtime_dirs())
}

/// A bus on an abstract socket is not a file, so no mask covers it: the
/// sandbox shares the network namespace unless `--isolate-net`. Say so.
pub fn abstract_bus_note(address: Option<&str>, isolate_net: bool) -> Option<&'static str> {
    let abstract_bus =
        address.is_some_and(|a| a.split(';').any(|p| p.starts_with("unix:abstract=")));
    (abstract_bus && !isolate_net && !allowed()).then_some(
        "your session bus is on an abstract socket, which the sandbox cannot hide: \
         the agent can reach it (and its keyrings) unless you add --isolate-net",
    )
}

/// Print `abstract_bus_note` for this process's environment.
pub fn warn_if_abstract(isolate_net: bool) {
    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
    if let Some(note) = abstract_bus_note(address.as_deref(), isolate_net) {
        eprintln!("kepr: sandbox: {note}");
    }
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
        let runtimes = vec![dir.clone()];
        let got = bus_files(&runtimes, Some(&address));
        assert_eq!(got, vec![bus.clone(), other.clone()]);
        assert_eq!(
            bus_files(&runtimes, None),
            vec![bus.clone()],
            "the default socket without an address"
        );
        assert!(
            bus_files(&[], Some("unix:abstract=/tmp/dbus-X")).is_empty(),
            "an abstract socket is not a file"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_runtime_directory_is_covered_and_systemds_is_always_one() {
        let two = vec![PathBuf::from("/run/user/1"), PathBuf::from("/tmp/xdg")];
        assert_eq!(
            keyring_dirs(&two),
            vec![
                PathBuf::from("/run/user/1/keyring"),
                PathBuf::from("/run/user/1/gcr"),
                PathBuf::from("/tmp/xdg/keyring"),
                PathBuf::from("/tmp/xdg/gcr"),
            ]
        );
        assert!(keyring_dirs(&[]).is_empty());
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        assert!(runtime_dirs().contains(&PathBuf::from(format!("/run/user/{uid}"))));
    }

    #[test]
    fn an_abstract_bus_is_called_out_unless_the_network_is_isolated() {
        let a = Some("unix:abstract=/tmp/dbus-AbC,guid=1");
        assert!(abstract_bus_note(a, false).is_some());
        assert!(abstract_bus_note(a, true).is_none());
        assert!(abstract_bus_note(Some("unix:path=/run/user/1/bus"), false).is_none());
        assert!(abstract_bus_note(None, false).is_none());
    }
}
