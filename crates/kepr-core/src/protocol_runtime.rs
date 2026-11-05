//! User runtime selection, shared by daemon and clients.

use std::path::PathBuf;

pub(super) fn root() -> PathBuf {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR");
    #[cfg(target_os = "linux")]
    {
        linux_root(runtime.as_deref())
    }
    #[cfg(not(target_os = "linux"))]
    {
        runtime
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(std::env::temp_dir)
                    .join(".local/state/kepr/runtime")
            })
            .join("kepr")
    }
}

#[cfg(target_os = "linux")]
fn linux_root(runtime: Option<&std::ffi::OsStr>) -> PathBuf {
    runtime
        .map(std::path::Path::new)
        .filter(|path| path.is_absolute())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // SAFETY: getuid has no preconditions; use the same uid as client peer checks.
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/run/user/{uid}"))
        })
        .join("kepr")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn missing_empty_and_relative_runtime_use_the_user_run_directory() {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let expected = PathBuf::from(format!("/run/user/{uid}/kepr"));
        for runtime in [
            None,
            Some(OsStr::new("")),
            Some(OsStr::new("relative/runtime")),
        ] {
            assert_eq!(linux_root(runtime), expected);
        }
    }

    #[test]
    fn explicit_absolute_runtime_is_shared_by_isolated_daemons_and_clients() {
        assert_eq!(
            linux_root(Some(OsStr::new("/tmp/isolated-user-runtime"))),
            PathBuf::from("/tmp/isolated-user-runtime/kepr")
        );
        assert_eq!(
            linux_root(Some(OsStr::new("/run/user/1234/"))),
            PathBuf::from("/run/user/1234/kepr")
        );
    }
}
