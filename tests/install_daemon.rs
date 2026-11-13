//! Installer restarts are confined to one user socket and preserve its key.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Detached(OwnedFd);

impl Detached {
    fn track(pid: i32) -> Self {
        // SAFETY: pidfd_open returns a new owned descriptor for this test daemon.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "could not track replacement daemon");
        // SAFETY: the successful syscall transferred ownership of this descriptor.
        Self(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
}

impl Drop for Detached {
    fn drop(&mut self) {
        // SAFETY: this pidfd identifies only the replacement created by the test.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.0.as_raw_fd(),
                libc::SIGTERM,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
    }
}

fn socket(home: &Path, profile: &str) -> PathBuf {
    let runtime = home.join("run/kepr");
    if profile == "default" {
        runtime.join("kepr.sock")
    } else {
        runtime.join("profiles").join(profile).join("kepr.sock")
    }
}

fn peer_pid(path: &Path) -> Option<i32> {
    let stream = UnixStream::connect(path).ok()?;
    let mut peer: libc::ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of_val(&peer) as libc::socklen_t;
    // SAFETY: both output pointers refer to writable, correctly sized locals.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut peer).cast(),
            &mut len,
        )
    };
    (result == 0).then_some(peer.pid)
}

fn environment(command: &mut Command, home: &Path, profile: &str) {
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .env("KEPR_PROFILE", profile)
        .env("PYTHONDONTWRITEBYTECODE", "1");
}

fn start(home: &Path, profile: &str) -> Daemon {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kepr-daemon"));
    environment(&mut command, home, profile);
    let mut daemon = Daemon(
        command
            .arg("--user")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while peer_pid(&socket(home, profile)).is_none() {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "fixture daemon exited"
        );
        assert!(Instant::now() < deadline, "fixture daemon did not start");
        std::thread::sleep(Duration::from_millis(25));
    }
    daemon
}

fn restart(home: &Path, daemon: &Path) -> std::process::Output {
    let mut command = Command::new("python3");
    environment(&mut command, home, "default");
    command
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/restart-user-daemon.py"))
        .arg(daemon)
        .output()
        .unwrap()
}

#[test]
fn installer_restarts_only_selected_daemon_without_replacing_keys() {
    let home = tempfile::tempdir().unwrap();
    fs::create_dir(home.path().join("run")).unwrap();
    let mut original = start(home.path(), "default");
    let mut other = start(home.path(), "other");
    let key = home.path().join(".local/state/kepr/master.key");
    let before = fs::read(&key).unwrap();
    let output = restart(home.path(), Path::new(env!("CARGO_BIN_EXE_kepr-daemon")));
    let replacement = peer_pid(&socket(home.path(), "default"));
    let _replacement_guard = replacement
        .filter(|pid| *pid != original.0.id() as i32)
        .map(Detached::track);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(replacement, Some(original.0.id() as i32));
    assert!(original.0.wait().unwrap().code().is_none());
    assert!(
        other.0.try_wait().unwrap().is_none(),
        "another profile was stopped"
    );
    assert!(fs::read(&key).unwrap() == before, "master key was replaced");
}

#[test]
fn missing_installed_binary_does_not_stop_existing_daemon() {
    let home = tempfile::tempdir().unwrap();
    fs::create_dir(home.path().join("run")).unwrap();
    let mut original = start(home.path(), "default");
    let output = restart(home.path(), &home.path().join("missing-kepr-daemon"));
    assert!(!output.status.success());
    assert!(original.0.try_wait().unwrap().is_none());
    assert_eq!(
        peer_pid(&socket(home.path(), "default")),
        Some(original.0.id() as i32)
    );
}
