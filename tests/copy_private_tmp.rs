// copy_private_tmp.rs — `kepr __private-tmp` (T12.46) gives the command
// it runs a tmpfs /tmp of its own, leaves the host's /tmp alone, and
// passes stdin through (wl-copy reads the value there). Skips when user
// namespaces are denied (exit 3).

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn private_tmp(script: &str, stdin: &[u8]) -> Option<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kepr"))
        .args(["__private-tmp", "--", "sh", "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kepr");
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let out = child.wait_with_output().unwrap();
    if out.status.code() == Some(3) {
        eprintln!(
            "skip: user namespaces unavailable: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(out)
}

#[test]
fn private_tmp_is_tmpfs() {
    let Some(out) = private_tmp("stat -f -c %T /tmp", b"") else {
        return;
    };
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "tmpfs");
}

#[test]
fn host_tmp_untouched_and_stdin_passes_through() {
    let marker = format!("kepr-private-tmp-{}", std::process::id());
    let script =
        format!("touch /tmp/{marker} && test -z \"$(ls -A /tmp | grep -v {marker})\" && cat");
    let Some(out) = private_tmp(&script, b"value-on-stdin") else {
        return;
    };
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stdout, b"value-on-stdin");
    assert!(!std::path::Path::new("/tmp").join(&marker).exists());
}

// ── `kepr copy` end to end against a user-mode daemon, with a fake
// wl-copy on PATH that records its argv, its /tmp and its stdin.

struct Daemon {
    child: std::process::Child,
    home: tempfile::TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn env(cmd: &mut Command, home: &std::path::Path, path: &std::ffi::OsStr) {
    cmd.env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .env("WAYLAND_DISPLAY", "kepr-test-no-compositor")
        .env("KEPR_LOCK_ON_SLEEP", "0");
}

fn kepr(d: &Daemon, path: &std::ffi::OsStr, args: &[&str]) -> Output {
    let t = std::time::Instant::now();
    loop {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr"));
        env(&mut cmd, d.home.path(), path);
        let o = cmd.args(args).stdin(Stdio::null()).output().unwrap();
        let limited = |b: &[u8]| String::from_utf8_lossy(b).contains("rate limited");
        if !(limited(&o.stdout) || limited(&o.stderr)) || t.elapsed().as_secs() > 20 {
            return o;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

#[test]
fn copy_feeds_wl_copy_on_stdin_with_a_memory_tmp() {
    // Fake tools and their records live outside /tmp: the private /tmp
    // hides the host's.
    let work = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let (bin, out) = (work.path().join("bin"), work.path().join("out"));
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    let fake = |name: &str, body: &str| {
        use std::os::unix::fs::PermissionsExt;
        let p = bin.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    let o = out.display();
    fake(
        "wl-copy",
        &format!(
            "printf '%s\\n' \"$@\" > {o}/argv\nstat -f -c %T /tmp > {o}/tmpfs\ncat > {o}/value"
        ),
    );
    fake("wl-paste", "exit 1");
    let mut path = std::ffi::OsString::from(bin.as_os_str());
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());

    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("run")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr-daemon"));
    env(&mut cmd, home.path(), &path);
    let child = cmd
        .arg("--user")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let d = Daemon { child, home };
    let t = std::time::Instant::now();
    while !kepr(&d, &path, &["status"]).status.success() {
        assert!(t.elapsed().as_secs() < 10, "daemon did not come up");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let set = kepr(&d, &path, &["set", "CLIP_KEY", "--value", "clip-value-1"]);
    assert!(set.status.success(), "{set:?}");

    let copy = kepr(&d, &path, &["copy", "CLIP_KEY", "--clear", "1"]);
    let stderr = String::from_utf8_lossy(&copy.stderr).to_string();
    assert!(copy.status.success(), "{copy:?}");
    assert!(
        !stderr.contains("clip-value-1")
            && !String::from_utf8_lossy(&copy.stdout).contains("clip-value-1")
    );
    let read = |f: &str| std::fs::read_to_string(out.join(f)).unwrap_or_default();
    assert_eq!(read("value"), "clip-value-1");
    assert_eq!(read("argv"), "--type\ntext/plain;charset=utf-8\n");
    if stderr.contains("user namespaces unavailable") {
        eprintln!("skip tmpfs check: user namespaces unavailable");
        return;
    }
    assert_eq!(read("tmpfs").trim(), "tmpfs");
}
