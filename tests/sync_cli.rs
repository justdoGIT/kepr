// sync_cli.rs — T6.10 multi-device sync end to end: user-mode kepr-daemons
// in temporary HOMEs pair with `kepr device add` / `enroll`, share a
// `dir:` remote and run `kepr sync now`. Hermetic: nothing outside the
// temp dirs is touched.

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
    home: tempfile::TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn env(cmd: &mut Command, home: &Path) {
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .env("KEPR_LOCK_ON_SLEEP", "0");
}

fn start() -> Daemon {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("run")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr-daemon"));
    env(&mut cmd, home.path());
    let child = cmd
        .arg("--user")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start kepr-daemon");
    let d = Daemon { child, home };
    let t = Instant::now();
    while !kepr(&d, &["status"]).status.success() {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "daemon did not come up"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

fn kepr(d: &Daemon, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr"));
    env(&mut cmd, d.home.path());
    cmd.args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run kepr")
}

fn ok(d: &Daemon, args: &[&str]) -> String {
    let o = kepr(d, args);
    assert!(
        o.status.success(),
        "kepr {args:?} failed: {}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// `device` asks for a token, `new` writes the request, `device` pins it.
fn enroll(device: &Daemon, new: &Daemon) {
    let token = ok(device, &["device", "add", "peer"]);
    let token = token.lines().next().unwrap().trim();
    let file = new.home.path().join(format!("enroll-{}.json", token.len()));
    let _ = std::fs::remove_file(&file);
    let f = file.to_str().unwrap();
    ok(new, &["device", "enroll", token, "-o", f]);
    ok(device, &["device", "enroll", "--from", f]);
    std::fs::remove_file(&file).unwrap();
}

fn get(d: &Daemon, name: &str) -> Option<String> {
    let o = kepr(d, &["--json", "get", name]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).ok()?;
    v["value"].as_str().map(str::to_string)
}

#[test]
fn two_devices_sync_through_a_directory() {
    let (a, b) = (start(), start());
    enroll(&a, &b);
    enroll(&b, &a);
    let remote = tempfile::tempdir().unwrap();
    let url = format!("dir:{}", remote.path().display());
    for d in [&a, &b] {
        ok(d, &["sync", "remote", "add", &url]);
        assert!(ok(d, &["sync", "remote", "ls"]).contains(&url));
    }
    assert!(!kepr(&a, &["sync", "remote", "add", &url]).status.success());

    ok(&a, &["set", "SYNC_ONE", "--value", "one"]);
    ok(&b, &["set", "SYNC_TWO", "--value", "two"]);
    ok(&a, &["sync", "now"]);
    ok(&b, &["sync", "now"]);
    ok(&a, &["sync", "now"]);
    for d in [&a, &b] {
        assert_eq!(get(d, "SYNC_ONE").as_deref(), Some("one"));
        assert_eq!(get(d, "SYNC_TWO").as_deref(), Some("two"));
    }
    // The remote holds two bundles of ciphertext, one per device.
    let files: Vec<_> = std::fs::read_dir(remote.path())
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(files.len(), 2);
    for f in files {
        let text = String::from_utf8_lossy(&std::fs::read(f.path()).unwrap()).into_owned();
        assert!(!text.contains("SYNC_ONE") && !text.contains("two"));
    }

    // A delete on b reaches a.
    ok(&b, &["delete", "SYNC_TWO", "--force"]);
    ok(&b, &["sync", "now"]);
    ok(&a, &["sync", "now"]);
    assert_eq!(get(&a, "SYNC_TWO"), None);
    assert_eq!(get(&a, "SYNC_ONE").as_deref(), Some("one"));

    // A device a never enrolled drops its bundle on the remote: ignored.
    let c = start();
    ok(&c, &["share", "key"]);
    enroll(&c, &a);
    ok(&c, &["set", "SYNC_EVIL", "--value", "x"]);
    ok(&c, &["sync", "now", "--remote", &url]);
    let out = ok(&a, &["--json", "sync", "now"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["kind"], "sync_done", "{out}");
    let ignored = v["ignored"].to_string();
    assert!(ignored.contains("unknown device"), "{out}");
    assert_eq!(get(&a, "SYNC_EVIL"), None);

    ok(&a, &["sync", "remote", "rm", &url]);
    assert!(!kepr(&a, &["sync", "now"]).status.success());
}
