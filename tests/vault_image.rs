// vault_image.rs — the vault image as the daemon's store (T4.06, T4.07),
// end to end: a user-mode kepr-daemon in a temporary HOME, driven
// through the real `kepr` CLI, so every handler runs exactly as in
// production. Hermetic: nothing outside the temp dir is touched.

use std::path::{Path, PathBuf};
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

fn start(home: tempfile::TempDir, store: Option<&str>) -> Daemon {
    std::fs::create_dir_all(home.path().join("run")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr-daemon"));
    env(&mut cmd, home.path());
    if let Some(s) = store {
        cmd.env("KEPR_STORE", s);
    }
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

fn names(d: &Daemon) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(&ok(d, &["--json", "list"])).unwrap();
    v["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect()
}

fn store_dir(d: &Daemon) -> PathBuf {
    d.home.path().join("data/kepr/credentials")
}

fn cred_files(d: &Daemon) -> Vec<String> {
    std::fs::read_dir(store_dir(d))
        .map(|r| {
            r.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("kepr-"))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn set_list_get_delete_through_the_handlers_with_the_image() {
    let d = start(tempfile::tempdir().unwrap(), Some("image"));
    ok(&d, &["set", "ALPHA", "--value", "alpha-value"]);
    ok(&d, &["set", "BETA", "--value", "beta-one", "--ttl", "3600"]);
    ok(&d, &["set", "BETA", "--value", "beta-two"]);
    assert_eq!(names(&d), ["ALPHA", "BETA"]);
    assert_eq!(ok(&d, &["get", "BETA", "--quiet"]).trim(), "beta-two");
    // History slots live in the image too.
    let hist: serde_json::Value =
        serde_json::from_str(&ok(&d, &["--json", "history", "BETA"])).unwrap();
    assert_eq!(hist["versions"].as_array().map(Vec::len), Some(1), "{hist}");
    ok(&d, &["delete", "ALPHA", "--force"]);
    assert_eq!(names(&d), ["BETA"]);
    assert!(!kepr(&d, &["get", "ALPHA"]).status.success());
    // Nothing went to per-file storage; the image holds it all.
    assert!(store_dir(&d).join("vault.img").exists());
    assert!(cred_files(&d).is_empty(), "{:?}", cred_files(&d));

    // A restart reads the same image.
    let home = {
        let mut d = d;
        let _ = d.child.kill();
        let _ = d.child.wait();
        std::mem::replace(&mut d.home, tempfile::tempdir().unwrap())
    };
    let d = start(home, Some("image"));
    assert_eq!(ok(&d, &["get", "BETA", "--quiet"]).trim(), "beta-two");
}

#[test]
fn the_file_store_stays_the_default() {
    let d = start(tempfile::tempdir().unwrap(), None);
    ok(&d, &["set", "PLAIN", "--value", "v"]);
    assert_eq!(cred_files(&d), [format!("kepr-{}-plain", uid())]);
    assert!(!store_dir(&d).join("vault.img").exists());
}

fn uid() -> String {
    // SAFETY: getuid(2) has no preconditions.
    unsafe { libc::getuid() }.to_string()
}
