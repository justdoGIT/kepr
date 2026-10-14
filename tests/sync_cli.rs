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
///
/// `kepr device enroll --from` asks polkit for the human's approval
/// before it pins a key, and a test has no polkit agent to answer (on a
/// desktop it would pop up a prompt). So the last step writes into
/// `device`'s device file what the approved step pins: the new machine's
/// share key from its request. The daemon side, approval included, is
/// covered by the daemon's unit tests.
fn enroll(device: &Daemon, new: &Daemon) {
    let token = ok(device, &["device", "add", "peer"]);
    let token = token.lines().next().unwrap().trim();
    let file = new.home.path().join(format!("enroll-{}.json", token.len()));
    let _ = std::fs::remove_file(&file);
    let f = file.to_str().unwrap();
    ok(new, &["device", "enroll", token, "-o", f]);
    let req: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    pin(device, req["public"].as_str().unwrap());
    std::fs::remove_file(&file).unwrap();
}

/// Add `public` to `d`'s enrolled devices (its user-mode state file).
fn pin(d: &Daemon, public: &str) {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata(d.home.path()).unwrap().uid();
    let path = d.home.path().join(format!("state/kepr/devices-{uid}.json"));
    let mut v: serde_json::Value = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let mut list = v["devices"].as_array().cloned().unwrap_or_default();
    let id = format!("test{}", list.len());
    list.push(serde_json::json!({
        "id": id,
        "label": "peer",
        "public": public,
        "added": 0,
    }));
    v["devices"] = serde_json::Value::Array(list);
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(ok(d, &["--json", "device", "ls"]).contains(&id));
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

#[test]
fn a_folder_shared_with_a_pinned_contact() {
    let (a, b) = (start(), start());
    let key_a = ok(&a, &["share", "key"]).trim().to_string();
    let key_b = ok(&b, &["share", "key"]).trim().to_string();
    ok(&a, &["share", "contact", "add", "bob", &key_b]);
    ok(&a, &["set", "TEAM_TOKEN", "--value", "team-value"]);
    ok(&a, &["set", "SOLO_TOKEN", "--value", "solo-value"]);
    ok(&a, &["mv", "TEAM_TOKEN", "team"]);
    let file = a.home.path().join("team.bundle");
    let f = file.to_str().unwrap();
    ok(&a, &["folder", "share", "team", "--to", "bob", "-o", f]);
    let text = String::from_utf8_lossy(&std::fs::read(&file).unwrap()).into_owned();
    assert!(text.contains("TEAM_TOKEN") && !text.contains("team-value") && !text.contains("SOLO"));

    // Not pinned yet: refused. Pinned: a plan, then the import.
    let o = kepr(&b, &["folder", "import", f, "--yes"]);
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("pinned"),
        "{o:?}"
    );
    ok(&b, &["share", "contact", "add", "alice", &key_a]);
    assert!(ok(&b, &["import", f]).contains("create"));
    assert_eq!(get(&b, "TEAM_TOKEN"), None);
    ok(&b, &["folder", "import", f, "--yes"]);
    assert_eq!(get(&b, "TEAM_TOKEN").as_deref(), Some("team-value"));
    assert_eq!(get(&b, "SOLO_TOKEN"), None);
    let again = ok(&b, &["--json", "folder", "import", f, "--yes"]);
    let v: serde_json::Value = serde_json::from_str(&again).unwrap();
    assert_eq!(
        (v["from"].as_str(), v["unchanged"].as_u64()),
        (Some("alice"), Some(1)),
        "{again}"
    );
}

#[test]
fn a_key_with_approvals_is_locked_until_approved() {
    let d = start();
    ok(&d, &["share", "key"]);
    ok(&d, &["set", "QUORUM_KEY", "--value", "v"]);
    assert_eq!(get(&d, "QUORUM_KEY").as_deref(), Some("v"));
    ok(&d, &["quorum", "set", "QUORUM_KEY", "2"]);
    assert_eq!(get(&d, "QUORUM_KEY"), None);
    // A new value keeps the requirement; turning it off is a request.
    ok(&d, &["set", "QUORUM_KEY", "--value", "w"]);
    assert_eq!(get(&d, "QUORUM_KEY"), None);
    let off = ok(&d, &["--json", "quorum", "set", "QUORUM_KEY", "off"]);
    let v: serde_json::Value = serde_json::from_str(&off).unwrap();
    assert_eq!(
        (v["kind"].as_str(), v["need"].as_u64()),
        (Some("quorum_status"), Some(2)),
        "{off}"
    );
    let req = ok(&d, &["quorum", "request", "QUORUM_KEY", "--for", "30m"]);
    assert!(
        req.contains("kepr-quorum1-") && req.contains("0 of 2"),
        "{req}"
    );
    let ls = ok(&d, &["quorum", "ls"]);
    assert!(
        ls.contains("QUORUM_KEY") && ls.contains("use for 30m"),
        "{ls}"
    );
    assert_eq!(get(&d, "QUORUM_KEY"), None);
}
