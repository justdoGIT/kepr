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
    // These tests fire requests faster than the daemon's per-uid rate limit
    // (burst 30, 10/s) allows; wait for the bucket to refill and retry.
    let t = Instant::now();
    loop {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr"));
        env(&mut cmd, d.home.path());
        let o = cmd
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run kepr");
        let limited = String::from_utf8_lossy(&o.stdout).contains("rate limited")
            || String::from_utf8_lossy(&o.stderr).contains("rate limited");
        if !limited || t.elapsed() > Duration::from_secs(20) {
            return o;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
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

fn restart(d: Daemon, store: Option<&str>) -> Daemon {
    let mut d = d;
    let _ = d.child.kill();
    let _ = d.child.wait();
    let home = std::mem::replace(&mut d.home, tempfile::tempdir().unwrap());
    start(home, store)
}

fn json(d: &Daemon, args: &[&str]) -> serde_json::Value {
    let all: Vec<&str> = std::iter::once("--json")
        .chain(args.iter().copied())
        .collect();
    serde_json::from_str(&ok(d, &all)).unwrap()
}

/// `kepr agent add NAME --stdin`: a sealed key bound to its provider.
fn add_sealed(d: &Daemon, name: &str, value: &str) {
    use std::io::Write;
    let mut add = Command::new(env!("CARGO_BIN_EXE_kepr"));
    env(&mut add, d.home.path());
    let mut child = add
        .args(["agent", "add", name, "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{value}").unwrap();
    assert!(child.wait().unwrap().success(), "agent add");
}

fn fails_with(d: &Daemon, args: &[&str]) -> String {
    let o = kepr(d, args);
    assert!(!o.status.success(), "kepr {args:?} succeeded");
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn migrate_moves_the_file_store_into_the_image() {
    let d = start(tempfile::tempdir().unwrap(), None);
    ok(&d, &["set", "PLAIN", "--value", "plain-value"]);
    ok(&d, &["set", "ROTATED", "--value", "first"]);
    ok(
        &d,
        &["set", "ROTATED", "--value", "second", "--ttl", "3600"],
    );
    let sealed = "sk-ant-api03-VAULTMIGRATE0123456789SECRET";
    add_sealed(&d, "ANTHROPIC_API_KEY", sealed);
    ok(&d, &["ssh", "generate", "DEPLOY_KEY"]);
    let ssh_keys = json(&d, &["ssh", "list"])["keys"].clone();
    assert_eq!(ssh_keys.as_array().map(Vec::len), Some(1), "{ssh_keys}");

    let st = json(&d, &["vault", "status"]);
    assert_eq!(
        (&st["backend"], &st["image"]),
        (&"file".into(), &false.into())
    );
    // PLAIN, ROTATED, its history slot, the sealed key, the SSH key.
    assert_eq!(st["legacy_files"], 5, "{st}");
    assert!(fails_with(&d, &["vault", "migrate"]).contains("KEPR_STORE=image"));

    let d = restart(d, Some("image"));
    assert!(names(&d).is_empty(), "the image starts empty");
    let m = json(&d, &["vault", "migrate"]);
    assert_eq!(
        (&m["migrated"], &m["skipped"]),
        (&5.into(), &0.into()),
        "{m}"
    );
    assert_eq!(
        names(&d),
        ["ANTHROPIC_API_KEY", "DEPLOY_KEY", "PLAIN", "ROTATED"]
    );
    // The SSH key is still sign-only, with the same public key.
    assert_eq!(json(&d, &["ssh", "list"])["keys"], ssh_keys);
    assert!(!kepr(&d, &["get", "DEPLOY_KEY", "--quiet"]).status.success());
    assert_eq!(ok(&d, &["get", "PLAIN", "--quiet"]).trim(), "plain-value");
    assert_eq!(ok(&d, &["get", "ROTATED", "--quiet"]).trim(), "second");
    // The meta moved with the value: the TTL and the seal still hold.
    let list = json(&d, &["list"]);
    let cred = |n: &str| {
        list["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == n)
            .unwrap()
            .clone()
    };
    assert!(cred("ROTATED")["expires_at"].is_string(), "{list}");
    assert_eq!(cred("ANTHROPIC_API_KEY")["sealed"], true, "{list}");
    let o = kepr(&d, &["get", "ANTHROPIC_API_KEY", "--quiet"]);
    assert!(!o.status.success());
    assert!(!String::from_utf8_lossy(&o.stdout).contains(sealed));
    assert!(!String::from_utf8_lossy(&o.stderr).contains(sealed));
    let hist = json(&d, &["history", "ROTATED"]);
    assert_eq!(hist["versions"].as_array().map(Vec::len), Some(1), "{hist}");
    assert!(cred_files(&d).is_empty(), "{:?}", cred_files(&d));

    let v = json(&d, &["vault", "verify"]);
    assert_eq!(v["records"], 5, "{v}");
    let st = json(&d, &["vault", "status"]);
    assert_eq!(
        (&st["backend"], &st["image"]),
        (&"image".into(), &true.into())
    );
    assert_eq!(
        (&st["legacy_files"], &st["size_mib"]),
        (&0.into(), &16.into())
    );
    assert!(st["used_slots"].as_u64().unwrap() >= 6, "{st}");
    let again = json(&d, &["vault", "migrate"]);
    assert_eq!(again["migrated"], 0, "{again}");
}

#[test]
fn verify_names_each_damaged_slot_and_only_used_ones() {
    let d = start(tempfile::tempdir().unwrap(), Some("image"));
    ok(&d, &["vault", "init", "--size", "1"]);
    assert!(fails_with(&d, &["vault", "init"]).contains("already exists"));
    ok(&d, &["set", "ONE", "--value", "one"]);
    let path = store_dir(&d).join("vault.img");
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 1 << 20);
    let before = std::fs::read(&path).unwrap();
    ok(&d, &["set", "TWO", "--value", "two"]);
    let after = std::fs::read(&path).unwrap();
    ok(&d, &["vault", "verify"]);

    // The write changed TWO's page, a new index page, decoys and the
    // freed old index page. Damage in exactly two of them is caught.
    let changed: Vec<usize> = (2..after.len() / 4096)
        .filter(|s| before[s * 4096..(s + 1) * 4096] != after[s * 4096..(s + 1) * 4096])
        .collect();
    assert!(changed.len() >= 5, "decoys are written too: {changed:?}");
    let flip = |s: usize| {
        use std::os::unix::fs::FileExt;
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let at = s * 4096 + 2048;
        f.write_at(&[after[at] ^ 0x01], at as u64).unwrap();
    };
    let restore = || std::fs::write(&path, &after).unwrap();
    let mut caught = Vec::new();
    for &s in &changed {
        flip(s);
        let o = kepr(&d, &["vault", "verify"]);
        restore();
        if !o.status.success() {
            let err = String::from_utf8_lossy(&o.stderr).into_owned();
            assert!(err.contains(&format!("slot {s} ")), "slot {s}: {err}");
            caught.push(s);
        }
    }
    assert_eq!(caught.len(), 2, "changed {changed:?}, caught {caught:?}");
    ok(&d, &["vault", "verify"]);

    // Reads fail closed, without saying why: damage in TWO's page
    // breaks TWO only; damage in the index page breaks both.
    let mut two_only = 0;
    for &s in &caught {
        flip(s);
        // (verify re-reads the image; reads otherwise use the index
        // the daemon last loaded)
        fails_with(&d, &["vault", "verify"]);
        let two = kepr(&d, &["get", "TWO", "--quiet"]);
        let one = kepr(&d, &["get", "ONE", "--quiet"]);
        restore();
        assert!(!two.status.success());
        let err = String::from_utf8_lossy(&two.stderr).into_owned();
        assert!(err.contains("credential unavailable"), "{err}");
        two_only += usize::from(one.status.success());
    }
    assert_eq!(two_only, 1);
    assert_eq!(ok(&d, &["get", "TWO", "--quiet"]).trim(), "two");
}

/// T4.14: the store batch's features with the image as the store.
#[test]
fn trash_aliases_verify_and_delete_all_work_on_the_image() {
    let d = start(tempfile::tempdir().unwrap(), Some("image"));
    ok(&d, &["set", "KEEP", "--value", "one"]);
    ok(&d, &["set", "KEEP", "--value", "two"]);
    ok(&d, &["tag", "KEEP", "+prod"]);
    let sealed = "sk-ant-api03-VAULTTRASH0123456789SECRET";
    add_sealed(&d, "ANTHROPIC_API_KEY", sealed);
    let entry = |list: &serde_json::Value, n: &str| {
        list["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == n)
            .cloned()
            .unwrap_or_default()
    };

    // rm → the trash (history, tags and seal with it) → restore.
    json(&d, &["rm", "KEEP"]);
    json(&d, &["rm", "ANTHROPIC_API_KEY"]);
    assert!(names(&d).is_empty());
    assert!(!kepr(&d, &["get", "KEEP", "--quiet"]).status.success());
    let trash = json(&d, &["trash"]);
    let mut trashed: Vec<&str> = trash["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    trashed.sort_unstable();
    assert_eq!(trashed, ["ANTHROPIC_API_KEY", "KEEP"], "{trash}");
    ok(&d, &["trash", "restore", "KEEP"]);
    ok(&d, &["trash", "restore", "ANTHROPIC_API_KEY"]);
    assert_eq!(json(&d, &["trash"])["items"], serde_json::json!([]));
    assert_eq!(ok(&d, &["get", "KEEP", "--quiet"]).trim(), "two");
    let hist = json(&d, &["history", "KEEP"]);
    assert_eq!(hist["versions"].as_array().map(Vec::len), Some(1), "{hist}");
    let list = json(&d, &["list"]);
    assert_eq!(entry(&list, "KEEP")["tags"], serde_json::json!(["prod"]));
    assert_eq!(entry(&list, "ANTHROPIC_API_KEY")["sealed"], true, "{list}");
    let o = kepr(&d, &["get", "ANTHROPIC_API_KEY", "--quiet"]);
    assert!(!o.status.success());
    assert!(!String::from_utf8_lossy(&o.stdout).contains(sealed));

    // An alias is a meta-only record: listed, resolved, removed alone.
    ok(&d, &["ln", "SHORT", "KEEP"]);
    assert_eq!(ok(&d, &["get", "SHORT", "--quiet"]).trim(), "two");
    let list = json(&d, &["list"]);
    assert_eq!(entry(&list, "SHORT")["alias_of"], "KEEP", "{list}");
    ok(&d, &["ln", "GONE", "KEEP"]);
    json(&d, &["rm", "GONE"]);
    assert_eq!(ok(&d, &["get", "KEEP", "--quiet"]).trim(), "two");
    assert!(!kepr(&d, &["get", "GONE", "--quiet"]).status.success());

    // Folders, history diff and the duplicate finder read the image too.
    ok(&d, &["mv", "KEEP", "team/app"]);
    assert_eq!(entry(&json(&d, &["list"]), "KEEP")["folder"], "team/app");
    let diff = json(&d, &["history", "KEEP", "--diff", "1", "0"]);
    let changed = serde_json::json!([{"field": "value", "change": "changed"}]);
    assert_eq!(diff["changes"], changed, "{diff}");
    ok(&d, &["set", "COPY", "--value", "two"]);
    let dupes = json(&d, &["dupes"]);
    assert_eq!(
        dupes["groups"],
        serde_json::json!([["COPY", "KEEP"]]),
        "{dupes}"
    );
    ok(&d, &["dupes", "--merge", "KEEP"]);
    assert_eq!(entry(&json(&d, &["list"]), "COPY")["alias_of"], "KEEP");
    assert_eq!(ok(&d, &["get", "COPY", "--quiet"]).trim(), "two");

    // doctor --verify checks what the image holds.
    let v = json(&d, &["doctor", "--verify"]);
    assert_eq!(v["all_ok"], true, "{v}");
    assert_eq!(v["results"]["SHORT"], "ok", "{v}");
    assert_eq!(v["results"]["COPY"], "ok", "{v}");
    assert_eq!(v["results"]["KEEP~0"], "ok", "{v}");
    assert_eq!(v["count"], 6, "{v}"); // KEEP, KEEP~0, the key, 2 aliases, COPY's trash entry

    // delete --all takes values, history, trash and aliases.
    ok(&d, &["set", "BIN", "--value", "b"]);
    json(&d, &["rm", "BIN"]);
    ok(&d, &["delete", "--all", "--yes"]);
    assert!(names(&d).is_empty());
    assert_eq!(json(&d, &["trash"])["items"], serde_json::json!([]));
    assert!(!kepr(&d, &["get", "SHORT", "--quiet"]).status.success());
    assert_eq!(json(&d, &["vault", "verify"])["records"], 0);
    // Nothing ever went to per-file storage.
    assert!(cred_files(&d).is_empty(), "{:?}", cred_files(&d));
}

/// T4.14: attachments (T5.03) are chunk records in the image; they go
/// to the trash and back with their credential, are checked by doctor
/// --verify and removed by delete --all.
#[test]
fn attachments_follow_their_credential_on_the_image() {
    let d = start(tempfile::tempdir().unwrap(), Some("image"));
    ok(&d, &["set", "DOC", "--value", "v"]);
    let src = d.home.path().join("notes.bin");
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &data).unwrap(); // three 45 KiB chunks
    ok(&d, &["attach", "add", "DOC", src.to_str().unwrap()]);
    let records = |d: &Daemon| json(d, &["vault", "verify"])["records"].clone();
    assert_eq!(records(&d), 4, "DOC and three chunks");

    json(&d, &["rm", "DOC"]);
    assert!(!kepr(&d, &["attach", "ls", "DOC"]).status.success());
    assert_eq!(records(&d), 4, "the chunks went to the trash with DOC");
    ok(&d, &["trash", "restore", "DOC"]);
    let ls = json(&d, &["attach", "ls", "DOC"]);
    assert_eq!(ls["files"][0]["file"], "notes.bin", "{ls}");
    let out = d.home.path().join("out.bin");
    let out_s = out.to_str().unwrap();
    ok(&d, &["attach", "get", "DOC", "notes.bin", "-o", out_s]);
    assert_eq!(std::fs::read(&out).unwrap(), data);

    let v = json(&d, &["doctor", "--verify"]);
    assert_eq!(v["all_ok"], true, "{v}");
    assert_eq!(v["count"], 4, "{v}");
    assert_eq!(v["results"]["DOC~a0~2"], "ok", "{v}");

    ok(&d, &["delete", "--all", "--yes"]);
    assert_eq!(records(&d), 0);
    assert!(cred_files(&d).is_empty(), "{:?}", cred_files(&d));
}

fn uid() -> String {
    // SAFETY: getuid(2) has no preconditions.
    unsafe { libc::getuid() }.to_string()
}
