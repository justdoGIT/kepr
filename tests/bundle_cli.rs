// bundle_cli.rs — T6.09 encrypted bundles end to end: two user-mode
// kepr-daemons in temporary HOMEs, driven through the real `kepr` CLI
// (`kepr export --encrypted`, `kepr import BUNDLE`). Hermetic: nothing
// outside the temp dirs is touched.

use std::io::Write;
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
    while !kepr(&d, &["status"], "").status.success() {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "daemon did not come up"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

/// Run `kepr ARGS` with `stdin` as its input (the passphrase prompts).
fn kepr(d: &Daemon, args: &[&str], stdin: &str) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr"));
    env(&mut cmd, d.home.path());
    let mut child = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run kepr");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn ok(d: &Daemon, args: &[&str], stdin: &str) -> String {
    let o = kepr(d, args, stdin);
    assert!(
        o.status.success(),
        "kepr {args:?} failed: {}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

const PASS: &str = "a long bundle passphrase\n";

#[test]
fn export_then_import_into_another_store() {
    let (a, b) = (start(), start());
    ok(&a, &["set", "API_KEY", "--value", "first-value"], "");
    ok(&a, &["set", "API_KEY", "--value", "second-value"], "");
    ok(&a, &["set", "PLAIN", "--value", "plain-value"], "");
    let file = a.home.path().join("out.bundle");
    let file = file.to_str().unwrap();

    let both = format!("{PASS}{PASS}");
    let mismatch = kepr(
        &a,
        &["export", "--encrypted", "-o", file],
        &format!("{PASS}other\n"),
    );
    assert!(!mismatch.status.success());
    let out = ok(&a, &["--json", "export", "--encrypted", "-o", file], &both);
    let ready: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(ready["kind"], "bundle_ready", "{out}");
    assert_eq!(ready["items"], 2);
    let bytes = std::fs::read(file).unwrap();
    assert!(bytes.starts_with(b"kepr_bundle1\n"));
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("second-value") && !text.contains("API_KEY"));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    // Wrong passphrase: refused, nothing stored.
    let bad = kepr(&b, &["import", file, "--yes"], "not the passphrase\n");
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("wrong passphrase"));

    // A plan first, then the import.
    let plan = ok(&b, &["import", file], PASS);
    assert!(
        plan.contains("create") && plan.contains("API_KEY"),
        "{plan}"
    );
    assert!(!kepr(&b, &["get", "API_KEY"], "").status.success());
    ok(&b, &["import", file, "--yes"], PASS);
    assert!(ok(&b, &["get", "API_KEY"], "").contains("second-value"));
    assert!(ok(&b, &["get", "PLAIN"], "").contains("plain-value"));
    let history = ok(&b, &["--json", "history", "API_KEY"], "");
    assert!(history.contains("\"version\": 1"), "{history}");

    // Importing again changes nothing.
    let again = ok(&b, &["--json", "import", file, "--yes"], PASS);
    let v: serde_json::Value = serde_json::from_str(&again).unwrap();
    assert_eq!(v["unchanged"], 2, "{again}");
}
