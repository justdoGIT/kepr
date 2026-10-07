// records_cli.rs — typed records end to end (T11.7, T11.8): a user-mode
// kepr-daemon in a temporary HOME driven through the real `kepr` CLI,
// with a user record type in that HOME's ~/.config/kepr/types.
// Hermetic: nothing outside the temp dir is touched.

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
    // Wait out the per-uid rate limit (burst 30, 10/s) if it bites.
    let t = Instant::now();
    loop {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr"));
        env(&mut cmd, d.home.path());
        let o = cmd
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run kepr");
        let text = |b: &[u8]| String::from_utf8_lossy(b).contains("rate limited");
        if !(text(&o.stdout) || text(&o.stderr)) || t.elapsed() > Duration::from_secs(20) {
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

fn fails(d: &Daemon, args: &[&str]) -> String {
    let o = kepr(d, args);
    assert!(!o.status.success(), "kepr {args:?} should fail");
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn json(d: &Daemon, args: &[&str]) -> serde_json::Value {
    let mut all = vec!["--json"];
    all.extend_from_slice(args);
    serde_json::from_str(&ok(d, &all)).unwrap()
}

fn record_type(d: &Daemon, name: &str) -> Option<String> {
    json(d, &["list"])["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .and_then(|c| c["record_type"].as_str().map(str::to_string))
}

const WIFI: &str = r#"name = "wifi"
fields = [
  { name = "ssid", required = true },
  { name = "password", type = "secret", required = true },
  { name = "router", type = "ref" },
]
"#;

#[test]
fn user_types_templates_required_fields_clone_and_convert() {
    let d = start();
    let types = d.home.path().join(".config/kepr/types");
    std::fs::create_dir_all(&types).unwrap();
    std::fs::write(types.join("wifi.toml"), WIFI).unwrap();

    // T11.7: the user type is listed next to the built-ins.
    let listed = ok(&d, &["record", "types"]);
    assert!(listed.contains("login") && listed.contains("ssid!, password!*, router"));

    // T11.8: required fields are enforced; the template matches the type.
    let e = fails(
        &d,
        &[
            "record",
            "add",
            "W",
            "--type",
            "wifi",
            "--field",
            "ssid=home",
        ],
    );
    assert!(e.contains("needs password"), "{e}");
    let tpl: serde_json::Value =
        serde_json::from_str(&ok(&d, &["record", "template", "wifi"])).unwrap();
    assert_eq!(tpl["type"], "wifi");
    let mut keys: Vec<&String> = tpl["fields"].as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["password", "router", "ssid"]);

    // --from-file with the filled-in template; the ref field becomes a link.
    ok(
        &d,
        &[
            "record",
            "add",
            "RTR",
            "--type",
            "server",
            "--field",
            "host=10.0.0.1",
        ],
    );
    let mut filled = tpl.clone();
    filled["fields"]["ssid"] = "home".into();
    filled["fields"]["password"] = "wpa-pass-123".into();
    filled["fields"]["router"] = "rtr".into();
    let f = d.home.path().join("w.json");
    std::fs::write(&f, filled.to_string()).unwrap();
    ok(
        &d,
        &["record", "add", "W", "--from-file", f.to_str().unwrap()],
    );
    assert_eq!(record_type(&d, "W").as_deref(), Some("wifi"));
    assert_eq!(ok(&d, &["resolve", "kepr://W/router/host"]), "10.0.0.1\n");
    let shown = ok(&d, &["record", "show", "W"]);
    assert!(
        shown.contains("ssid: home") && shown.contains("router: -> RTR"),
        "{shown}"
    );
    assert!(
        !shown.contains("wpa-pass-123"),
        "masked field shown: {shown}"
    );

    // --clone copies fields, but not attachments or history.
    ok(
        &d,
        &[
            "record",
            "add",
            "SRC",
            "--type",
            "login",
            "--field",
            "username=a",
            "--field",
            "password=p1",
        ],
    );
    ok(
        &d,
        &[
            "record",
            "add",
            "SRC",
            "--type",
            "login",
            "--field",
            "username=b",
            "--field",
            "password=p2",
        ],
    );
    let file = d.home.path().join("note.txt");
    std::fs::write(&file, "attached").unwrap();
    ok(&d, &["attach", "add", "SRC", file.to_str().unwrap()]);
    assert_eq!(
        json(&d, &["attach", "ls", "SRC"])["files"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!json(&d, &["history", "SRC"])["versions"]
        .as_array()
        .unwrap()
        .is_empty());
    ok(
        &d,
        &[
            "record",
            "add",
            "DST",
            "--clone",
            "src",
            "--field",
            "url=https://x",
        ],
    );
    assert_eq!(record_type(&d, "DST").as_deref(), Some("login"));
    assert_eq!(ok(&d, &["record", "get", "DST", "username"]), "b\n");
    assert_eq!(ok(&d, &["record", "get", "DST", "url"]), "https://x\n");
    assert!(json(&d, &["attach", "ls", "DST"])["files"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(json(&d, &["history", "DST"])["versions"]
        .as_array()
        .unwrap()
        .is_empty());

    // T11.7: convert keeps the unmatched fields as custom fields.
    ok(&d, &["record", "convert", "DST", "wifi"]);
    assert_eq!(record_type(&d, "DST").as_deref(), Some("wifi"));
    assert_eq!(
        ok(&d, &["record", "get", "DST", "custom_field/username"]),
        "b\n"
    );
    assert_eq!(ok(&d, &["record", "get", "DST", "password"]), "p2\n");
    let e = fails(&d, &["record", "convert", "DST", "nosuchtype"]);
    assert!(e.contains("unknown record type"), "{e}");
}
