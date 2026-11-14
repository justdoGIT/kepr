//! User-mode startup must not inherit a system-mode socket or store.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn explicit_user_mode_overrides_inherited_system_mode() {
    let home = tempfile::tempdir().unwrap();
    let runtime = home.path().join("run");
    std::fs::create_dir(&runtime).unwrap();
    let socket = runtime.join("kepr/kepr.sock");
    let log_path = home.path().join("daemon.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_kepr-daemon"))
            .arg("--user")
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("KEPR_SYSTEM_MODE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        if let Ok(stream) = UnixStream::connect(&socket) {
            break stream;
        }
        assert!(
            daemon.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "user daemon failed: {}",
            std::fs::read_to_string(&log_path).unwrap()
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let ping = br#"{"cmd":"ping"}"#;
    stream
        .write_all(&(ping.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(ping).unwrap();
    let mut len = [0; 4];
    stream.read_exact(&mut len).unwrap();
    let mut reply = vec![0; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut reply).unwrap();
    let response: kepr_core::protocol::Response = serde_json::from_slice(&reply).unwrap();
    assert!(matches!(response, kepr_core::protocol::Response::Pong));
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(home.path().join(".local/state/kepr/master.key").is_file());
    assert!(home.path().join(".local/share/kepr").is_dir());
}

#[test]
fn daemon_reconciles_unfinished_decision_on_startup() {
    let home = tempfile::tempdir().unwrap();
    let state_home = home.path().join("state");
    let state_dir = state_home.join("kepr");
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let records_dir = state_dir.join("agent-decisions").join(uid.to_string());
    std::fs::create_dir_all(&records_dir).unwrap();
    let decision = serde_json::json!({
        "session": "session-before-restart",
        "kind": "decision",
        "record": {
            "session": "claimed-by-gate",
            "intent_id": "intent-before-restart",
            "actor_ref": "actor-ref",
            "tenant": "tenant",
            "policy_version": "v1",
            "sensitivity": "credential-scoped",
            "destination": "api.example.test",
            "action": "write",
            "decision": "allow"
        }
    });
    std::fs::write(
        records_dir.join("records.jsonl"),
        format!("{}\n", serde_json::to_string(&decision).unwrap()),
    )
    .unwrap();

    let runtime = home.path().join("run");
    std::fs::create_dir(&runtime).unwrap();
    let socket = runtime.join("kepr/kepr.sock");
    let log_path = home.path().join("daemon.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_kepr-daemon"))
            .arg("--user")
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", &state_home)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("KEPR_SYSTEM_MODE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if UnixStream::connect(&socket).is_ok() {
            break;
        }
        assert!(
            daemon.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "user daemon failed: {}",
            std::fs::read_to_string(&log_path).unwrap()
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    let records = std::fs::read_to_string(records_dir.join("records.jsonl")).unwrap();
    let records: Vec<serde_json::Value> = records
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1]["kind"], "result");
    assert_eq!(records[1]["record"]["intent_id"], "intent-before-restart");
    assert_eq!(records[1]["record"]["outcome"], "unknown");
}
