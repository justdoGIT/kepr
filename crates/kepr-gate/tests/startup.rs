//! Runs the real kepr-gate binary the way kepr-daemon does: config on
//! stdin, socket pair on fd 3, --owner-pid. Checks the ready line, the
//! health endpoint, and that the gate exits when its owner exits.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn starts_reports_ready_and_exits_with_owner() {
    let mut owner = Command::new("sleep").arg("30").spawn().unwrap();
    let (_daemon_end, gate_end) = UnixStream::pair().unwrap();
    let gate_fd = gate_end.as_raw_fd();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr-gate"));
    cmd.arg("--owner-pid")
        .arg(owner.id().to_string())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    // SAFETY: dup2 and fcntl are async-signal-safe; gate_fd stays open
    // in the parent until after spawn returns.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(gate_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::fcntl(3, libc::F_SETFD, 0);
            Ok(())
        });
    }
    let mut gate = cmd.spawn().unwrap();
    let cfg = serde_json::json!({
        "session_id": "0123456789abcdef",
        "session_key_hex": "11".repeat(32),
        "routes": [{"provider": "anthropic", "cred": "ANTHROPIC_API_KEY", "slot": 0}]
    });
    let mut stdin = gate.stdin.take().unwrap();
    stdin.write_all(cfg.to_string().as_bytes()).unwrap();
    drop(stdin);

    let mut line = String::new();
    BufReader::new(gate.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["ready"], true);
    let ph = ready["placeholders"]["anthropic"].as_str().unwrap();
    assert!(ph.starts_with("kepr-ph-0123456789abcdef-0000-"));
    let port = ready["port"].as_u64().unwrap();

    let mut s = TcpStream::connect(("127.0.0.1", port as u16)).unwrap();
    s.write_all(b"GET /__kepr/health HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");

    owner.kill().unwrap();
    owner.wait().unwrap();
    let start = Instant::now();
    loop {
        if gate.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "gate outlived its owner"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn refuses_without_owner_pid() {
    let out = Command::new(env!("CARGO_BIN_EXE_kepr-gate"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(70));
}
