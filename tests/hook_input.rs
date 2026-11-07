use std::io::Write;
use std::process::{Command, Stdio};

fn hook(event: &str, input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kepr"))
        .args(["hook", event])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A refused request may close stdin before the sender finishes.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

#[test]
fn malformed_and_oversized_requests_never_report_success() {
    for event in ["redact", "prompt", "pre-tool"] {
        for input in [b"{".as_slice(), b"null", b"{}"] {
            let out = hook(event, input);
            assert_eq!(out.status.code(), Some(2));
            assert!(out.stdout.is_empty());
        }
    }
    let input = serde_json::to_vec(&serde_json::json!({"text": "a".repeat(10 << 20)})).unwrap();
    let out = hook("redact", &input);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

#[test]
fn empty_text_is_a_valid_successful_check() {
    let out = hook("redact", br#"{"text":""}"#);
    assert!(out.status.success());
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(reply, serde_json::json!({"text":"", "found":0}));
}
