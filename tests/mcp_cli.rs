//! MCP grants must reach the server without corrupting its JSON-RPC stream.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn scoped_mcp_session_keeps_stdout_json_rpc_only() {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kepr"))
        .args([
            "--json",
            "mcp",
            "--credential",
            "TEST_API_KEY",
            "--read-only",
            "--max-requests",
            "1",
        ])
        .env_clear()
        .env("HOME", home.path())
        .env("XDG_RUNTIME_DIR", home.path().join("run"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            concat!(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}\n",
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
            )
            .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let replies: Vec<serde_json::Value> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 2, "unexpected MCP stdout: {replies:?}");
    assert_eq!(replies[0]["jsonrpc"], "2.0");
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(
        replies[0]["result"]["capabilities"]["tools"],
        serde_json::json!({})
    );
    assert_eq!(
        replies[1],
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "result": {}})
    );
}
