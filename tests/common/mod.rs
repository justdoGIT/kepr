//! Private workspace lifecycle uses local copies and digest-bound export.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub(crate) fn run(state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kepr"))
        .args(args)
        .arg("--json")
        .env("XDG_STATE_HOME", state)
        .env("XDG_CONFIG_HOME", state.join("config"))
        .env_remove("KEPR_PROFILE")
        .env_remove("KEPR_AGENT_HARNESS")
        .env_remove("KEPR_GATE_URL")
        .output()
        .unwrap()
}

pub(crate) fn reply(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).expect("workspace CLI must return JSON")
}

pub(crate) fn prepare(state: &Path, source: &Path, files: &[&str]) -> Value {
    let mut args = vec!["workspace", "prepare", source.to_str().unwrap()];
    for file in files {
        args.extend(["--file", file]);
    }
    let out = run(state, &args);
    let data = reply(&out);
    assert!(
        out.status.success(),
        "workspace prepare must work locally: {}",
        data["error"]
    );
    assert_eq!(data["kind"], "workspace_prepared_ok");
    data
}

pub(crate) fn review(state: &Path, session: &str) -> Value {
    let out = run(state, &["workspace", "review", session]);
    assert!(out.status.success(), "workspace review must work locally");
    reply(&out)
}

pub(crate) fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let state = root.path().join("state");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&state).unwrap();
    std::fs::write(source.join("main.rs"), "fn main() {}\n").unwrap();
    (root, source, state)
}
