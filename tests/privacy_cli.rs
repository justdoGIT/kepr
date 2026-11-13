//! Operator privacy configuration and preview never need a daemon or provider.

use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(root: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kepr"))
        .args(args)
        .arg("--json")
        .env("XDG_CONFIG_HOME", root)
        .env_remove("KEPR_PROFILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn reply(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).expect("CLI must return a JSON response")
}

fn seed(root: &Path, policy: Value) {
    let dir = root.join("kepr");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("privacy.json");
    std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn privacy_initialization_is_private_and_does_not_overwrite_operator_settings() {
    let root = tempfile::tempdir().unwrap();
    let out = run(root.path(), &["privacy", "init"], "");
    assert!(
        out.status.success(),
        "privacy initialization must work without a daemon"
    );
    let path = root.path().join("kepr/privacy.json");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let before = std::fs::read(&path).unwrap();
    let out = run(
        root.path(),
        &["privacy", "init", "--preset", "local-only"],
        "",
    );
    assert!(!out.status.success());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let out = run(root.path(), &["privacy", "status"], "");
    let data = reply(&out);
    assert!(out.status.success());
    assert_eq!(data["configured"], true);
    assert_eq!(data["preset"], "private-cloud");
    assert_eq!(data["device_enforcement_available"], false);
    assert_eq!(data["local_inference_available"], false);
}

#[test]
fn preview_masks_personal_data_and_counts_repeated_occurrences_without_echoing_originals() {
    let root = tempfile::tempdir().unwrap();
    seed(
        root.path(),
        json!({"version":1,"preset":"private-cloud","identifiers":["Acme Lichen"]}),
    );
    let out = run(
        root.path(),
        &["privacy", "preview"],
        "Acme Lichen: alice@example.invalid, alice@example.invalid",
    );
    assert!(
        out.status.success(),
        "preview must work locally without a daemon"
    );
    let data = reply(&out);
    let text = data["text"].as_str().unwrap();
    assert!(!text.contains("alice@example.invalid"));
    assert!(!text.contains("Acme Lichen"));
    assert_eq!(data["redactions"], 3);
    assert_eq!(data["counts"]["email"], 2);
    assert_eq!(data["counts"]["identifier"], 1);
    let emails: Vec<_> = text
        .split_whitespace()
        .filter(|s| s.starts_with("kepr-private-email-"))
        .collect();
    assert_eq!(emails.len(), 2);
    assert_eq!(emails[0].trim_end_matches(','), emails[1]);
    assert!(out.stderr.is_empty());
}

#[test]
fn configuration_from_stdin_validates_before_replacing_the_policy() {
    let root = tempfile::tempdir().unwrap();
    let policy = json!({"version":1,"preset":"local-only","identifiers":["Acme Lichen"]});
    let out = run(
        root.path(),
        &["privacy", "configure", "--stdin"],
        &policy.to_string(),
    );
    assert!(out.status.success());
    let path = root.path().join("kepr/privacy.json");
    let before = std::fs::read(&path).unwrap();
    let out = run(
        root.path(),
        &["privacy", "configure", "--stdin"],
        "{\"version\":99,\"preset\":\"private-cloud\",\"identifiers\":[\"alice@example.invalid\"]}",
    );
    assert!(!out.status.success());
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("alice@example.invalid"));
}

#[test]
fn malformed_insecure_and_symlinked_policy_files_are_refused_without_defaulting() {
    let root = tempfile::tempdir().unwrap();
    seed(
        root.path(),
        json!({"version":99,"preset":"private-cloud","identifiers":["alice@example.invalid"]}),
    );
    let out = run(root.path(), &["privacy", "preview"], "hello");
    assert!(!out.status.success());
    assert_eq!(reply(&out)["error"], "unsupported privacy policy version");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("alice@example.invalid"));
    seed(root.path(), json!({"version":1,"preset":"private-cloud"}));
    let path = root.path().join("kepr/privacy.json");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = run(root.path(), &["privacy", "preview"], "hello");
    assert!(!out.status.success());
    assert!(reply(&out)["error"]
        .as_str()
        .unwrap()
        .contains("privacy policy file"));
    std::fs::remove_file(&path).unwrap();
    let target = root.path().join("other.json");
    std::fs::write(&target, "{\"version\":1,\"preset\":\"private-cloud\"}").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(target, path).unwrap();
    let out = run(root.path(), &["privacy", "preview"], "hello");
    assert!(!out.status.success());
    assert!(reply(&out)["error"]
        .as_str()
        .unwrap()
        .contains("privacy policy file"));
}

#[test]
fn preview_refuses_encoded_private_data_without_echoing_input() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let root = tempfile::tempdir().unwrap();
    seed(root.path(), json!({"version":1,"preset":"private-cloud"}));
    for input in [
        STANDARD.encode("alice@example.invalid"),
        "alice%40example.invalid".into(),
        "alice\\u0040example.invalid".into(),
    ] {
        let out = run(root.path(), &["privacy", "preview"], &input);
        assert!(!out.status.success());
        assert_eq!(
            reply(&out)["error"],
            "encoded private data requires local processing"
        );
        for output in [&out.stdout, &out.stderr] {
            let output = String::from_utf8_lossy(output);
            assert!(!output.contains("alice@example.invalid"));
            assert!(!output.contains(&input));
        }
    }
}
