use super::common::*;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
#[test]
fn protected_launch_auto_prepares_the_named_folder_and_refuses_downgrades() {
    let (_root, source, state) = fixture();
    let missing = source.join("missing");
    let out = run(
        &state,
        &[
            "agent",
            "run",
            "omp",
            "--workspace",
            missing.to_str().unwrap(),
        ],
    );
    let refusal = reply(&out);
    let error = refusal["error"].as_str().unwrap();
    assert!(error.contains("prepare"), "unexpected refusal: {error}");
    assert!(!error.contains("requires --workspace-session"));
    let prepared = prepare(&state, &source, &["main.rs"]);
    let session = prepared["session"].as_str().unwrap();
    let out = run(
        &state,
        &[
            "agent",
            "run",
            "omp",
            "--workspace-session",
            session,
            "--compatibility",
        ],
    );
    assert!(!out.status.success());
    assert!(reply(&out)["error"]
        .as_str()
        .unwrap()
        .contains("requires protected isolation"));
    let out = run(
        &state,
        &[
            "agent",
            "run",
            "omp",
            "--workspace",
            source.to_str().unwrap(),
            "--compatibility",
        ],
    );
    assert!(!out.status.success());
    assert!(reply(&out)["error"]
        .as_str()
        .unwrap()
        .contains("protected isolation"));
    let out = run(
        &state,
        &["agent", "run", "omp", "--workspace-session", "../elsewhere"],
    );
    assert!(!out.status.success());
    assert!(reply(&out)["error"]
        .as_str()
        .unwrap()
        .contains("identifier"));
}

/// A launch must run against the copy: the host tree, the vault and the
/// immutable root stay out of reach while workspace edits are kept locally.
#[test]
fn protected_launch_runs_the_copy_in_isolation() {
    let (_root, source, state) = fixture();
    let prepared = prepare(&state, &source, &["main.rs"]);
    let session = prepared["session"].as_str().unwrap();
    let workspace = Path::new(prepared["workspace"].as_str().unwrap());
    let script = "test \"$(pwd)\" = /session/private/workspace || exit 11
test -e /home && exit 12
test -e /var/lib/kepr && exit 13
printf blocked > /etc/kepr-write 2>/dev/null && exit 14
printf 'changed\\n' > main.rs";
    let out = Command::new(env!("CARGO_BIN_EXE_kepr"))
        .args([
            "agent",
            "run",
            "omp",
            "--workspace-session",
            session,
            "--json",
            "--",
            "sh",
            "-c",
            script,
        ])
        .env("XDG_STATE_HOME", &state)
        .env("XDG_CONFIG_HOME", state.join("config"))
        .env_remove("KEPR_PROFILE")
        .env_remove("KEPR_AGENT_HARNESS")
        .env_remove("KEPR_GATE_URL")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stderr.contains("isolation unavailable") || stdout.contains("isolation unavailable") {
        eprintln!("skip private launch: host refuses namespace isolation: {stderr}{stdout}");
        return;
    }
    assert!(
        out.status.success(),
        "private launch failed: stderr={stderr} stdout={stdout}"
    );
    assert_eq!(
        std::fs::read(workspace.join("main.rs")).unwrap(),
        b"changed\n"
    );
    assert_eq!(
        std::fs::read(source.join("main.rs")).unwrap(),
        b"fn main() {}\n"
    );
}

#[test]
fn a_directory_in_stdin_cannot_smuggle_host_filesystem_authority_into_a_private_launch() {
    let (_root, source, state) = fixture();
    let prepared = prepare(&state, &source, &["main.rs"]);
    let out = Command::new(env!("CARGO_BIN_EXE_kepr"))
        .args([
            "agent",
            "run",
            "omp",
            "--workspace-session",
            prepared["session"].as_str().unwrap(),
            "--json",
        ])
        .env("XDG_STATE_HOME", &state)
        .env("XDG_CONFIG_HOME", state.join("config"))
        .env_remove("KEPR_PROFILE")
        .env_remove("KEPR_AGENT_HARNESS")
        .env_remove("KEPR_GATE_URL")
        .stdin(Stdio::from(std::fs::File::open(&source).unwrap()))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        std::fs::read(source.join("main.rs")).unwrap(),
        b"fn main() {}\n"
    );
}

#[test]
fn credential_shapes_in_file_names_and_encoded_contents_never_reach_a_review() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let (_root, source, state) = fixture();
    let shape = ["sk", "-proj", "-", &"B".repeat(48)].concat();
    let name = format!("{shape}.txt");
    std::fs::write(source.join(&name), "ordinary text\n").unwrap();
    let out = run(
        &state,
        &[
            "workspace",
            "prepare",
            source.to_str().unwrap(),
            "--file",
            &name,
        ],
    );
    assert!(
        !out.status.success(),
        "a credential-shaped filename must not become metadata"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains(&shape));
    for text in [
        shape.replace('s', "\\u0073"),
        shape.replace('-', "%2d"),
        URL_SAFE_NO_PAD.encode(&shape),
        format!(
            "-----BEGIN {}-----\nsynthetic payload\n-----END {}-----\n",
            "PRIVATE KEY", "PRIVATE KEY"
        ),
    ] {
        std::fs::write(source.join("encoded.txt"), text).unwrap();
        let out = run(
            &state,
            &[
                "workspace",
                "prepare",
                source.to_str().unwrap(),
                "--file",
                "encoded.txt",
            ],
        );
        assert!(!out.status.success());
        assert!(reply(&out)["error"]
            .as_str()
            .unwrap()
            .contains("credential"));
        assert!(!String::from_utf8_lossy(&out.stdout).contains(&shape));
    }
}

#[test]
fn renewed_expired_and_cross_session_approvals_cannot_be_replayed() {
    let (root, source, state) = fixture();
    let prepared = prepare(&state, &source, &["main.rs"]);
    let id = prepared["session"].as_str().unwrap();
    let workspace = Path::new(prepared["workspace"].as_str().unwrap());
    std::fs::write(workspace.join("main.rs"), "reviewed change\n").unwrap();
    let old = review(&state, id);
    let latest = review(&state, id);
    assert_ne!(
        old["digest"], latest["digest"],
        "each review must issue fresh authority"
    );
    let output = root.path().join("export");
    let out = run(
        &state,
        &[
            "workspace",
            "export",
            id,
            "--approve",
            old["digest"].as_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert!(reply(&out)["error"].as_str().unwrap().contains("stale"));
    let other = prepare(&state, &source, &["main.rs"]);
    let other_id = other["session"].as_str().unwrap();
    review(&state, other_id);
    let out = run(
        &state,
        &[
            "workspace",
            "export",
            other_id,
            "--approve",
            latest["digest"].as_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    let approval = workspace
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("control/approval.json");
    let mut data: Value = serde_json::from_slice(&std::fs::read(&approval).unwrap()).unwrap();
    data["issued_at"] = 0.into();
    data["expires_at"] = 3600.into();
    std::fs::write(&approval, serde_json::to_vec(&data).unwrap()).unwrap();
    let out = run(
        &state,
        &[
            "workspace",
            "export",
            id,
            "--approve",
            latest["digest"].as_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert!(reply(&out)["error"].as_str().unwrap().contains("expired"));
    assert!(!output.exists());
}

#[test]
fn live_locks_unconfirmed_completion_and_tampered_baselines_block_review() {
    use std::os::fd::AsRawFd;
    let (_root, source, state) = fixture();
    let prepared = prepare(&state, &source, &["main.rs"]);
    let id = prepared["session"].as_str().unwrap();
    let workspace = Path::new(prepared["workspace"].as_str().unwrap());
    let control = workspace
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("control");
    let lock = std::fs::File::open(control.join("lock")).unwrap();
    // SAFETY: flock operates on an owned test file descriptor.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let out = run(&state, &["workspace", "review", id]);
    assert!(!out.status.success());
    assert!(reply(&out)["error"].as_str().unwrap().contains("in use"));
    drop(lock);
    let path = control.join("session.json");
    let before = std::fs::read(&path).unwrap();
    let mut manifest: Value = serde_json::from_slice(&before).unwrap();
    manifest["phase"] = "running".into();
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let out = run(&state, &["workspace", "review", id]);
    assert!(!out.status.success());
    assert!(reply(&out)["error"]
        .as_str()
        .unwrap()
        .contains("unconfirmed"));
    std::fs::write(&path, before).unwrap();
    let baseline = control.join("baseline/main.rs");
    std::fs::set_permissions(&baseline, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&baseline, "tampered baseline\n").unwrap();
    std::fs::set_permissions(&baseline, std::fs::Permissions::from_mode(0o400)).unwrap();
    let out = run(&state, &["workspace", "review", id]);
    assert!(!out.status.success());
    assert!(reply(&out)["error"]
        .as_str()
        .unwrap()
        .contains("baseline changed"));
}

#[test]
fn exported_payload_is_private_and_failed_destination_checks_do_not_consume_approval() {
    let (root, source, state) = fixture();
    let prepared = prepare(&state, &source, &["main.rs"]);
    let id = prepared["session"].as_str().unwrap();
    let workspace = Path::new(prepared["workspace"].as_str().unwrap());
    std::fs::write(workspace.join("main.rs"), "change\n").unwrap();
    let reviewed = review(&state, id);
    let digest = reviewed["digest"].as_str().unwrap();
    let existing = root.path().join("existing");
    std::fs::create_dir(&existing).unwrap();
    let out = run(
        &state,
        &[
            "workspace",
            "export",
            id,
            "--approve",
            digest,
            "--output",
            existing.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    let output = root.path().join("fresh");
    let out = run(
        &state,
        &[
            "workspace",
            "export",
            id,
            "--approve",
            digest,
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert!(out.status.success());
    assert_eq!(
        std::fs::metadata(output.join("files/main.rs"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
