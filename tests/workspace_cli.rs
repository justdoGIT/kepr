mod common;
use common::*;
use serde_json::Value;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
#[test]
fn prepare_without_files_captures_safe_source_tree() {
    let (_root, source, state) = fixture();
    std::fs::create_dir(source.join(".git")).unwrap();
    std::fs::write(source.join(".git/config"), "host secret\n").unwrap();
    std::fs::create_dir(source.join(".venv")).unwrap();
    std::fs::write(source.join(".venv/ignored.py"), "generated\n").unwrap();
    std::fs::create_dir(source.join("src")).unwrap();
    std::fs::write(source.join("src/lib.rs"), "pub fn ready() {}\n").unwrap();

    let prepared = prepare(&state, &source, &[]);
    let workspace = Path::new(prepared["workspace"].as_str().unwrap());
    assert!(workspace.join("main.rs").exists());
    assert!(workspace.join("src/lib.rs").exists());
    assert!(!workspace.join(".git").exists());
    assert!(!workspace.join(".venv").exists());
}

#[test]
fn prepare_without_files_skips_uninspectable_source_files() {
    let (_root, source, state) = fixture();
    std::fs::write(source.join("logo.bin"), [0_u8, 0xff, 0x00]).unwrap();

    let prepared = prepare(&state, &source, &[]);
    assert_eq!(prepared["files"], 1);
    assert_eq!(prepared["skipped"], 1);
    let workspace = Path::new(prepared["workspace"].as_str().unwrap());
    assert!(workspace.join("main.rs").exists());
    assert!(!workspace.join("logo.bin").exists());
}

#[test]
fn workspace_snapshot_review_and_export_preserve_originals() {
    use std::os::unix::fs::MetadataExt;
    let (root, source, state) = fixture();
    std::fs::write(source.join("remove.txt"), "old file\n").unwrap();
    std::fs::write(source.join("unselected.txt"), "not imported\n").unwrap();
    let prepared = prepare(&state, &source, &["main.rs", "remove.txt"]);
    let session = prepared["session"].as_str().unwrap();
    let workspace = Path::new(prepared["workspace"].as_str().unwrap());
    assert!(!workspace.join("unselected.txt").exists());
    assert_ne!(
        std::fs::metadata(source.join("main.rs")).unwrap().ino(),
        std::fs::metadata(workspace.join("main.rs")).unwrap().ino()
    );
    assert_eq!(std::fs::metadata(workspace).unwrap().mode() & 0o777, 0o700);
    std::fs::write(
        workspace.join("main.rs"),
        "fn main() { println!(\"ready\"); }\n",
    )
    .unwrap();
    std::fs::remove_file(workspace.join("remove.txt")).unwrap();
    std::fs::write(workspace.join("added.txt"), "new file\n").unwrap();
    std::fs::set_permissions(
        workspace.join("added.txt"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let reviewed = review(&state, session);
    let changes = reviewed["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 3);
    assert_eq!(changes[0]["path"], "added.txt");
    assert_eq!(changes[0]["action"], "added");
    assert_eq!(changes[1]["action"], "modified");
    assert_eq!(changes[2]["action"], "deleted");
    let patch = std::fs::read_to_string(reviewed["patch_file"].as_str().unwrap()).unwrap();
    assert!(patch.contains("-fn main() {}"));
    assert!(patch.contains("+fn main() { println!(\"ready\"); }"));
    let output = root.path().join("export");
    let digest = reviewed["digest"].as_str().unwrap();
    let out = run(
        &state,
        &[
            "workspace",
            "export",
            session,
            "--approve",
            digest,
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "reviewed export must succeed");
    assert_eq!(reply(&out)["digest"], digest);
    assert_eq!(
        std::fs::read(output.join("files/main.rs")).unwrap(),
        std::fs::read(workspace.join("main.rs")).unwrap()
    );
    assert!(output.join("files/added.txt").exists());
    assert!(!output.join("files/remove.txt").exists());
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(output.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["digest"], digest);
    assert_eq!(manifest["changes"], reviewed["changes"]);
    assert_eq!(
        std::fs::read(source.join("main.rs")).unwrap(),
        b"fn main() {}\n"
    );
    assert_eq!(
        std::fs::read(source.join("remove.txt")).unwrap(),
        b"old file\n"
    );
    let replay = run(
        &state,
        &[
            "workspace",
            "export",
            session,
            "--approve",
            digest,
            "--output",
            root.path().join("replay").to_str().unwrap(),
        ],
    );
    assert!(!replay.status.success());
    assert!(reply(&replay)["error"]
        .as_str()
        .unwrap()
        .contains("consumed"));
    assert!(!root.path().join("replay").exists());
}

#[test]
fn export_refuses_content_or_mode_changes_after_review_and_existing_destinations() {
    let (root, source, state) = fixture();
    let prepared = prepare(&state, &source, &["main.rs"]);
    let session = prepared["session"].as_str().unwrap();
    let workspace = Path::new(prepared["workspace"].as_str().unwrap());
    std::fs::write(workspace.join("main.rs"), "first review\n").unwrap();
    let reviewed = review(&state, session);
    let output = root.path().join("export");
    let args = [
        "workspace",
        "export",
        session,
        "--approve",
        reviewed["digest"].as_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ];
    std::fs::write(workspace.join("main.rs"), "changed after review\n").unwrap();
    let out = run(&state, &args);
    assert!(!out.status.success());
    assert!(reply(&out)["error"].as_str().unwrap().contains("stale"));
    assert!(!output.exists());
    let reviewed = review(&state, session);
    std::fs::set_permissions(
        workspace.join("main.rs"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let out = run(
        &state,
        &[
            "workspace",
            "export",
            session,
            "--approve",
            reviewed["digest"].as_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert!(reply(&out)["error"].as_str().unwrap().contains("stale"));
    let reviewed = review(&state, session);
    std::fs::create_dir(&output).unwrap();
    std::fs::write(output.join("keep"), "operator data").unwrap();
    let out = run(
        &state,
        &[
            "workspace",
            "export",
            session,
            "--approve",
            reviewed["digest"].as_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    assert_eq!(
        std::fs::read(output.join("keep")).unwrap(),
        b"operator data"
    );
}

#[test]
fn snapshot_rejects_links_credentials_traversal_and_unbounded_inputs() {
    let (root, source, state) = fixture();
    let outside = root.path().join("outside");
    std::fs::write(&outside, "outside data\n").unwrap();
    symlink(&outside, source.join("linked.txt")).unwrap();
    std::fs::hard_link(&outside, source.join("hard.txt")).unwrap();
    std::fs::create_dir(source.join(".git")).unwrap();
    std::fs::create_dir(source.join(".ssh")).unwrap();
    let mut credential_shape = String::from("sk");
    credential_shape.push_str("-proj");
    credential_shape.push('-');
    credential_shape.push_str(&"A".repeat(48));
    std::fs::write(
        source.join("example.rs"),
        format!("let value = \"{credential_shape}\";\n"),
    )
    .unwrap();
    for file in [
        "linked.txt",
        "hard.txt",
        "../outside",
        ".env",
        ".git/config",
        ".ssh/id_ed25519",
        "example.rs",
    ] {
        let out = run(
            &state,
            &[
                "workspace",
                "prepare",
                source.to_str().unwrap(),
                "--file",
                file,
            ],
        );
        assert!(!out.status.success(), "excluded input accepted: {file}");
        let data = reply(&out);
        assert_eq!(data["kind"], "err");
        assert!(data["error"].as_str().unwrap().contains("workspace"));
        assert!(!String::from_utf8_lossy(&out.stdout).contains(&credential_shape));
    }
    let out = run(&state, &["workspace", "prepare", source.to_str().unwrap()]);
    assert!(!out.status.success());
    let data = reply(&out);
    let error = data["error"].as_str().unwrap();
    assert!(error.contains("workspace"));
    assert!(!error.contains("--file"));
    std::fs::write(source.join("large.txt"), vec![b'x'; 1_048_577]).unwrap();
    let out = run(
        &state,
        &[
            "workspace",
            "prepare",
            source.to_str().unwrap(),
            "--file",
            "large.txt",
        ],
    );
    assert!(!out.status.success());
    assert!(reply(&out)["error"].as_str().unwrap().contains("limit"));
    let sessions = state.join("kepr/workspaces");
    assert!(!sessions.exists() || std::fs::read_dir(sessions).unwrap().next().is_none());
}

#[test]
fn review_refuses_link_escapes_and_new_credential_files_without_echoing_contents() {
    let (root, source, state) = fixture();
    let prepared = prepare(&state, &source, &["main.rs"]);
    let session = prepared["session"].as_str().unwrap();
    let workspace = Path::new(prepared["workspace"].as_str().unwrap());
    let outside = root.path().join("outside");
    std::fs::write(&outside, "not imported\n").unwrap();
    symlink(&outside, workspace.join("escape.txt")).unwrap();
    let out = run(&state, &["workspace", "review", session]);
    assert!(!out.status.success());
    assert!(reply(&out)["error"].as_str().unwrap().contains("workspace"));
    std::fs::remove_file(workspace.join("escape.txt")).unwrap();
    std::fs::write(workspace.join(".env"), "PRIVATE=not imported\n").unwrap();
    let out = run(&state, &["workspace", "review", session]);
    assert!(!out.status.success());
    assert!(reply(&out)["error"].as_str().unwrap().contains("workspace"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("not imported"));
}

#[test]
fn session_ids_and_symlinked_state_roots_are_not_authority() {
    let (root, source, state) = fixture();
    for session in ["..", "/tmp/session", "0/../0"] {
        let out = run(&state, &["workspace", "review", session]);
        assert!(!out.status.success());
        assert!(reply(&out)["error"].as_str().unwrap().contains("session"));
    }
    std::fs::create_dir(state.join("kepr")).unwrap();
    symlink(&source, state.join("kepr/workspaces")).unwrap();
    let out = run(
        &state,
        &[
            "workspace",
            "prepare",
            source.to_str().unwrap(),
            "--file",
            "main.rs",
        ],
    );
    assert!(!out.status.success());
    assert!(reply(&out)["error"].as_str().unwrap().contains("workspace"));
    assert_eq!(
        std::fs::read(source.join("main.rs")).unwrap(),
        b"fn main() {}\n"
    );
    assert_eq!(std::fs::read_dir(&source).unwrap().count(), 1);
    assert!(root.path().exists());
}

#[test]
fn credential_directory_roots_are_excluded_before_selected_files_are_read() {
    let (_root, source, state) = fixture();
    let credential_root = source.join(".ssh");
    std::fs::create_dir(&credential_root).unwrap();
    std::fs::write(credential_root.join("example.txt"), "ordinary text\n").unwrap();
    let out = run(
        &state,
        &[
            "workspace",
            "prepare",
            credential_root.to_str().unwrap(),
            "--file",
            "example.txt",
        ],
    );
    assert!(
        !out.status.success(),
        "credential directory must never be imported"
    );
    assert!(reply(&out)["error"].as_str().unwrap().contains("excluded"));
    assert!(!state.join("kepr/workspaces").exists());
}

mod workspace_launch_cases;
