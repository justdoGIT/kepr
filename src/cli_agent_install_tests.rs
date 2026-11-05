// Configuration migration, preservation and path-selection regressions.
use super::*;

#[test]
fn omp_insert_replace_idempotent() {
    let fresh = upsert_omp("", Some(7878));
    assert!(fresh.starts_with("providers:\n  kepr-anthropic:\n"));
    assert_eq!(upsert_omp(&fresh, Some(7878)), fresh);
    let user = "providers:\n  mine:\n    baseUrl: https://x\n    apiKey: MINE\n";
    let added = upsert_omp(user, Some(7878));
    assert!(added.contains("  mine:\n    baseUrl: https://x"));
    assert!(added.contains("apiKey: KEPR_PH_ANTHROPIC"));
    let moved = upsert_omp(&added, Some(9000));
    assert!(moved.contains("127.0.0.1:9000/anthropic") && !moved.contains(":7878/"));
    assert!(moved.contains("  mine:"));
    assert_eq!(moved.matches(OMP_ID).count(), 1);
}

#[test]
fn dynamic_omp_install_removes_only_its_old_fixed_port_provider() {
    let user = "providers:\n  mine:\n    baseUrl: https://example.test/v1\n    apiKey: MY_KEY\n";
    let fixed = upsert_omp(user, Some(7878));
    assert_eq!(upsert_omp(&fixed, None), user);
    let empty = upsert_omp(&upsert_omp("", Some(7878)), None);
    assert_eq!(empty, "providers: {}\n");
    assert_eq!(upsert_omp(&empty, None), empty);
}

#[test]
fn grok_insert_replace_idempotent() {
    let user = "[models]\ndefault = \"grok-4\"\n\n[model.other]\nbase_url = \"x\"\n";
    let added = upsert_grok(user, Some(7878));
    assert!(added.contains("[model.other]\nbase_url = \"x\""));
    assert!(added.contains("env_key = \"KEPR_PH_XAI\""));
    assert_eq!(upsert_grok(&added, Some(7878)), added);
    let moved = upsert_grok(&added, Some(9000));
    assert!(moved.contains(":9000/xai/v1") && !moved.contains(":7878/"));
    assert_eq!(moved.matches(GROK_HEADER).count(), 1);
    let dynamic = upsert_grok(user, None);
    assert!(dynamic.contains("env_key = \"KEPR_PH_XAI\""));
}

#[test]
fn omp_config_prefers_agent_dir_then_xdg_canonical_path() {
    let home = std::path::Path::new("/h");
    assert_eq!(
        omp_config(home, Some("/custom/pi-agent".into()), Some("/x".into())),
        PathBuf::from("/custom/pi-agent/models.yml")
    );
    assert_eq!(
        omp_config(home, None, Some("/x".into())),
        PathBuf::from("/x/omp/agent/models.yml")
    );
    assert_eq!(
        omp_config(home, None, Some("relative".into())),
        PathBuf::from("/h/.config/omp/agent/models.yml")
    );
    assert_eq!(
        omp_config(home, None, None),
        PathBuf::from("/h/.config/omp/agent/models.yml")
    );
}

#[test]
fn opencode_config_path_ignores_a_relative_xdg_dir() {
    let home = std::path::Path::new("/h");
    let want = |p: &str| PathBuf::from(p).join("opencode/opencode.json");
    assert_eq!(opencode_config(home, None), want("/h/.config"));
    assert_eq!(opencode_config(home, Some("/x".into())), want("/x"));
    assert_eq!(
        opencode_config(home, Some("rel".into())),
        want("/h/.config")
    );
    assert_eq!(opencode_config(home, Some("".into())), want("/h/.config"));
}

#[test]
fn opencode_keeps_user_keys() {
    let user = r#"{"$schema": "https://example.test/mine.json", "model": "anthropic/claude-sonnet-4-5",
          "provider": {"openai": {"options": {"baseURL": "https://proxy.example/v1"}},
                       "anthropic": {"models": {"x": {}}, "options": {"apiKey": "sk-ant-api03-old", "timeout": 5}}}}"#;
    let out = upsert_opencode(user, Some(9000)).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["$schema"], "https://example.test/mine.json");
    assert_eq!(v["model"], "anthropic/claude-sonnet-4-5");
    assert_eq!(
        v["provider"]["openai"]["options"]["baseURL"],
        "https://proxy.example/v1"
    );
    let a = &v["provider"]["anthropic"];
    assert_eq!(a["models"]["x"], serde_json::json!({}));
    assert_eq!(a["options"]["timeout"], 5);
    assert_eq!(
        a["options"]["baseURL"],
        "http://127.0.0.1:9000/anthropic/v1"
    );
    assert_eq!(a["options"]["apiKey"], "{env:KEPR_PH_ANTHROPIC}");
    assert!(!out.contains("sk-"));
    assert_eq!(upsert_opencode(&out, Some(9000)).unwrap(), out);
}

#[test]
fn opencode_refuses_a_non_object_and_leaves_the_file() {
    for bad in ["[1, 2]", "{\"provider\": 3}", "{\"a\": 1, // note\n}"] {
        assert!(upsert_opencode(bad, Some(7878)).is_err(), "{bad}");
    }
    let dir = std::env::temp_dir().join(format!("kepr-oc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("opencode.json");
    std::fs::write(&path, "[1, 2]\n").unwrap();
    assert!(install_opencode(&path, Some(7878)).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "[1, 2]\n");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no backup");
    std::fs::remove_file(&path).unwrap();
    assert!(install_opencode(&path, Some(7878)).unwrap());
    assert!(!install_opencode(&path, Some(7878)).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn apply_writes_backup_and_is_idempotent() {
    let dir = std::env::temp_dir().join(format!("kepr-install-{}", std::process::id()));
    let path = dir.join("cfg.toml");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&path, "[a]\n").unwrap();
    assert!(apply(&path, |text| upsert_grok(text, Some(7878))).unwrap());
    assert!(!apply(&path, |text| upsert_grok(text, Some(7878))).unwrap());
    let backups = std::fs::read_dir(&dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("kepr-backup")
        })
        .count();
    assert_eq!(backups, 1);
    std::fs::remove_dir_all(&dir).unwrap();
}
