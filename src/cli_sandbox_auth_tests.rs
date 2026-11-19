use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

fn environment(root: &Path) -> Vec<(String, String)> {
    vec![("HOME".into(), root.display().to_string())]
}

fn cache(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "synthetic-sentinel").unwrap();
}

#[test]
fn redirected_cache_masks_both_names_without_read_permission() {
    let dir = tempfile::tempdir().unwrap();
    let name = dir.path().join(".codex/auth.json");
    let target = dir.path().join("cached-auth");
    cache(&target);
    std::fs::create_dir_all(name.parent().unwrap()).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o0)).unwrap();
    symlink(&target, &name).unwrap();
    let masked = files(&environment(dir.path())).unwrap();
    assert!(masked.contains(&name));
    assert!(masked.contains(&target));
    assert!(files(&[]).unwrap().is_empty());
}

#[test]
fn unsafe_overrides_and_uninspectable_caches_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    for invalid in ["relative", "/tmp/../escape", "/tmp/nul\0path", ""] {
        assert!(files(&vec![("CODEX_HOME".into(), invalid.into())]).is_err());
    }
    let name = dir.path().join(".codex/auth.json");
    std::fs::create_dir_all(name.parent().unwrap()).unwrap();
    symlink(dir.path().join("missing"), &name).unwrap();
    assert!(files(&environment(dir.path())).is_err());
    std::fs::remove_file(&name).unwrap();
    std::fs::create_dir(&name).unwrap();
    assert!(files(&environment(dir.path())).is_err());
}

#[test]
fn dangling_parent_symlinks_and_hard_link_aliases_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join(".codex");
    symlink(dir.path().join("missing"), &root).unwrap();
    assert!(files(&environment(dir.path())).is_err());
    std::fs::remove_file(&root).unwrap();
    let name = root.join("auth.json");
    cache(&name);
    std::fs::hard_link(&name, dir.path().join("alias")).unwrap();
    assert!(files(&environment(dir.path())).is_err());
}

#[test]
fn sqlite_sidecars_cover_logical_and_canonical_database_names() {
    let dir = tempfile::tempdir().unwrap();
    let name = dir.path().join("named/auth.db");
    let target = dir.path().join("target/cache.db");
    cache(&target);
    std::fs::create_dir_all(name.parent().unwrap()).unwrap();
    symlink(&target, &name).unwrap();
    let mut expected = vec![name.clone(), target.clone()];
    for base in [&name, &target] {
        for suffix in ["-wal", "-shm", "-journal"] {
            let path = PathBuf::from(format!("{}{suffix}", base.display()));
            cache(&path);
            expected.push(path);
        }
    }
    let mut actual = Vec::new();
    paths::append(&name, true, &mut actual).unwrap();
    for path in expected {
        assert!(actual.contains(&path), "missing {path:?}");
    }
}

#[test]
fn orphaned_sqlite_sidecars_are_not_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("auth.db");
    let wal = dir.path().join("auth.db-wal");
    cache(&wal);
    let mut actual = Vec::new();
    paths::append(&db, true, &mut actual).unwrap();
    assert_eq!(actual, [wal.clone(), wal]);
}

#[test]
fn every_documented_override_is_discovered_before_harness_allowlisting() {
    let dir = tempfile::tempdir().unwrap();
    let mut env = environment(dir.path());
    let overrides = [
        ("CODEX_HOME", "auth.json"), ("CLAUDE_CONFIG_DIR", ".credentials.json"),
        ("GEMINI_CLI_HOME", ".gemini/oauth_creds.json"),
        ("PI_CODING_AGENT_DIR", "auth.json"),
        ("XDG_CONFIG_HOME", "omp/agent/auth.json"),
        ("XDG_DATA_HOME", "opencode/auth.json"),
    ];
    let mut expected = Vec::new();
    for (key, relative) in overrides {
        let base = dir.path().join(key);
        let name = base.join(relative);
        let target = dir.path().join(format!("{key}-target"));
        cache(&target);
        std::fs::create_dir_all(name.parent().unwrap()).unwrap();
        symlink(&target, &name).unwrap();
        env.push((key.into(), base.display().to_string()));
        expected.extend([name, target]);
    }
    let adc = dir.path().join("application-credential.json");
    cache(&adc);
    env.push(("GOOGLE_APPLICATION_CREDENTIALS".into(), adc.display().to_string()));
    expected.push(adc);
    let masked = files(&env).unwrap();
    for path in expected { assert!(masked.contains(&path), "missing {path:?}"); }
}

#[test]
fn selected_mixed_databases_refuse_without_blanketing_settings_or_logins() {
    let dir = tempfile::tempdir().unwrap();
    let env = environment(dir.path());
    for (owner, relative) in [
        ("omp", ".omp/agent/agent.db"),
        ("omp", ".config/omp/agent/agent.db"),
        ("opencode", ".local/share/opencode/opencode.db"),
    ] {
        let path = dir.path().join(relative);
        for suffix in ["", "-wal", "-shm"] {
            let name = PathBuf::from(format!("{}{suffix}", path.display()));
            cache(&name);
            let error = validate_selected(owner, &env).unwrap_err();
            assert!(error.contains("unsupported credential broker"));
            assert!(error.contains("private-home workspace"));
            assert!(validate_selected("claude", &env).is_ok());
            assert!(files(&env).unwrap().contains(&name));
            assert_eq!(std::fs::read(&name).unwrap(), b"synthetic-sentinel");
            std::fs::remove_file(name).unwrap();
        }
    }
}

#[test]
fn named_profiles_and_custom_database_targets_include_orphaned_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let mut env = environment(dir.path());
    env.extend([
        ("PI_CONFIG_DIR".into(), ".custom-omp".into()),
        ("OMP_PROFILE".into(), "work".into()),
        ("XDG_DATA_HOME".into(), dir.path().join("data").display().to_string()),
        ("OPENCODE_DB".into(), "custom.db".into()),
    ]);
    let expected = [
        ".custom-omp/profiles/work/agent/agent.db-wal",
        "data/omp/profiles/work/agent.db-shm",
        "data/opencode/custom.db-wal",
        ".local/share/opencode/opencode.db-shm",
    ];
    for name in expected { cache(&dir.path().join(name)); }
    let masked = files(&env).unwrap();
    for name in expected { assert!(masked.contains(&dir.path().join(name))); }
    assert!(validate_selected("omp", &env).is_err());
    assert!(validate_selected("opencode", &env).is_err());
    env.push(("PI_PROFILE".into(), "../../escape".into()));
    assert!(files(&env).is_ok(), "explicit OMP_PROFILE takes precedence");
    env.retain(|(key, _)| key != "OMP_PROFILE");
    assert!(files(&env).is_err());
}

#[test]
fn documented_default_files_are_isolated_without_masking_generic_settings() {
    let dir = tempfile::tempdir().unwrap();
    let names = [
        ".claude/.credentials.json", ".gemini/oauth_creds.json",
        ".gemini/gemini-credentials.json", ".gemini/mcp-oauth-tokens.json",
        ".gemini/a2a-oauth-tokens.json", ".pi/agent/auth.json",
        ".omp/agent/auth.json", ".config/omp/agent/auth.json",
        ".local/share/opencode/auth.json",
    ];
    for name in names { cache(&dir.path().join(name)); }
    let settings = dir.path().join(".claude/settings.json");
    cache(&settings);
    let masked = files(&environment(dir.path())).unwrap();
    for name in names { assert!(masked.contains(&dir.path().join(name))); }
    assert!(!masked.contains(&settings));
}

#[test]
fn absolute_database_and_agent_root_aliases_protect_targets_and_orphaned_wal() {
    let dir = tempfile::tempdir().unwrap();
    let omp = dir.path().join("custom-omp");
    let db = dir.path().join("custom-opencode.db");
    let target = dir.path().join("outside/credentials-wal");
    cache(&target);
    let omp_wal = omp.join("agent.db-wal");
    std::fs::create_dir_all(&omp).unwrap();
    symlink(&target, &omp_wal).unwrap();
    let code_wal = PathBuf::from(format!("{}-wal", db.display()));
    let code_target = dir.path().join("outside/opencode-wal");
    cache(&code_target);
    symlink(&code_target, &code_wal).unwrap();
    let mut env = environment(dir.path());
    env.extend([
        ("PI_CODING_AGENT_DIR".into(), omp.display().to_string()),
        ("OPENCODE_DB".into(), db.display().to_string()),
    ]);
    let masked = files(&env).unwrap();
    for name in [omp_wal, target, code_wal, code_target] {
        assert!(masked.contains(&name), "missing {name:?}");
    }
    assert!(validate_selected("omp", &env).is_err());
    assert!(validate_selected("opencode", &env).is_err());
}

#[test]
fn observed_legacy_pi_roots_include_auth_json_and_mixed_database_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join("legacy-pi");
    std::fs::create_dir_all(dir.path().join(".config")).unwrap();
    std::fs::create_dir(&legacy).unwrap();
    symlink(&legacy, dir.path().join(".config/pi")).unwrap();
    let custom = dir.path().join("custom-config");
    let names = ["auth.json", "agent/auth.json", "agent/agent.db", "agent/agent.db-wal", "agent/agent.db-shm"];
    let mut env = environment(dir.path());
    env.push(("XDG_CONFIG_HOME".into(), custom.display().to_string()));
    for name in names {
        cache(&legacy.join(name));
        cache(&custom.join("pi").join(name));
    }
    let masked = files(&env).unwrap();
    for name in names {
        assert!(masked.contains(&dir.path().join(".config/pi").join(name)));
        assert!(masked.contains(&legacy.join(name)));
        assert!(masked.contains(&custom.join("pi").join(name)));
    }
    assert!(validate_selected("omp", &env).unwrap_err().contains("unsupported credential broker"));
    assert!(validate_selected("claude", &env).is_ok());
}
