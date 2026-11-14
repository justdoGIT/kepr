// Protected-launch credential isolation and sandbox regressions.
use std::collections::HashMap;

#[test]
fn codex_cannot_fall_back_to_an_unprotected_process() {
    use super::*;
    assert_eq!(
        harness_sandbox("codex", SandboxMode::Auto),
        Ok(SandboxMode::Required)
    );
    assert!(harness_sandbox("codex", SandboxMode::Off).is_err());
    assert_eq!(
        harness_sandbox("claude", SandboxMode::Off),
        Ok(SandboxMode::Off)
    );
}

#[test]
fn real_keys_in_the_environment_are_withheld() {
    let vars = vec![
        ("PATH".to_string(), "/usr/bin".to_string()),
        (
            "OPENAI_API_KEY".to_string(),
            "sk-proj-abcdefghijklmnopqrstuvwx".to_string(),
        ),
        (
            "GH".to_string(),
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789".to_string(),
        ),
    ];
    let (keep, withheld) = keep_safe_env(vars.into_iter());
    assert_eq!(keep, vec![("PATH".to_string(), "/usr/bin".to_string())]);
    assert_eq!(
        withheld,
        vec!["GH".to_string(), "OPENAI_API_KEY".to_string()]
    );
}
use super::*;

fn claude() -> &'static Adapter {
    cli_agent_adapters::lookup("claude").unwrap()
}

#[test]
fn real_key_in_shell_is_replaced_by_placeholder() {
    let mut ph = HashMap::new();
    ph.insert("anthropic".to_string(), "kepr-ph-x".to_string());
    let inherited = vec![
        ("ANTHROPIC_API_KEY".to_string(), "sk-ant-real".to_string()),
        (
            "ANTHROPIC_BASE_URL".to_string(),
            "https://evil.example".to_string(),
        ),
        ("PATH".to_string(), "/usr/bin".to_string()),
    ];
    let env = build_env(claude(), 7000, &ph, inherited.into_iter());
    let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("ANTHROPIC_API_KEY"), Some("kepr-ph-x"));
    assert_eq!(
        get("ANTHROPIC_BASE_URL"),
        Some("http://127.0.0.1:7000/anthropic")
    );
    assert_eq!(get("PATH"), Some("/usr/bin"));
    assert!(!env.iter().any(|(_, v)| v == "sk-ant-real"));
    assert_eq!(
        env.iter().filter(|(k, _)| k == "ANTHROPIC_API_KEY").count(),
        1
    );
}

#[test]
fn missing_credential_drops_its_variables() {
    let env = build_env(claude(), 7000, &HashMap::new(), std::iter::empty());
    assert!(env.is_empty());
}

#[test]
fn inherited_environment_is_allowlisted_before_harness_contracts_are_added() {
    let inherited = [
        ("PATH", "/usr/bin"),
        ("HOME", "/home/operator"),
        ("LANG", "C.UTF-8"),
        ("TERM", "xterm-256color"),
        ("CUSTOM_PASSWORD", "synthetic-sensitive-value"),
        ("GITHUB_TOKEN", "synthetic-sensitive-value"),
        ("AWS_SECRET_ACCESS_KEY", "synthetic-sensitive-value"),
        ("LD_PRELOAD", "/tmp/injected.so"),
        ("NODE_OPTIONS", "--require=/tmp/injected.js"),
        ("PYTHONPATH", "/tmp/injected"),
        ("HTTPS_PROXY", "http://proxy.example"),
        ("EMAIL", "operator@example.test"),
        ("GIT_AUTHOR_EMAIL", "operator@example.test"),
        ("DBUS_SESSION_BUS_ADDRESS", "unix:abstract=/tmp/session-bus"),
    ]
    .map(|(k, v)| (k.to_string(), v.to_string()));
    let env = build_env(claude(), 7000, &HashMap::new(), inherited.into_iter());
    assert_eq!(env.len(), 4);
    assert!(env
        .iter()
        .all(|(k, _)| ["PATH", "HOME", "LANG", "TERM"].contains(&k.as_str())));
}

#[test]
fn only_selected_harness_configuration_paths_are_inherited() {
    let inherited = [
        ("CODEX_HOME", "/home/operator/codex-config"),
        ("PI_CODING_AGENT_DIR", "/home/operator/omp-config"),
    ]
    .map(|(k, v)| (k.to_string(), v.to_string()));
    let codex = cli_agent_adapters::lookup("codex").unwrap();
    let env = build_env(codex, 7000, &HashMap::new(), inherited.clone().into_iter());
    assert_eq!(env, [inherited[0].clone()]);
    assert!(build_env(claude(), 7000, &HashMap::new(), inherited.into_iter()).is_empty());
}

#[test]
fn sdk_region_is_inherited_only_for_an_approved_sigv4_route() {
    let inherited = [
        ("AWS_REGION".to_string(), "us-east-1".to_string()),
        (
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "synthetic-sensitive-value".to_string(),
        ),
        ("AWS_PROFILE".to_string(), "personal".to_string()),
    ];
    assert!(build_env(
        claude(),
        7000,
        &HashMap::new(),
        inherited.clone().into_iter()
    )
    .is_empty());
    let placeholders = HashMap::from([("aws:APP".to_string(), "kepr-ph-test".to_string())]);
    assert_eq!(
        build_env(claude(), 7000, &placeholders, inherited.clone().into_iter()),
        [inherited[0].clone()]
    );
}

#[test]
fn sandbox_probe_failure_never_downgrades_protected_launches() {
    assert!(launch::after_probe(SandboxMode::Required, true, Err("unavailable".into())).is_err());
    assert!(launch::after_probe(SandboxMode::Required, false, Err("unavailable".into())).is_err());
    assert!(launch::after_probe(SandboxMode::Auto, true, Err("unavailable".into())).is_err());
    assert_eq!(
        launch::after_probe(SandboxMode::Auto, false, Err("unavailable".into())),
        Ok(false)
    );
}

#[test]
fn inherited_debug_overrides_cannot_weaken_protected_isolation() {
    assert!(launch::validate_controls(SandboxMode::Required, Some("0"), None).is_err());
    assert!(launch::validate_controls(SandboxMode::Required, None, Some("allow")).is_err());
    assert!(launch::validate_controls(SandboxMode::Required, Some("strict"), None).is_ok());
    assert!(launch::validate_controls(SandboxMode::Auto, Some("0"), Some("allow")).is_ok());
}

#[test]
fn protected_reply_requires_matching_gate_privacy_acknowledgement() {
    use kepr_core::privacy::Preset;
    assert!(launch::confirm_privacy(Some(Preset::PrivateCloud), None).is_err());
    assert!(launch::confirm_privacy(Some(Preset::PrivateCloud), Some(Preset::LocalOnly)).is_err());
    assert!(
        launch::confirm_privacy(Some(Preset::PrivateCloud), Some(Preset::PrivateCloud)).is_ok()
    );
    assert!(launch::confirm_privacy(None, None).is_ok());
}

#[test]
fn final_generated_environment_cannot_reintroduce_loader_controls_or_gate_bypasses() {
    for (key, value) in [
        ("LD_PRELOAD", "kepr-ph-test"),
        ("NODE_OPTIONS", "--require=/tmp/injected.js"),
        ("GIT_CONFIG_GLOBAL", "/tmp/config"),
        ("HTTPS_PROXY", "http://outside.example"),
        ("KEPR_GATE_URL", "http://outside.example"),
        ("NO_PROXY", "*"),
    ] {
        assert!(launch::validate_final_env(&[(key.into(), value.into())], 7000).is_err());
    }
    assert!(launch::validate_final_env(
        &[
            ("HTTPS_PROXY".into(), "http://127.0.0.1:7000".into()),
            ("NO_PROXY".into(), "127.0.0.1,localhost".into()),
            ("GITHUB_TOKEN".into(), "kepr-ph-first".into()),
            ("GITHUB_TOKEN".into(), "kepr-ph-second".into()),
        ],
        7000
    )
    .is_ok());
}

#[test]
fn final_environment_preserves_only_the_generated_git_credential_helper() {
    let directory = tempfile::tempdir().unwrap();
    let placeholders = HashMap::from([("git".to_string(), "kepr-ph-test".to_string())]);
    let mut env = crate::cli_aws::presets::write(
        directory.path(),
        &directory.path().join("ca"),
        &placeholders,
    )
    .unwrap();
    assert!(launch::validate_final_env(&env, 7000).is_ok());
    let helper = env
        .iter_mut()
        .find(|(key, _)| key == "GIT_CONFIG_VALUE_1")
        .unwrap();
    helper.1 = "/tmp/injected-helper".to_string();
    assert!(launch::validate_final_env(&env, 7000).is_err());
}

#[test]
fn routes_need_a_sealed_credential() {
    let none = HashSet::new();
    assert!(routes_for(claude(), &none)
        .unwrap_err()
        .contains("kepr agent add ANTHROPIC_API_KEY"));
    let some: HashSet<String> = ["ANTHROPIC_API_KEY".to_string()].into();
    let r = routes_for(claude(), &some).unwrap();
    assert_eq!((r[0].provider.as_str(), r[0].slot), ("anthropic", 0));
}
