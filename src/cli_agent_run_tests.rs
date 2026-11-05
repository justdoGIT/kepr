// Protected-launch credential isolation and sandbox regressions.

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
fn routes_need_a_sealed_credential() {
    let none = HashSet::new();
    assert!(routes_for(claude(), &none)
        .unwrap_err()
        .contains("kepr agent add ANTHROPIC_API_KEY"));
    let some: HashSet<String> = ["ANTHROPIC_API_KEY".to_string()].into();
    let r = routes_for(claude(), &some).unwrap();
    assert_eq!((r[0].provider.as_str(), r[0].slot), ("anthropic", 0));
}
