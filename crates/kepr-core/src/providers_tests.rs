// Provider registry behavior and destination binding regressions.
use super::*;

#[test]
fn selora_binding_is_host_limited() {
    let p = lookup("selora").expect("Selora must be a supported provider");
    assert_eq!(p.binding().host, "api.selora.lol");
    assert_eq!(p.binding().port, 443);
    assert_eq!(p.binding().inject, Inject::Bearer);
    assert_eq!(
        detect(Some("SELORA_API_KEY"), "synthetic").map(|p| p.name),
        Some("selora")
    );
}

#[test]
fn reviewed_openai_compatible_provider_bindings_are_host_limited() {
    for (name, host, variable) in [
        ("fireworks", "api.fireworks.ai", "FIREWORKS_API_KEY"),
        ("moonshot", "api.moonshot.cn", "MOONSHOT_API_KEY"),
        ("venice", "api.venice.ai", "VENICE_API_KEY"),
    ] {
        let provider = lookup(name).expect("provider must be registered");
        assert_eq!(provider.binding().host, host);
        assert_eq!(provider.binding().port, 443);
        assert_eq!(provider.binding().inject, Inject::Bearer);
        assert_eq!(
            detect(Some(variable), "synthetic").map(|p| p.name),
            Some(name)
        );
    }
}

#[test]
fn rotation_allowlist_requires_management_api_support() {
    for provider in ["openai", "openrouter", "venice"] {
        assert!(supports_rotation(provider));
    }
    for provider in ["fireworks", "moonshot", "anthropic", "selora"] {
        assert!(!supports_rotation(provider));
    }
}

#[test]
fn agentrouter_binding_is_host_limited() {
    let provider = lookup("agentrouter").expect("AgentRouter must be a supported provider");
    let binding = provider.binding();
    assert_eq!(binding.host, "agentrouter.org");
    assert_eq!(binding.port, 443);
    assert_eq!(binding.inject, Inject::Bearer);
    assert_eq!(
        detect(Some("AGENTROUTER_API_KEY"), "synthetic-secret").map(|p| p.name),
        Some("agentrouter")
    );
}
use crate::binding::validate_binding;

#[test]
fn table_is_consistent() {
    for p in PROVIDERS {
        assert!(validate_binding(&p.binding()).is_ok(), "{}", p.name);
        assert_eq!(
            PROVIDERS
                .iter()
                .filter(|q| q.name == p.name || q.host == p.host)
                .count(),
            1
        );
        assert!(p.name.chars().all(|c| c.is_ascii_lowercase()));
    }
}

#[test]
fn detection() {
    let d = |n: Option<&str>, v: &str| detect(n, v).map(|p| p.name);
    assert_eq!(d(None, "sk-ant-api03-x"), Some("anthropic"));
    assert_eq!(d(None, "sk-or-v1-x"), Some("openrouter"));
    assert_eq!(d(None, "sk-proj-x"), Some("openai"));
    assert_eq!(d(None, "sk-0123abcd"), None, "bare sk- is ambiguous");
    assert_eq!(d(Some("DEEPSEEK_API_KEY"), "sk-0123abcd"), Some("deepseek"));
    assert_eq!(d(Some("OPENAI_API_KEY"), "sk-legacy"), Some("openai"));
    assert_eq!(
        d(Some("OPENAI_API_KEY"), "sk-ant-x"),
        Some("anthropic"),
        "prefix beats name"
    );
    assert_eq!(d(Some("MISTRAL_KEY"), "abc"), Some("mistral"));
    assert_eq!(d(Some("MY_KEY"), "abc"), None);
}

#[test]
fn cli_presets() {
    let d = |n: Option<&str>, v: &str| detect(n, v).map(|p| p.name);
    assert_eq!(d(None, "sk_live_51Habc"), Some("stripe"));
    assert_eq!(d(None, "sk_test_51Habc"), Some("stripe"));
    assert_eq!(d(None, "rk_live_51Habc"), Some("stripe"));
    assert_eq!(
        d(None, "npm_abcdefghijklmnopqrstuvwxyz0123456789"),
        Some("npm")
    );
    assert_eq!(d(None, "ya29.a0AfB_byC"), Some("gcloud"));
    assert_eq!(d(None, "dckr_pat_abcdef"), Some("docker"));
    assert_eq!(d(Some("NPM_TOKEN"), "legacy-uuid"), Some("npm"));
    assert_eq!(d(Some("DOCKERHUB_LOGIN"), "me:pat"), Some("docker"));
    assert_eq!(lookup("docker").unwrap().binding().inject, Inject::Basic);
    assert_eq!(lookup("npm").unwrap().binding().inject, Inject::Bearer);
    assert_eq!(lookup("stripe").unwrap().egress_env, ["STRIPE_API_KEY"]);
    assert_eq!(under_domain("storage.googleapis.com"), Some("gcloud"));
    assert_eq!(under_domain("a.b.googleapis.com"), Some("gcloud"));
    for h in [
        "googleapis.com",
        "evilgoogleapis.com",
        "googleapis.com.evil.com",
        ".googleapis.com",
    ] {
        assert_eq!(under_domain(h), None, "{h}");
    }
    for h in GCLOUD_HOSTS {
        assert_eq!(under_domain(h), Some("gcloud"));
        assert!(crate::binding::validate_host(h).is_ok());
    }
}

#[test]
fn git_over_https_on_github_com() {
    assert_eq!(detect(None, "ghp_x").map(|p| p.name), Some("github"));
    assert_eq!(by_host("github.com").map(|p| p.name), Some("git"));
    assert_eq!(by_host("api.github.com").map(|p| p.name), Some("github"));
    let git = lookup("git").unwrap();
    assert_eq!(git.binding().inject, Inject::BasicPassword);
    assert!(git.prefixes.is_empty() && git.name_hints.is_empty());
    assert_eq!(git_cred_name("github.com"), "GIT_GITHUB_COM");
    for host in [
        format!("git-{}.example", "a".repeat(100)),
        "git.example.net:8443".into(),
    ] {
        assert!(git_cred_name(&host).len() <= 128);
        assert_eq!(
            git_cred_name(&host),
            git_cred_name(&host.to_ascii_uppercase())
        );
    }
    assert_ne!(
        git_cred_name("foo-bar.example"),
        git_cred_name("foo.bar.example.host.666f6f2d6261722e6578616d706c65")
    );
    assert_ne!(git_cred_name("a.b-c"), git_cred_name("a-b.c"));
}
