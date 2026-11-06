// Provider registry behavior and destination binding regressions.
use super::*;

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
    assert_eq!(
        git_cred_name("git.example.net:8443"),
        "GIT_GIT_EXAMPLE_NET_8443_HOST_6769742E6578616D706C652E6E65743A38343433"
    );
    assert_ne!(git_cred_name("a.b-c"), git_cred_name("a-b.c"));
}
