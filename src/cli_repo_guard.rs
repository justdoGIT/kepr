// cli_repo_guard.rs — repository-scoped provider eligibility guard across all
// coding agents (omp, claude, grok, codex, aider, goose, crush, gemini,
// opencode, cursor, copilot). Blocks third-party LLM relays in restricted
// repositories and permits only approved first-party or local providers.

pub use crate::cli_repo_policy::{is_restricted_repo, load_policy, PrivacyPolicy};
use kepr_core::gate_protocol::GateRoute;
use kepr_core::providers::PROVIDERS;
use serde_json::Value;
use std::path::{Path, PathBuf};

const BLOCKED_RELAY_DOMAINS: &[&str] = &[
    "openrouter.ai",
    "agentrouter.",
    "selora.",
    "api.venice.ai",
    "api.fireworks.ai",
    "api.moonshot.cn",
    "gateway.ai.cloudflare.com",
];

pub fn canonical_provider_for_host(host: &str) -> Option<&'static str> {
    let h = host
        .trim()
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match h.as_str() {
        "api.anthropic.com" => Some("anthropic"),
        "api.openai.com" | "chatgpt.com" => Some("openai"),
        "generativelanguage.googleapis.com" => Some("google"),
        "aiplatform.googleapis.com" => Some("google-vertex"),
        "api.x.ai" => Some("xai"),
        "api.deepseek.com" => Some("deepseek"),
        "api.groq.com" => Some("groq"),
        "api.mistral.ai" => Some("mistral"),
        "integrate.api.nvidia.com" => Some("nvidia"),
        "localhost" | "127.0.0.1" | "::1" => Some("ollama"),
        _ if h.ends_with("-aiplatform.googleapis.com") => Some("google-vertex"),
        _ => PROVIDERS
            .iter()
            .find(|p| p.host.eq_ignore_ascii_case(&h))
            .map(|p| p.name),
    }
}

fn host_from_url(url: &str) -> Option<&str> {
    let rest = url
        .trim()
        .strip_prefix("https://")
        .or_else(|| url.trim().strip_prefix("http://"))?;
    let host = rest
        .split(['/', '?', '#'])
        .next()?
        .rsplit('@')
        .next()?
        .split(':')
        .next()?;
    (!host.is_empty()).then_some(host)
}

pub fn is_provider_allowed(provider_or_route: &str, policy: &PrivacyPolicy) -> bool {
    let s = provider_or_route.trim().to_ascii_lowercase();
    if s.is_empty() {
        return false;
    }
    if ["db:", "aws:", "kube:", "cf:", "ssh:", "tcp:"]
        .iter()
        .any(|p| s.starts_with(p))
    {
        return true;
    }
    let allowed = |name: &str| policy.allowed_providers.iter().any(|a| a == name);
    if let Some(rest) = s.strip_prefix("https+").or_else(|| s.strip_prefix("http+")) {
        let host = rest.split('+').next().unwrap_or("");
        return canonical_provider_for_host(host).is_some_and(allowed) || allowed(host);
    }
    if let Some(host) = host_from_url(&s) {
        return matches!(host, "127.0.0.1" | "localhost" | "::1")
            || canonical_provider_for_host(host).is_some_and(allowed)
            || allowed(host);
    }
    allowed(&s)
        || s.split_once('/').is_some_and(|(p, _)| allowed(p))
        || canonical_provider_for_host(&s).is_some_and(allowed)
}

pub fn filter_routes_for_dir(
    cwd: &Path,
    routes: Vec<GateRoute>,
    policy: &PrivacyPolicy,
) -> Result<Vec<GateRoute>, String> {
    let Some(repo) = is_restricted_repo(cwd, policy) else {
        return Ok(routes);
    };
    let had_llm = routes.iter().any(|r| r.target.is_none());
    let mut next_slot = 0u16;
    let mut kept = Vec::with_capacity(routes.len());
    for mut r in routes {
        if !is_provider_allowed(&r.provider, policy) {
            continue;
        }
        if r.target.is_none() {
            r.slot = next_slot;
            next_slot += 1;
        }
        kept.push(r);
    }
    if had_llm && !kept.iter().any(|r| r.target.is_none()) {
        return Err(format!(
            "[PRIVACY GUARD BLOCKED] Restricted repository ({repo}) allows only first-party/local providers ({}), and no eligible sealed credentials matched.",
            policy.allowed_providers.join(", ")
        ));
    }
    Ok(kept)
}

pub fn filter_routes(routes: Vec<GateRoute>) -> Result<Vec<GateRoute>, String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    filter_routes_for_dir(&cwd, routes, &load_policy())
}

fn extract_str<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for k in path {
        cur = cur.get(*k)?;
    }
    cur.as_str().map(str::trim).filter(|s| !s.is_empty())
}

pub fn check_hook_in(
    event: &str,
    input: &Value,
    cwd: &Path,
    policy: &PrivacyPolicy,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<String>, String> {
    let dir = extract_str(input, &["cwd"])
        .or_else(|| extract_str(input, &["workspace"]))
        .map(PathBuf::from)
        .unwrap_or_else(|| cwd.to_path_buf());
    let Some(repo) = is_restricted_repo(&dir, policy) else {
        return Ok(None);
    };
    let provider = [
        &["provider"][..],
        &["model_provider"],
        &["model", "provider"],
        &["context", "provider"],
        &["context", "model", "provider"],
        &["session", "provider"],
    ]
    .into_iter()
    .find_map(|p| extract_str(input, p).map(str::to_string))
    .or_else(|| {
        [
            "KEPR_AGENT_PROVIDER",
            "AGENT_PROVIDER",
            "OMP_PROVIDER",
            "PI_PROVIDER",
            "LLM_PROVIDER",
        ]
        .into_iter()
        .find_map(|k| env(k).filter(|s| !s.trim().is_empty()))
    });
    if let Some(prov) = provider.filter(|p| !is_provider_allowed(p, policy)) {
        return Err(format!(
            "[PRIVACY GUARD BLOCKED] Third-party provider '{prov}' is forbidden in restricted repository ({repo}). Allowed first-party/local providers: {}",
            policy.allowed_providers.join(", ")
        ));
    }
    let base_url = [
        &["base_url"][..],
        &["baseUrl"],
        &["model", "baseUrl"],
        &["context", "model", "baseUrl"],
    ]
    .into_iter()
    .find_map(|p| extract_str(input, p).map(str::to_string))
    .or_else(|| {
        ["ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"]
            .into_iter()
            .find_map(|k| env(k).filter(|s| !s.trim().is_empty()))
    });
    if let Some(url) = base_url.filter(|u| !is_provider_allowed(u, policy)) {
        return Err(format!(
            "[PRIVACY GUARD BLOCKED] Third-party endpoint '{url}' is forbidden in restricted repository ({repo}). Allowed first-party/local providers: {}",
            policy.allowed_providers.join(", ")
        ));
    }
    if event == "pre-tool" {
        let ti = input
            .get("tool_input")
            .or_else(|| input.get("toolInput"))
            .unwrap_or(&Value::Null);
        let blob = ti.to_string().to_ascii_lowercase();
        if let Some(relay) = BLOCKED_RELAY_DOMAINS.iter().find(|d| blob.contains(*d)) {
            return Err(format!(
                "[PRIVACY GUARD BLOCKED] Outbound tool request to third-party relay '{relay}' is forbidden in restricted repository ({repo})."
            ));
        }
    }
    if event == "session-start" {
        return Ok(Some(format!(
            "Privacy Guard: Active repository ({repo}) enforces first-party/local provider eligibility ({}).",
            policy.allowed_providers.join(", ")
        )));
    }
    Ok(None)
}

pub fn check_hook(event: &str, input: &Value) -> Result<Option<String>, String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    check_hook_in(event, input, &cwd, &load_policy(), &|k| {
        std::env::var(k).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn policy_and_provider_eligibility_checks() {
        let p = PrivacyPolicy::default();
        assert!(p.strict);
        for ok in [
            "anthropic",
            "openai/gpt-5",
            "https+api.anthropic.com+K",
            "http://127.0.0.1:4229/v1",
            "db:PG",
        ] {
            assert!(is_provider_allowed(ok, &p), "{ok}");
        }
        for bad in [
            "openrouter",
            "agentrouter",
            "selora",
            "venice",
            "fireworks",
            "https+openrouter.ai+K",
            "https://openrouter.ai/v1",
        ] {
            assert!(!is_provider_allowed(bad, &p), "{bad}");
        }
    }

    #[test]
    fn restricted_repo_hook_and_route_filtering() {
        let p = PrivacyPolicy::default();
        let tmp = tempfile::tempdir().unwrap();
        let dev = tmp.path().join("dev-setup");
        std::fs::create_dir_all(&dev).unwrap();
        assert_eq!(is_restricted_repo(&dev, &p).as_deref(), Some("dev-setup"));
        assert!(check_hook_in(
            "prompt",
            &json!({"provider": "openrouter"}),
            &dev,
            &p,
            &|_| None
        )
        .is_err());
        assert!(check_hook_in(
            "prompt",
            &json!({"model": {"provider": "anthropic"}}),
            &dev,
            &p,
            &|_| None
        )
        .unwrap()
        .is_none());
        assert!(check_hook_in(
            "pre-tool",
            &json!({"tool_input": {"cmd": "curl https://openrouter.ai/api/v1"}}),
            &dev,
            &p,
            &|_| None
        )
        .is_err());

        let routes = vec![
            GateRoute {
                provider: "openrouter".into(),
                cred: "OR".into(),
                slot: 0,
                target: None,
            },
            GateRoute {
                provider: "anthropic".into(),
                cred: "AN".into(),
                slot: 1,
                target: None,
            },
        ];
        let kept = filter_routes_for_dir(&dev, routes, &p).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].provider.as_str(), kept[0].slot), ("anthropic", 0));
    }
}
