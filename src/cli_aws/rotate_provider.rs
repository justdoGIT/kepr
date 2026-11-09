// rotate_provider.rs — `kepr rotate NAME --provider [NAME]`
//
// Replaces a stored API key by calling the provider's key-creation API,
// extracting the new key, and committing it atomically through `commit_request`.
//
// Invariants:
//   - Zero secrets leaked: values are held in ZeroString and never logged or
//     echoed in error messages.
//   - Atomic: validate-then-commit. If provider API fails, credential is untouched.
//   - Safe error messages: uses sync_http::error_summary to strip sensitive payloads.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{CredInfo, Response};

use crate::cli_exec::{CredFetcher, DaemonFetcher};

/// Map a credential to a known provider name based on hints, bindings or schedule.
pub fn detect_provider_for_name(name: &str) -> Option<String> {
    let upper = name.to_ascii_uppercase();
    let words: Vec<&str> = upper.split(|c: char| !c.is_ascii_alphanumeric()).collect();
    for p in kepr_core::providers::PROVIDERS {
        if words.iter().any(|w| p.name_hints.contains(w))
            || upper.replace('_', "-") == p.name.to_ascii_uppercase()
        {
            return Some(p.name.to_string());
        }
    }
    None
}

/// Detect provider from CredInfo (used by `kepr rotate --all`).
pub fn detect_provider_for_cred(c: &CredInfo) -> Option<String> {
    if let Some(via) = &c.rotate_via {
        if let Some(prov) = via.strip_prefix("provider:") {
            if prov != "auto" {
                return Some(prov.to_string());
            }
        }
    }
    if let Some(hosts) = &c.bound_hosts {
        for bound in hosts {
            let host = bound.strip_suffix(":443").unwrap_or(bound);
            if let Some(p) = kepr_core::providers::by_host(host) {
                return Some(p.name.to_string());
            }
        }
    }
    detect_provider_for_name(&c.name)
}

/// URL endpoint and custom header for provider key generation.
pub fn provider_endpoint(provider: &str) -> Option<(String, Option<&'static str>, String)> {
    if let Ok(url) = std::env::var("KEPR_ROTATE_URL") {
        return Some((url, None, r#"{"name":"kepr-rotated"}"#.to_string()));
    }
    let env_var = format!("KEPR_{}_ROTATE_URL", provider.to_ascii_uppercase().replace('-', "_"));
    if let Ok(url) = std::env::var(&env_var) {
        return Some((url, None, r#"{"name":"kepr-rotated"}"#.to_string()));
    }
    match provider.to_ascii_lowercase().as_str() {
        "openrouter" => Some((
            "https://openrouter.ai/api/v1/keys".into(),
            None,
            r#"{"name":"kepr-rotated"}"#.into(),
        )),
        "openai" => Some((
            "https://api.openai.com/v1/organization/admin_api_keys".into(),
            None,
            r#"{"name":"kepr-rotated"}"#.into(),
        )),
        "anthropic" => Some((
            "https://api.anthropic.com/v1/api_keys".into(),
            Some("x-api-key"),
            r#"{"name":"kepr-rotated"}"#.into(),
        )),
        "groq" => Some((
            "https://api.groq.com/openai/v1/keys".into(),
            None,
            r#"{"name":"kepr-rotated"}"#.into(),
        )),
        "mistral" => Some((
            "https://api.mistral.ai/v1/api-keys".into(),
            None,
            r#"{"name":"kepr-rotated"}"#.into(),
        )),
        "deepseek" => Some((
            "https://api.deepseek.com/v1/keys".into(),
            None,
            r#"{"name":"kepr-rotated"}"#.into(),
        )),
        "xai" => Some((
            "https://api.x.ai/v1/api-key".into(),
            None,
            r#"{"name":"kepr-rotated"}"#.into(),
        )),
        _ => None,
    }
}

/// Extract key from JSON response across common provider patterns.
pub fn extract_key(body: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| "provider returned malformed JSON".to_string())?;
    for ptr in ["/key", "/api_key", "/secret", "/token", "/result/value", "/data/key"] {
        if let Some(s) = v.pointer(ptr).and_then(|val| val.as_str()) {
            if !s.is_empty() {
                return Ok(s.to_string());
            }
        }
    }
    Err("provider reply did not contain a new API key".to_string())
}

/// Call provider's API to generate a new key using the existing key for authentication.
pub fn call_provider_rotation(provider: &str, old_key: &str) -> Result<ZeroString, String> {
    let (url, custom_header, body) = provider_endpoint(provider)
        .ok_or_else(|| format!("provider '{provider}' has no automated rotation endpoint"))?;
    let mut req = crate::sync_http::agent().post(&url);
    match custom_header {
        Some(h) => {
            req = req.set(h, old_key);
        }
        None => {
            req = req.set("Authorization", &format!("Bearer {old_key}"));
        }
    }
    req = req.set("Content-Type", "application/json");
    let (status, resp_body) = crate::sync_http::send(req, Some(body.as_bytes()))
        .map_err(|e| format!("provider request failed: {e}"))?;
    if !(200..=299).contains(&status) {
        let err = crate::sync_http::error_summary(&resp_body);
        let msg = if err.is_empty() {
            format!("provider returned HTTP {status}")
        } else {
            format!("provider error (HTTP {status}): {err}")
        };
        return Err(msg);
    }
    let key = extract_key(&resp_body)?;
    if key == old_key {
        return Err("provider returned the same key unchanged".to_string());
    }
    Ok(ZeroString::from(key))
}

/// Rotate a credential via provider API.
pub fn cmd(name: &str, provider_override: Option<&str>) -> Response {
    let upper = name.to_uppercase();
    let old_key = match DaemonFetcher.fetch(&upper) {
        Ok(k) => k,
        Err(e) => return Response::fail(format!("could not read {upper}: {e}")),
    };
    let prov = provider_override
        .filter(|p| !p.is_empty() && *p != "auto")
        .map(|s| s.to_ascii_lowercase())
        .or_else(|| detect_provider_for_name(&upper))
        .ok_or_else(|| format!("could not detect provider for {upper}; pass --provider NAME"));
    let prov = match prov {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
    let new_key = match call_provider_rotation(&prov, old_key.as_str()) {
        Ok(k) => k,
        Err(e) => return Response::fail(format!("rotation failed for {upper} ({prov}): {e}")),
    };
    let req = crate::cli_rotate::commit_request(&upper, new_key);
    let resp = crate::client::send_request(&req).unwrap_or_else(Response::fail);
    if resp.is_success() && !crate::cli_ui::json_mode() {
        crate::cli_ui::ok(&format!("{upper} rotated via {prov} API"));
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_provider_from_name_and_hints() {
        assert_eq!(detect_provider_for_name("OPENAI_API_KEY"), Some("openai".into()));
        assert_eq!(detect_provider_for_name("ANTHROPIC_KEY"), Some("anthropic".into()));
        assert_eq!(detect_provider_for_name("OPENROUTER_TOKEN"), Some("openrouter".into()));
        assert_eq!(detect_provider_for_name("GROQ_API_KEY"), Some("groq".into()));
        assert_eq!(detect_provider_for_name("MY_MISTRAL_SECRET"), Some("mistral".into()));
        assert_eq!(detect_provider_for_name("UNKNOWN_KEY"), None);
    }

    #[test]
    fn detect_provider_from_credinfo() {
        let cred = CredInfo {
            name: "MODEL_KEY".into(),
            bound_hosts: Some(vec!["api.openai.com:443".into()]),
            ..Default::default()
        };
        assert_eq!(detect_provider_for_cred(&cred), Some("openai".into()));

        let sched = CredInfo {
            name: "CUSTOM_NAME".into(),
            rotate_via: Some("provider:openrouter".into()),
            ..Default::default()
        };
        assert_eq!(detect_provider_for_cred(&sched), Some("openrouter".into()));
    }

    #[test]
    fn key_extraction_from_various_provider_shapes() {
        assert_eq!(extract_key(r#"{"key":"sk-or-new-key"}"#).unwrap(), "sk-or-new-key");
        assert_eq!(extract_key(r#"{"api_key":"sk-ant-new-key"}"#).unwrap(), "sk-ant-new-key");
        assert_eq!(extract_key(r#"{"secret":"mistral-new-secret"}"#).unwrap(), "mistral-new-secret");
        assert_eq!(extract_key(r#"{"result":{"value":"cf-new-token"}}"#).unwrap(), "cf-new-token");
        assert!(extract_key(r#"{"error":"unauthorized"}"#).is_err());
        assert!(extract_key(r#"invalid json"#).is_err());
    }

    #[test]
    fn rotation_call_with_fake_provider() {
        let fake = crate::cli_aws::fake::serve(vec![
            (200, r#"{"key":"sk-new-rotated-key"}"#.into()),
        ]);
        std::env::set_var("KEPR_OPENAI_ROTATE_URL", &fake.url);
        let res = call_provider_rotation("openai", "old-key");
        std::env::remove_var("KEPR_OPENAI_ROTATE_URL");
        assert_eq!(res.unwrap().as_str(), "sk-new-rotated-key");
        let req = fake.requests.recv().unwrap();
        assert!(req.contains("Bearer old-key"));
        assert!(req.contains(r#"{"name":"kepr-rotated"}"#));
    }
}
