// rotate_provider.rs — `kepr rotate NAME --provider PROVIDER`.
//
// Provider key management uses a separately stored bootstrap credential. A
// normal inference key is never treated as an administrator key, and a
// provider with no documented key-creation API is refused rather than sent a
// guessed request. The replacement is validated before the daemon commits it.

use kepr_core::protocol::{CredInfo, Request, Response};

/// Map a credential to a known provider name based on hints, bindings or its
/// schedule. Schedule metadata may append `:<bootstrap-name>`.
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

pub fn detect_provider_for_cred(c: &CredInfo) -> Option<String> {
    if let Some(via) = &c.rotate_via {
        if let Some(prov) = via.strip_prefix("provider:") {
            let provider = prov.split(':').next().unwrap_or(prov);
            if provider != "auto" {
                return Some(provider.to_string());
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

pub fn supports_automated_rotation(provider: &str) -> bool {
    kepr_core::providers::supports_rotation(provider)
}

/// `kepr rotate NAME --provider PROVIDER --bootstrap ADMIN_KEY`.
pub fn cmd(name: &str, provider_override: Option<&str>, bootstrap: Option<&str>) -> Response {
    let upper = name.to_uppercase();
    let provider = provider_override
        .filter(|p| !p.is_empty() && *p != "auto")
        .map(str::to_ascii_lowercase)
        .or_else(|| detect_provider_for_name(&upper))
        .ok_or_else(|| format!("could not detect provider for {upper}; pass --provider NAME"));
    let provider = match provider {
        Ok(provider) if supports_automated_rotation(&provider) => provider,
        Ok(provider) => {
            return Response::fail(format!(
                "provider '{provider}' has no documented automated key-creation flow"
            ))
        }
        Err(error) => return Response::fail(error),
    };
    let Some(bootstrap) = bootstrap.filter(|name| !name.is_empty()) else {
        return Response::fail(
            "provider rotation requires --bootstrap KEY; keep a separate provider management key in kepr",
        );
    };
    let bootstrap = bootstrap.to_uppercase();
    if bootstrap == upper {
        return Response::fail("--bootstrap must name a separate credential");
    }
    let request = Request::RotateProvider {
        target: upper.clone(),
        provider: provider.clone(),
        bootstrap,
    };
    match crate::client::send_request(&request) {
        Ok(Response::ProviderRotated { name, provider }) => {
            if !crate::cli_ui::json_mode() {
                crate::cli_ui::ok(&format!("{name} rotated via {provider} provider API"));
            }
            Response::ProviderRotated { name, provider }
        }
        Ok(Response::Err { error }) => Response::fail(error),
        Ok(_) => Response::fail("unexpected daemon response"),
        Err(error) => Response::fail(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_and_support_are_conservative() {
        assert_eq!(
            detect_provider_for_name("OPENROUTER_TOKEN"),
            Some("openrouter".into())
        );
        assert_eq!(detect_provider_for_name("UNKNOWN_KEY"), None);
        assert!(supports_automated_rotation("venice"));
        assert!(!supports_automated_rotation("fireworks"));
    }

    #[test]
    fn unsupported_provider_rotation_is_rejected_before_daemon_access() {
        let response = cmd("MOONSHOT_API_KEY", Some("moonshot"), Some("ADMIN"));
        assert!(matches!(response, Response::Err { .. }));
    }

    #[test]
    fn missing_or_same_bootstrap_is_rejected() {
        assert!(matches!(
            cmd("OPENROUTER_KEY", Some("openrouter"), None),
            Response::Err { .. }
        ));
        assert!(matches!(
            cmd("OPENROUTER_KEY", Some("openrouter"), Some("OPENROUTER_KEY")),
            Response::Err { .. }
        ));
    }
}
