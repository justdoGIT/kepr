// cli_agent_detect.rs — provider table and key-prefix detection for
// `kepr agent add` (T1.12). Hosts mirror kepr-gate's route table; the
// inject style here is what the daemon stores in the binding.

use kepr_core::binding::{parse_binding, Binding, Inject};

pub struct ProviderInfo {
    pub name: &'static str,
    pub host: &'static str,
    /// `None` = `Authorization: Bearer`; `Some(h)` = header `h`.
    pub header: Option<&'static str>,
}

pub const PROVIDERS: &[ProviderInfo] = &[
    ProviderInfo {
        name: "anthropic",
        host: "api.anthropic.com",
        header: Some("x-api-key"),
    },
    ProviderInfo {
        name: "openai",
        host: "api.openai.com",
        header: None,
    },
    ProviderInfo {
        name: "xai",
        host: "api.x.ai",
        header: None,
    },
    ProviderInfo {
        name: "google",
        host: "generativelanguage.googleapis.com",
        header: Some("x-goog-api-key"),
    },
    ProviderInfo {
        name: "mistral",
        host: "api.mistral.ai",
        header: None,
    },
    ProviderInfo {
        name: "deepseek",
        host: "api.deepseek.com",
        header: None,
    },
    ProviderInfo {
        name: "groq",
        host: "api.groq.com",
        header: None,
    },
    ProviderInfo {
        name: "openrouter",
        host: "openrouter.ai",
        header: None,
    },
];

pub fn provider(name: &str) -> Option<&'static ProviderInfo> {
    PROVIDERS.iter().find(|p| p.name == name)
}

/// Guess the provider from a key's well-known prefix. Order matters:
/// `sk-ant-` and `sk-or-` must win over the generic OpenAI `sk-`.
pub fn detect(value: &str) -> Option<&'static str> {
    const PREFIXES: &[(&str, &str)] = &[
        ("sk-ant-", "anthropic"),
        ("sk-or-", "openrouter"),
        ("xai-", "xai"),
        ("gsk_", "groq"),
        ("AIza", "google"),
        ("sk-", "openai"),
    ];
    PREFIXES
        .iter()
        .find(|(p, _)| value.starts_with(p))
        .map(|(_, n)| *n)
}

/// `--for` accepts a provider name or a raw `host[:port]:inject` binding.
pub fn binding_for(spec: &str) -> Result<Binding, String> {
    if let Some(p) = provider(spec) {
        return Ok(Binding {
            host: p.host.to_string(),
            port: 443,
            inject: match p.header {
                None => Inject::Bearer,
                Some(h) => Inject::Header {
                    name: h.to_string(),
                },
            },
        });
    }
    parse_binding(spec).map_err(|e| {
        let names: Vec<&str> = PROVIDERS.iter().map(|p| p.name).collect();
        format!(
            "--for {spec}: not a provider ({}) or binding: {e}",
            names.join("|")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_table() {
        assert_eq!(detect("sk-ant-api03-xyz"), Some("anthropic"));
        assert_eq!(detect("sk-or-v1-xyz"), Some("openrouter"));
        assert_eq!(detect("xai-abc"), Some("xai"));
        assert_eq!(detect("gsk_abc"), Some("groq"));
        assert_eq!(detect("AIzaSyabc"), Some("google"));
        assert_eq!(detect("sk-proj-abc"), Some("openai"));
        assert_eq!(detect("mistral-without-prefix"), None);
    }

    #[test]
    fn for_provider_and_raw_binding() {
        let b = binding_for("anthropic").unwrap();
        assert_eq!(b.host, "api.anthropic.com");
        assert_eq!(
            b.inject,
            Inject::Header {
                name: "x-api-key".into()
            }
        );
        assert_eq!(binding_for("xai").unwrap().inject, Inject::Bearer);
        assert_eq!(
            binding_for("api.example.com:bearer").unwrap().host,
            "api.example.com"
        );
        assert!(binding_for("nope").is_err());
    }

    #[test]
    fn hosts_validate() {
        for p in PROVIDERS {
            assert!(binding_for(p.name).is_ok(), "{}", p.name);
        }
    }
}
