// cli_agent_adapters.rs — which variables each agent harness reads
// (T1.14). `kepr agent run` removes every variable listed here from the
// inherited environment (so a real key exported in the shell never
// reaches the agent) and sets them to gate URLs / placeholders.
//
// Variable names were taken from each harness's documentation as of
// 2026-10; re-verify when a harness changes its configuration.

pub enum Value {
    /// `http://127.0.0.1:PORT/<provider><suffix>`
    BaseUrl(&'static str, &'static str),
    /// The session placeholder for this credential NAME.
    Placeholder(&'static str),
}

pub struct EnvVar {
    pub name: &'static str,
    pub value: Value,
}

pub struct Adapter {
    pub harness: &'static str,
    /// Default program to run when no argv follows `--`.
    pub program: &'static str,
    /// (provider, credential NAME)
    pub creds: &'static [(&'static str, &'static str)],
    pub env: &'static [EnvVar],
    /// Optional fixed port required by a manually configured harness.
    /// Install-backed harnesses default to a per-session ephemeral port.
    pub port: Option<u16>,
}

const fn var(name: &'static str, value: Value) -> EnvVar {
    EnvVar { name, value }
}

pub const ADAPTERS: &[Adapter] = &[
    // Claude Code: ANTHROPIC_BASE_URL + ANTHROPIC_API_KEY (sent as x-api-key).
    Adapter {
        harness: "claude",
        program: "claude",
        creds: &[("anthropic", "ANTHROPIC_API_KEY")],
        env: &[
            var("ANTHROPIC_BASE_URL", Value::BaseUrl("anthropic", "")),
            var("ANTHROPIC_API_KEY", Value::Placeholder("ANTHROPIC_API_KEY")),
        ],
        port: None,
    },
    // Codex API providers; cli_agent_codex pins the selected provider to the gate.
    Adapter {
        harness: "codex",
        program: "codex",
        creds: &[
            ("openai", "OPENAI_API_KEY"),
            ("agentrouter", "AGENTROUTER_API_KEY"),
            ("selora", "SELORA_API_KEY"),
        ],
        env: &[
            var("OPENAI_BASE_URL", Value::BaseUrl("openai", "/v1")),
            var("OPENAI_API_KEY", Value::Placeholder("OPENAI_API_KEY")),
            var(
                "AGENTROUTER_API_KEY",
                Value::Placeholder("AGENTROUTER_API_KEY"),
            ),
            var("SELORA_API_KEY", Value::Placeholder("SELORA_API_KEY")),
        ],
        port: None,
    },
    // Community grok-cli: GROK_BASE_URL + GROK_API_KEY (XAI_API_KEY alias).
    Adapter {
        harness: "grok-cli",
        program: "grok",
        creds: &[("xai", "XAI_API_KEY")],
        env: &[
            var("GROK_BASE_URL", Value::BaseUrl("xai", "/v1")),
            var("GROK_API_KEY", Value::Placeholder("XAI_API_KEY")),
            var("XAI_API_KEY", Value::Placeholder("XAI_API_KEY")),
        ],
        port: None,
    },
    // Aider (OpenAI-compatible path): OPENAI_API_BASE + OPENAI_API_KEY.
    Adapter {
        harness: "aider",
        program: "aider",
        creds: &[("openai", "OPENAI_API_KEY")],
        env: &[
            var("OPENAI_API_BASE", Value::BaseUrl("openai", "/v1")),
            var("OPENAI_API_KEY", Value::Placeholder("OPENAI_API_KEY")),
        ],
        port: None,
    },
    // oh-my-pi: the kepr extension registers a provider at KEPR_GATE_URL.
    Adapter {
        harness: "omp",
        program: "omp",
        creds: &[
            ("anthropic", "ANTHROPIC_API_KEY"),
            ("cloudflare", "CLOUDFLARE_AI_GATEWAY_API_KEY"),
        ],
        env: &[
            var("KEPR_PH_ANTHROPIC", Value::Placeholder("ANTHROPIC_API_KEY")),
            var("ANTHROPIC_API_KEY", Value::Placeholder("ANTHROPIC_API_KEY")),
            var(
                "KEPR_PH_CLOUDFLARE",
                Value::Placeholder("CLOUDFLARE_AI_GATEWAY_API_KEY"),
            ),
            var(
                "CLOUDFLARE_AI_GATEWAY_API_KEY",
                Value::Placeholder("CLOUDFLARE_AI_GATEWAY_API_KEY"),
            ),
        ],
        port: None,
    },
    // Grok Build's session base URL override points the installed model at
    // the per-session gate; the persisted model config need not pin a port.
    Adapter {
        harness: "grok",
        program: "grok",
        creds: &[("xai", "XAI_API_KEY")],
        env: &[
            var("GROK_XAI_API_BASE_URL", Value::BaseUrl("xai", "/v1")),
            var("KEPR_PH_XAI", Value::Placeholder("XAI_API_KEY")),
            var("XAI_API_KEY", Value::Placeholder("XAI_API_KEY")),
        ],
        port: None,
    },
    // Gemini CLI (T12.13): GOOGLE_GEMINI_BASE_URL (the API root; the SDK
    // adds /v1beta) + GEMINI_API_KEY (sent as x-goog-api-key).
    Adapter {
        harness: "gemini",
        program: "gemini",
        creds: &[("google", "GEMINI_API_KEY")],
        env: &[
            var("GOOGLE_GEMINI_BASE_URL", Value::BaseUrl("google", "")),
            var("GEMINI_API_KEY", Value::Placeholder("GEMINI_API_KEY")),
        ],
        port: None,
    },
    // OpenCode's config uses {env:KEPR_GATE_URL} at runtime.
    Adapter {
        harness: "opencode",
        program: "opencode",
        creds: &[("anthropic", "ANTHROPIC_API_KEY")],
        env: &[
            var("KEPR_PH_ANTHROPIC", Value::Placeholder("ANTHROPIC_API_KEY")),
            var("ANTHROPIC_API_KEY", Value::Placeholder("ANTHROPIC_API_KEY")),
        ],
        port: None,
    },
];

pub fn lookup(harness: &str) -> Result<&'static Adapter, String> {
    ADAPTERS
        .iter()
        .find(|a| a.harness == harness)
        .ok_or_else(|| {
            let names: Vec<&str> = ADAPTERS.iter().map(|a| a.harness).collect();
            format!(
                "unknown harness '{harness}' (supported: {})",
                names.join(", ")
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_routes_a_sealed_selora_credential() {
        let available = std::collections::HashSet::from(["SELORA_API_KEY".into()]);
        let routes = crate::cli_agent_run::routes_for(lookup("codex").unwrap(), &available)
            .expect("Selora key must route through the gate");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].provider, "selora");
        let env = crate::cli_agent_run::build_env(
            lookup("codex").unwrap(),
            7001,
            &std::collections::HashMap::from([("selora".into(), "kepr-ph-test".into())]),
            [("SELORA_API_KEY".into(), "synthetic-secret".into())].into_iter(),
        );
        assert_eq!(
            env.iter()
                .find(|(key, _)| key == "SELORA_API_KEY")
                .unwrap()
                .1,
            "kepr-ph-test"
        );
    }

    #[test]
    fn codex_routes_a_sealed_agentrouter_credential() {
        let available = std::collections::HashSet::from(["AGENTROUTER_API_KEY".to_string()]);
        let routes = crate::cli_agent_run::routes_for(lookup("codex").unwrap(), &available)
            .expect("Codex must support its configured AgentRouter key");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].provider, "agentrouter");
        assert_eq!(routes[0].cred, "AGENTROUTER_API_KEY");
        let ph = std::collections::HashMap::from([(
            "agentrouter".to_string(),
            "kepr-ph-test".to_string(),
        )]);
        let env = crate::cli_agent_run::build_env(
            lookup("codex").unwrap(),
            7001,
            &ph,
            [(
                "AGENTROUTER_API_KEY".to_string(),
                "synthetic-secret".to_string(),
            )]
            .into_iter(),
        );
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "AGENTROUTER_API_KEY")
                .map(|(_, v)| v.as_str()),
            Some("kepr-ph-test")
        );
        assert!(!env.iter().any(|(_, v)| v == "synthetic-secret"));
    }

    #[test]
    fn harness_names_unique_and_placeholders_declared() {
        for a in ADAPTERS {
            assert_eq!(
                ADAPTERS.iter().filter(|b| b.harness == a.harness).count(),
                1
            );
            for v in a.env {
                match v.value {
                    Value::Placeholder(c) => {
                        assert!(a.creds.iter().any(|(_, n)| *n == c), "{}", a.harness)
                    }
                    Value::BaseUrl(p, _) => {
                        assert!(a.creds.iter().any(|(q, _)| *q == p), "{}", a.harness)
                    }
                }
            }
            for (p, _) in a.creds {
                assert!(kepr_core::providers::lookup(p).is_some(), "{p}");
            }
        }
    }

    #[test]
    fn lookup_errors_list_supported() {
        assert!(lookup("claude").is_ok());
        assert!(matches!(lookup("nope"), Err(e) if e.contains("claude")));
    }
}
