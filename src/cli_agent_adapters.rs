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
    /// Fixed port, for harnesses configured through a file with a fixed
    /// base URL (written by `kepr agent install`).
    pub port: Option<u16>,
}

pub const INSTALL_PORT: u16 = 7878;

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
    // OpenAI Codex CLI: OPENAI_BASE_URL + OPENAI_API_KEY.
    Adapter {
        harness: "codex",
        program: "codex",
        creds: &[("openai", "OPENAI_API_KEY")],
        env: &[
            var("OPENAI_BASE_URL", Value::BaseUrl("openai", "/v1")),
            var("OPENAI_API_KEY", Value::Placeholder("OPENAI_API_KEY")),
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
    // oh-my-pi: ~/.omp/agent/models.yml (written by `kepr agent install omp`)
    // names KEPR_PH_ANTHROPIC as the provider's apiKey variable.
    Adapter {
        harness: "omp",
        program: "omp",
        creds: &[("anthropic", "ANTHROPIC_API_KEY")],
        env: &[
            var("KEPR_PH_ANTHROPIC", Value::Placeholder("ANTHROPIC_API_KEY")),
            var("ANTHROPIC_API_KEY", Value::Placeholder("ANTHROPIC_API_KEY")),
        ],
        port: Some(INSTALL_PORT),
    },
    // Grok Build (xAI): ~/.grok/config.toml (written by `kepr agent install
    // grok`) sets env_key = "KEPR_PH_XAI".
    Adapter {
        harness: "grok",
        program: "grok",
        creds: &[("xai", "XAI_API_KEY")],
        env: &[
            var("KEPR_PH_XAI", Value::Placeholder("XAI_API_KEY")),
            var("XAI_API_KEY", Value::Placeholder("XAI_API_KEY")),
        ],
        port: Some(INSTALL_PORT),
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
                assert!(crate::cli_agent_detect::provider(p).is_some(), "{p}");
            }
        }
    }

    #[test]
    fn lookup_errors_list_supported() {
        assert!(lookup("claude").is_ok());
        assert!(matches!(lookup("nope"), Err(e) if e.contains("claude")));
    }
}
