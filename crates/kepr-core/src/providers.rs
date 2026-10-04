//! The model providers kepr can broker: one table shared by the CLI
//! (`kepr agent add` bindings, key detection, `kepr mcp`) and kepr-gate
//! (routing). Keeping it in one place means a binding the CLI writes is
//! always a host the gate routes.

use crate::binding::{Binding, Inject};

pub struct Provider {
    /// URL prefix on the gate (`/anthropic/...`) and the `--for` name.
    pub name: &'static str,
    /// Upstream TLS host (port 443).
    pub host: &'static str,
    /// `None` = `Authorization: Bearer`; `Some(h)` = header `h`.
    pub header: Option<&'static str>,
    /// Key prefixes that identify this provider unambiguously.
    pub prefixes: &'static [&'static str],
    /// Upper-case words that identify it in a variable name.
    pub name_hints: &'static [&'static str],
    /// Where the user revokes or rotates keys (`kepr leaked`).
    pub keys_url: &'static str,
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "anthropic",
        host: "api.anthropic.com",
        header: Some("x-api-key"),
        prefixes: &["sk-ant-"],
        name_hints: &["ANTHROPIC", "CLAUDE"],
        keys_url: "https://console.anthropic.com/settings/keys",
    },
    Provider {
        name: "openai",
        host: "api.openai.com",
        header: None,
        prefixes: &["sk-proj-", "sk-svcacct-", "sk-admin-"],
        name_hints: &["OPENAI"],
        keys_url: "https://platform.openai.com/api-keys",
    },
    Provider {
        name: "xai",
        host: "api.x.ai",
        header: None,
        prefixes: &["xai-"],
        name_hints: &["XAI", "GROK"],
        keys_url: "https://console.x.ai",
    },
    Provider {
        name: "google",
        host: "generativelanguage.googleapis.com",
        header: Some("x-goog-api-key"),
        prefixes: &["AIza"],
        name_hints: &["GEMINI", "GOOGLE"],
        keys_url: "https://aistudio.google.com/app/apikey",
    },
    Provider {
        name: "mistral",
        host: "api.mistral.ai",
        header: None,
        prefixes: &[],
        name_hints: &["MISTRAL"],
        keys_url: "https://console.mistral.ai/api-keys",
    },
    Provider {
        name: "deepseek",
        host: "api.deepseek.com",
        header: None,
        prefixes: &[],
        name_hints: &["DEEPSEEK"],
        keys_url: "https://platform.deepseek.com/api_keys",
    },
    Provider {
        name: "groq",
        host: "api.groq.com",
        header: None,
        prefixes: &["gsk_"],
        name_hints: &["GROQ"],
        keys_url: "https://console.groq.com/keys",
    },
    Provider {
        name: "openrouter",
        host: "openrouter.ai",
        header: None,
        prefixes: &["sk-or-"],
        name_hints: &["OPENROUTER"],
        keys_url: "https://openrouter.ai/settings/keys",
    },
];

pub fn lookup(name: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.name == name)
}

pub fn by_host(host: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.host == host)
}

impl Provider {
    /// The binding `kepr agent add --for <name>` stores.
    pub fn binding(&self) -> Binding {
        Binding {
            host: self.host.to_string(),
            port: 443,
            inject: match self.header {
                None => Inject::Bearer,
                Some(h) => Inject::Header {
                    name: h.to_string(),
                },
            },
        }
    }
}

/// Guess the provider of a key. An unambiguous prefix wins; otherwise a
/// provider named in the variable name (`DEEPSEEK_API_KEY`) is used,
/// unless the value's prefix belongs to a different provider. A bare
/// `sk-` key is ambiguous (OpenAI, DeepSeek and others issue them) and
/// resolves only through the variable name.
pub fn detect(var_name: Option<&str>, value: &str) -> Option<&'static Provider> {
    let by_prefix = PROVIDERS
        .iter()
        .find(|p| p.prefixes.iter().any(|pre| value.starts_with(pre)));
    if by_prefix.is_some() {
        return by_prefix;
    }
    let upper = var_name.unwrap_or_default().to_ascii_uppercase();
    let words: Vec<&str> = upper.split(|c: char| !c.is_ascii_alphanumeric()).collect();
    PROVIDERS
        .iter()
        .find(|p| p.name_hints.iter().any(|h| words.contains(h)))
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
