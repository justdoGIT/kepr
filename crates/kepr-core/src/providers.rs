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
    /// `None` = `Authorization: Bearer`; `Some(h)` = header `h`;
    /// `Some(BASIC_AUTH)` = `Authorization: Basic` (value `user:password`).
    pub header: Option<&'static str>,
    /// Key prefixes that identify this provider unambiguously.
    pub prefixes: &'static [&'static str],
    /// Upper-case words that identify it in a variable name.
    pub name_hints: &'static [&'static str],
    /// Where the user revokes or rotates keys (`kepr leaked`).
    pub keys_url: &'static str,
    /// Variables tools read the key from when they reach this host through
    /// the gate's egress proxy (P2.1), e.g. `GH_TOKEN` for `gh`. Empty for
    /// providers reached by base URL only.
    pub egress_env: &'static [&'static str],
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "anthropic",
        host: "api.anthropic.com",
        header: Some("x-api-key"),
        prefixes: &["sk-ant-"],
        name_hints: &["ANTHROPIC", "CLAUDE"],
        keys_url: "https://console.anthropic.com/settings/keys",
        egress_env: &[],
    },
    Provider {
        name: "openai",
        host: "api.openai.com",
        header: None,
        prefixes: &["sk-proj-", "sk-svcacct-", "sk-admin-"],
        name_hints: &["OPENAI"],
        keys_url: "https://platform.openai.com/api-keys",
        egress_env: &[],
    },
    Provider {
        name: "xai",
        host: "api.x.ai",
        header: None,
        prefixes: &["xai-"],
        name_hints: &["XAI", "GROK"],
        keys_url: "https://console.x.ai",
        egress_env: &[],
    },
    Provider {
        name: "google",
        host: "generativelanguage.googleapis.com",
        header: Some("x-goog-api-key"),
        prefixes: &["AIza"],
        name_hints: &["GEMINI", "GOOGLE"],
        keys_url: "https://aistudio.google.com/app/apikey",
        egress_env: &[],
    },
    Provider {
        name: "mistral",
        host: "api.mistral.ai",
        header: None,
        prefixes: &[],
        name_hints: &["MISTRAL"],
        keys_url: "https://console.mistral.ai/api-keys",
        egress_env: &[],
    },
    Provider {
        name: "deepseek",
        host: "api.deepseek.com",
        header: None,
        prefixes: &[],
        name_hints: &["DEEPSEEK"],
        keys_url: "https://platform.deepseek.com/api_keys",
        egress_env: &[],
    },
    Provider {
        name: "groq",
        host: "api.groq.com",
        header: None,
        prefixes: &["gsk_"],
        name_hints: &["GROQ"],
        keys_url: "https://console.groq.com/keys",
        egress_env: &[],
    },
    Provider {
        name: "openrouter",
        host: "openrouter.ai",
        header: None,
        prefixes: &["sk-or-"],
        name_hints: &["OPENROUTER"],
        keys_url: "https://openrouter.ai/settings/keys",
        egress_env: &[],
    },
    Provider {
        name: "github",
        host: "api.github.com",
        header: None,
        prefixes: &["ghp_", "github_pat_", "gho_", "ghu_", "ghs_"],
        name_hints: &["GITHUB", "GH"],
        keys_url: "https://github.com/settings/tokens",
        egress_env: &["GH_TOKEN", "GITHUB_TOKEN"],
    },
    // T2.04 (batch: aws): presets for common CLIs through the egress proxy.
    Provider {
        name: "stripe",
        host: "api.stripe.com",
        header: None,
        prefixes: &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
        name_hints: &["STRIPE"],
        keys_url: "https://dashboard.stripe.com/apikeys",
        egress_env: &["STRIPE_API_KEY"],
    },
    Provider {
        name: "npm",
        host: "registry.npmjs.org",
        header: None,
        prefixes: &["npm_"],
        name_hints: &["NPM"],
        keys_url: "https://docs.npmjs.com/revoking-access-tokens",
        egress_env: &["NPM_TOKEN"],
    },
    Provider {
        // `kepr agent add --for gcloud` also binds GCLOUD_HOSTS; the gate
        // intercepts any bound host under googleapis.com (DOMAINS).
        name: "gcloud",
        host: "www.googleapis.com",
        header: None,
        prefixes: &["ya29."],
        name_hints: &["GCLOUD", "GCP", "CLOUDSDK"],
        keys_url: "https://console.cloud.google.com/apis/credentials",
        egress_env: &["CLOUDSDK_AUTH_ACCESS_TOKEN"],
    },
    Provider {
        // Docker Hub's token service: registry clients send the login
        // (`user:token`, Basic) here and use the short-lived token it
        // returns on registry-1.docker.io.
        name: "docker",
        host: "auth.docker.io",
        header: Some(BASIC_AUTH),
        prefixes: &["dckr_pat_"],
        name_hints: &["DOCKER", "DOCKERHUB"],
        keys_url: "https://app.docker.com/settings/personal-access-tokens",
        egress_env: &[],
    },
];

/// `Provider::header` sentinel for `Authorization: Basic`: a colon never
/// appears in a header name, so it can't clash with a real header.
pub const BASIC_AUTH: &str = ":basic";

/// T2.04: providers whose key works on every host under a domain. The
/// gate intercepts a CONNECT to such a host when the session's key for
/// the provider is bound to that exact host (the daemon decides).
pub const DOMAINS: &[(&str, &str)] = &[("gcloud", "googleapis.com")];

/// More hosts `--for gcloud` binds besides `www.googleapis.com`: the
/// services `gcloud` most often calls.
pub const GCLOUD_HOSTS: &[&str] = &[
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "storage.googleapis.com",
    "iam.googleapis.com",
    "serviceusage.googleapis.com",
    "container.googleapis.com",
    "run.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "pubsub.googleapis.com",
    "bigquery.googleapis.com",
    "sqladmin.googleapis.com",
];

/// The `DOMAINS` provider `host` is under, if any (never the bare domain).
pub fn under_domain(host: &str) -> Option<&'static str> {
    DOMAINS
        .iter()
        .find(|(_, d)| {
            host.strip_suffix(d)
                .and_then(|h| h.strip_suffix('.'))
                .is_some_and(|sub| !sub.is_empty())
        })
        .map(|(p, _)| *p)
}

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
                Some(BASIC_AUTH) => Inject::Basic,
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
}
