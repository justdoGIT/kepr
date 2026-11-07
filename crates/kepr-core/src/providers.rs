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
    /// `Some(BASIC_AUTH)` = `Authorization: Basic` (value `user:password`);
    /// `Some(BASIC_PASSWORD)` = Basic with the client's user name and the
    /// value as the password (T12.05).
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
        name: "agentrouter",
        host: "agentrouter.org",
        header: None,
        prefixes: &[],
        name_hints: &["AGENTROUTER"],
        keys_url: "https://agentrouter.org",
        egress_env: &["AGENTROUTER_API_KEY"],
    },
    Provider {
        name: crate::cloudflare::PROVIDER,
        host: crate::cloudflare::HOST,
        header: Some(CLOUDFLARE_GATEWAY),
        prefixes: &[],
        name_hints: &["CLOUDFLARE"],
        keys_url: "https://dash.cloudflare.com/profile/api-tokens",
        egress_env: &[crate::cloudflare::CREDENTIAL],
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
    // T12.06: git over HTTPS. `--for github` binds github.com too; git
    // reads the placeholder from git-credential-kepr, so no hints,
    // prefixes or variables (`detect` never picks this row).
    Provider {
        name: "git",
        host: "github.com",
        header: Some(BASIC_PASSWORD),
        prefixes: &[],
        name_hints: &[],
        keys_url: "https://github.com/settings/tokens",
        egress_env: &[],
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

/// T12.05: `Provider::header` sentinel for `Inject::BasicPassword`.
pub const BASIC_PASSWORD: &str = ":basic-password";

/// Structured Cloudflare credentials must never be sent as a raw header.
pub const CLOUDFLARE_GATEWAY: &str = ":cloudflare-gateway";

/// Exact DNS spellings retain their bounded legacy names; other hosts use
/// a disjoint, bounded digest namespace (including explicit ports).
pub fn git_cred_name(host: &str) -> String {
    use sha2::{Digest, Sha256};
    let host = host.to_ascii_lowercase();
    if host.len() <= 124 && host.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.') {
        return format!("GIT_{}", host.replace('.', "_").to_ascii_uppercase());
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut name = String::with_capacity(69);
    name.push_str("GIT2_");
    for b in Sha256::digest(host.as_bytes()) {
        name.push(HEX[(b >> 4) as usize] as char);
        name.push(HEX[(b & 15) as usize] as char);
    }
    name
}

/// T12.06: inside `kepr agent run`, `<GIT_PH_PREFIX><git_cred_name>`
/// holds the session placeholder git-credential-kepr hands to git.
pub const GIT_PH_PREFIX: &str = "KEPR_PH_";

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
                Some(BASIC_PASSWORD) => Inject::BasicPassword,
                Some(CLOUDFLARE_GATEWAY) => Inject::CloudflareGateway,
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
#[path = "providers_tests.rs"]
mod tests;
