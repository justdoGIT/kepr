//! Provider route table (T1.08): where each provider lives. Base URLs
//! handed to harnesses look like `http://127.0.0.1:PORT/<name>/...`.
//! How the key is injected is not decided here: it comes from the
//! credential's binding, which the daemon returns with the value.

pub struct Provider {
    pub name: &'static str,
    pub host: &'static str,
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "anthropic",
        host: "api.anthropic.com",
    },
    Provider {
        name: "openai",
        host: "api.openai.com",
    },
    Provider {
        name: "xai",
        host: "api.x.ai",
    },
    Provider {
        name: "google",
        host: "generativelanguage.googleapis.com",
    },
    Provider {
        name: "mistral",
        host: "api.mistral.ai",
    },
    Provider {
        name: "deepseek",
        host: "api.deepseek.com",
    },
    Provider {
        name: "groq",
        host: "api.groq.com",
    },
    Provider {
        name: "openrouter",
        host: "openrouter.ai",
    },
];

pub fn lookup(name: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.name == name)
}

/// `"/anthropic/v1/messages"` → `Some(("anthropic", "/v1/messages"))`.
pub fn split_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix('/')?;
    if rest.is_empty() {
        return None;
    }
    match rest.find('/') {
        Some(i) => Some((&rest[..i], &rest[i..])),
        None => Some((rest, "/")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::binding::{validate_binding, Binding, Inject};

    #[test]
    fn hosts_are_valid_and_names_unique() {
        for p in PROVIDERS {
            let b = Binding {
                host: p.host.into(),
                port: 443,
                inject: Inject::Bearer,
            };
            assert!(validate_binding(&b).is_ok(), "{}", p.host);
            assert_eq!(PROVIDERS.iter().filter(|q| q.name == p.name).count(), 1);
        }
    }

    #[test]
    fn split_path_cases() {
        assert_eq!(split_path("/xai/v1/chat"), Some(("xai", "/v1/chat")));
        assert_eq!(split_path("/openai"), Some(("openai", "/")));
        assert_eq!(split_path("/"), None);
        assert!(lookup(split_path("/unknown/x").unwrap().0).is_none());
    }
}
