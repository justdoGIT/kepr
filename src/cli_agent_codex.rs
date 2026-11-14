// Codex stores its provider in config.toml. Environment overrides alone cannot
// redirect a custom provider, and cached ChatGPT auth must stay out of a session.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use serde::Deserialize;

#[path = "cli_agent_codex_profile.rs"]
mod profile;

#[derive(Deserialize, Default)]
struct ProviderConfig {
    base_url: Option<String>,
    env_key: Option<String>,
    requires_openai_auth: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    experimental_bearer_token: bool,
    #[serde(default, deserialize_with = "present")]
    auth: bool,
    #[serde(default, deserialize_with = "present")]
    gateway_oauth: bool,
}

fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(d).map(|_| true)
}

#[derive(Deserialize, Default)]
struct ConfigFile {
    model_provider: Option<String>,
    #[serde(default)]
    model_providers: HashMap<String, ProviderConfig>,
}

pub struct Config {
    name: String,
    provider: &'static str,
    credential: &'static str,
    suffix: String,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        Self::parse_layers(text, None)
    }

    fn parse_layers(text: &str, overlay: Option<&str>) -> Result<Self, String> {
        let mut file: ConfigFile =
            toml::from_str(text).map_err(|_| "cannot parse Codex provider configuration")?;
        if let Some(overlay) = overlay {
            let overlay: ConfigFile =
                toml::from_str(overlay).map_err(|_| "cannot parse selected Codex profile")?;
            file.model_provider = overlay.model_provider.or(file.model_provider);
            for (name, info) in overlay.model_providers {
                let original = file.model_providers.entry(name).or_default();
                original.base_url = info.base_url.or(original.base_url.take());
                original.env_key = info.env_key.or(original.env_key.take());
                original.requires_openai_auth =
                    info.requires_openai_auth.or(original.requires_openai_auth);
                original.experimental_bearer_token |= info.experimental_bearer_token;
                original.auth |= info.auth;
                original.gateway_oauth |= info.gateway_oauth;
            }
        }
        let name = file.model_provider.as_deref().unwrap_or("openai");
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("unsupported Codex provider name".into());
        }
        let default = ProviderConfig::default();
        let info = file.model_providers.get(name).unwrap_or(&default);
        if info.experimental_bearer_token || info.auth || info.gateway_oauth {
            return Err(
                "Codex provider uses another credential source; use env_key with a sealed key"
                    .into(),
            );
        }
        let (provider, credential) = match info.env_key.as_deref() {
            Some("AGENTROUTER_API_KEY") if info.requires_openai_auth != Some(true) => {
                ("agentrouter", "AGENTROUTER_API_KEY")
            }
            Some("SELORA_API_KEY") if info.requires_openai_auth != Some(true) => {
                ("selora", "SELORA_API_KEY")
            }
            Some("OPENAI_API_KEY") => ("openai", "OPENAI_API_KEY"),
            None if name == "openai" => ("openai", "OPENAI_API_KEY"),
            _ => return Err("Codex provider needs a supported sealed env_key".into()),
        };
        let host = kepr_core::providers::lookup(provider)
            .expect("declared provider")
            .host;
        let root = format!("https://{host}");
        let suffix = match info.base_url.as_deref() {
            Some(url) => url
                .strip_prefix(&root)
                .filter(|p| p.starts_with('/'))
                .ok_or("Codex provider URL does not match its sealed credential host")?,
            None if provider == "openai" => "/v1",
            None => return Err("Codex provider has no base_url".into()),
        };
        if !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            || suffix.split('/').any(|p| p == ".." || p == ".")
        {
            return Err("unsupported Codex provider URL path".into());
        }
        Ok(Self {
            name: name.to_string(),
            provider,
            credential,
            suffix: suffix.trim_end_matches('/').to_string(),
        })
    }

    pub fn load(argv: &[String]) -> Result<Self, String> {
        let selected = profile::selected_profile(argv)?;
        let base = std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".codex")))
            .ok_or("cannot locate Codex configuration")?;
        let text = profile::read(&base.join("config.toml"), false)?;
        match selected {
            Some(name) => {
                let overlay = profile::read(&base.join(format!("{name}.config.toml")), true)?;
                Self::parse_layers(&text, Some(&overlay))
            }
            None => Self::parse(&text),
        }
    }

    pub fn require_credential(&self, names: &HashSet<String>) -> Result<(), String> {
        if names.contains(self.credential) {
            Ok(())
        } else {
            Err(format!(
                "no sealed credential for the configured Codex provider — run: kepr agent add {} --for {}",
                self.credential, self.provider,
            ))
        }
    }

    pub fn routes(
        &self,
        names: &HashSet<String>,
    ) -> Result<Vec<kepr_core::gate_protocol::GateRoute>, String> {
        self.require_credential(names)?;
        Ok(vec![kepr_core::gate_protocol::GateRoute {
            provider: self.provider.into(),
            cred: self.credential.into(),
            slot: 0,
            target: None,
        }])
    }

    pub fn argv(&self, port: u16, argv: &[String]) -> Vec<String> {
        // -- ARGV also permits a diagnostic probe in place of Codex.
        if PathBuf::from(&argv[0])
            .file_name()
            .is_none_or(|n| n != "codex")
        {
            return argv.to_vec();
        }
        let url = format!("http://127.0.0.1:{port}/{}{}", self.provider, self.suffix);
        let mut out = vec![argv[0].clone()];
        let quote = |s: &str| serde_json::to_string(s).expect("string serialization");
        for entry in [
            "cli_auth_credentials_store=\"ephemeral\"".to_string(),
            format!("model_provider={}", quote(&self.name)),
            format!("model_providers.{}.name={}", self.name, quote(&self.name)),
            format!("model_providers.{}.base_url={}", self.name, quote(&url)),
            format!(
                "model_providers.{}.env_key={}",
                self.name,
                quote(self.credential)
            ),
            format!("model_providers.{}.requires_openai_auth=false", self.name),
            format!("model_providers.{}.wire_api=\"responses\"", self.name),
        ] {
            out.extend(["--config".to_string(), entry]);
        }
        out.extend_from_slice(&argv[1..]);
        out
    }

    /// Provider selection was read on the host. Private homes have no host
    /// profile files, so retain the pinned provider and explicit arguments only.
    pub(crate) fn private_argv(&self, port: u16, argv: &[String]) -> Vec<String> {
        if std::path::Path::new(&argv[0])
            .file_name()
            .is_none_or(|n| n != "codex")
        {
            return argv.to_vec();
        }
        let mut selected = vec![argv[0].clone()];
        let mut args = argv.iter().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--" {
                selected.push(arg.clone());
                selected.extend(args.cloned());
                break;
            }
            if matches!(arg.as_str(), "--profile" | "-p") {
                args.next();
                continue;
            }
            if arg.starts_with("--profile=") || (arg.starts_with("-p") && arg.len() > 2) {
                continue;
            }
            selected.push(arg.clone());
        }
        self.argv(port, &selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELORA: &str = r#"
model_provider = "selora"
[model_providers.selora]
base_url = "https://api.selora.lol/v1"
env_key = "SELORA_API_KEY"
requires_openai_auth = false
wire_api = "responses"
"#;

    #[test]
    fn selora_uses_its_sealed_key_and_local_gate() {
        let c = Config::parse(SELORA).expect("Selora must be supported");
        assert!(c
            .require_credential(&HashSet::from(["SELORA_API_KEY".into()]))
            .is_ok());
        assert!(c
            .require_credential(&HashSet::from(["AGENTROUTER_API_KEY".into()]))
            .is_err());
        let args = c.argv(7001, &["codex".into(), "--profile".into(), "selora".into()]);
        assert!(args.contains(
            &"model_providers.selora.base_url=\"http://127.0.0.1:7001/selora/v1\"".into()
        ));
        assert!(args.contains(&"model_providers.selora.env_key=\"SELORA_API_KEY\"".into()));
    }

    #[test]
    fn selected_profile_grants_only_its_provider_credential() {
        let c = Config::parse(SELORA).unwrap();
        let names = HashSet::from([
            "OPENAI_API_KEY".into(),
            "AGENTROUTER_API_KEY".into(),
            "SELORA_API_KEY".into(),
        ]);
        let routes = c.routes(&names).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].provider, "selora");
        assert_eq!(routes[0].cred, "SELORA_API_KEY");
    }

    #[test]
    fn separate_profile_overlays_provider_selection_and_rechecks_host() {
        let base = format!(
            "{}{}",
            ROUTER,
            SELORA.replace("model_provider = \"selora\"", "")
        );
        let c = Config::parse_layers(&base, Some("model_provider='selora'\nmodel='gpt-6-astra'"))
            .unwrap();
        assert_eq!(c.provider, "selora");
        assert!(Config::parse_layers(&base, Some("model_provider='selora'\n[model_providers.selora]\nbase_url='https://evil.example/v1'")).is_err());
        assert!(Config::parse_layers(&base, Some("model_provider='selora'\n[model_providers.selora]\nexperimental_bearer_token='synthetic'")).is_err());
    }

    const ROUTER: &str = r#"
model_provider = "AgentRouter"
[model_providers.AgentRouter]
base_url = "https://agentrouter.org/v1"
env_key = "AGENTROUTER_API_KEY"
wire_api = "responses"
"#;

    #[test]
    fn configured_provider_uses_its_sealed_key_and_the_gate() {
        let c = Config::parse(ROUTER).unwrap();
        assert!(c
            .require_credential(&HashSet::from(["OPENAI_API_KEY".into()]))
            .is_err());
        assert!(c
            .require_credential(&HashSet::from(["AGENTROUTER_API_KEY".into()]))
            .is_ok());
        let args = c.argv(
            7654,
            &["/bin/codex".into(), "exec".into(), "example".into()],
        );
        assert!(args.contains(&"model_provider=\"AgentRouter\"".to_string()));
        assert!(args.contains(
            &"model_providers.AgentRouter.base_url=\"http://127.0.0.1:7654/agentrouter/v1\""
                .to_string()
        ));
        assert!(args.contains(&"cli_auth_credentials_store=\"ephemeral\"".to_string()));
        assert_eq!(&args[args.len() - 2..], ["exec", "example"]);
        assert!(!args.iter().any(|s| s.contains("https://")));
        assert_eq!(
            c.argv(1, &["python3".into(), "probe.py".into()]),
            ["python3", "probe.py"]
        );
    }

    #[test]
    fn default_openai_uses_environment_auth_without_the_login_cache() {
        let c = Config::parse("").unwrap();
        let args = c.argv(9000, &["codex".into()]);
        assert!(args.contains(&"model_providers.openai.env_key=\"OPENAI_API_KEY\"".to_string()));
        assert!(args.contains(&"model_providers.openai.requires_openai_auth=false".to_string()));
    }

    #[test]
    fn invalid_configuration_never_echoes_its_contents() {
        let marker = "synthetic-secret-do-not-echo";
        let bad = format!("model_provider = '{marker}");
        assert!(!Config::parse(&bad).err().unwrap().contains(marker));
        for url in [
            "http://agentrouter.org/v1",
            "https://agentrouter.org.evil.example/v1",
            "https://agentrouter.org:443/v1",
            "https://agentrouter.org/v1?token=synthetic",
            "https://agentrouter.org/../v1",
        ] {
            assert!(Config::parse(&ROUTER.replace("https://agentrouter.org/v1", url)).is_err());
        }
        assert!(
            Config::parse(&format!("{ROUTER}\nexperimental_bearer_token='synthetic'")).is_err()
        );
        assert!(Config::parse(&format!(
            "{ROUTER}\n[model_providers.AgentRouter.auth]\ncommand='example'"
        ))
        .is_err());
    }
}
