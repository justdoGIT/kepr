//! Launch environment and explicit sandbox compatibility policy.

use std::collections::{HashMap, HashSet};

use crate::cli_agent_adapters::{Adapter, Value};

const RUNTIME_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "SHELL",
    "TERM",
    "COLORTERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
];

fn inherited_allowed(harness: &str, key: &str) -> bool {
    RUNTIME_VARS.contains(&key)
        || matches!(
            (harness, key),
            ("codex", "CODEX_HOME") | ("omp", "PI_CODING_AGENT_DIR")
        )
}

fn unsafe_runtime_control(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    key.starts_with("LD_")
        || key.starts_with("DYLD_")
        || key.starts_with("GIT_CONFIG")
        || matches!(
            key.as_str(),
            "NODE_OPTIONS"
                | "NODE_PATH"
                | "PYTHONPATH"
                | "PYTHONHOME"
                | "PYTHONSTARTUP"
                | "RUBYOPT"
                | "RUBYLIB"
                | "PERL5OPT"
                | "PERL5LIB"
                | "PERLLIB"
                | "BASH_ENV"
                | "ENV"
                | "ZDOTDIR"
                | "SHELLOPTS"
                | "BASHOPTS"
                | "PROMPT_COMMAND"
                | "JAVA_TOOL_OPTIONS"
                | "_JAVA_OPTIONS"
                | "JDK_JAVA_OPTIONS"
                | "CLASSPATH"
                | "DOTNET_STARTUP_HOOKS"
                | "DOTNET_ADDITIONAL_DEPS"
                | "SSLKEYLOGFILE"
                | "GIT_SSH"
                | "GIT_SSH_COMMAND"
                | "GIT_ASKPASS"
                | "SSH_ASKPASS"
        )
}

pub(crate) fn reserved_environment_name(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    unsafe_runtime_control(key)
        || RUNTIME_VARS.contains(&upper.as_str())
        || upper.starts_with("KEPR_")
        || upper.starts_with("XDG_")
        || crate::cli_agent_egress::PROXY_VARS
            .iter()
            .any(|k| k.eq_ignore_ascii_case(key))
        || crate::cli_agent_db::DB_VARS.contains(&upper.as_str())
        || matches!(
            upper.as_str(),
            "CODEX_HOME"
                | "PI_CODING_AGENT_DIR"
                | "AWS_REGION"
                | "AWS_DEFAULT_REGION"
                | "DOCKER_CONFIG"
                | "REGISTRY_AUTH_FILE"
                | "NPM_CONFIG_USERCONFIG"
                | "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE"
                | "CLOUDSDK_CONFIG"
                | "GOOGLE_APPLICATION_CREDENTIALS"
                | "KUBECONFIG"
                | "AWS_CONFIG_FILE"
                | "AWS_SHARED_CREDENTIALS_FILE"
                | "AWS_PROFILE"
                | "AWS_DEFAULT_PROFILE"
                | "AWS_WEB_IDENTITY_TOKEN_FILE"
                | "AWS_ROLE_ARN"
                | "SSH_AUTH_SOCK"
                | "GIT_TERMINAL_PROMPT"
        )
}

pub(super) fn validate_final_env(env: &[(String, String)], gate_port: u16) -> Result<(), String> {
    let gate = format!("http://127.0.0.1:{gate_port}");
    let safe_git = crate::cli_aws::presets::validated_git_controls(env);
    let mut seen = HashMap::new();
    for (key, value) in env {
        if (unsafe_runtime_control(key) && !(safe_git && key.starts_with("GIT_CONFIG")))
            || kepr_core::leak::looks_like_key(value.as_bytes())
        {
            return Err(
                "launch environment contains a forbidden runtime control or unsealed credential"
                    .into(),
            );
        }
        let upper = key.to_ascii_uppercase();
        match upper.as_str() {
            "KEPR_GATE_URL" | "HTTPS_PROXY" | "HTTP_PROXY" | "ALL_PROXY" if value != &gate => {
                return Err("launch environment attempts to bypass the session gate".into());
            }
            "NO_PROXY" if value != "127.0.0.1,localhost" => {
                return Err("launch environment expands the proxy bypass list".into());
            }
            _ => {}
        }
        if let Some(previous) = seen.insert(key.as_str(), value.as_str()) {
            if previous != value && reserved_environment_name(key) {
                return Err("launch environment contains conflicting runtime controls".into());
            }
        }
    }
    Ok(())
}

/// Inherit only declared runtime/configuration variables, then install the
/// adapter's gate URLs and placeholders. Unrelated credentials, proxy controls,
/// loader controls and identifying environment metadata never pass through.
pub fn build_env(
    adapter: &Adapter,
    port: u16,
    placeholders: &HashMap<String, String>,
    inherited: impl Iterator<Item = (String, String)>,
) -> Vec<(String, String)> {
    let mut shadowed: HashSet<&str> = adapter.env.iter().map(|v| v.name).collect();
    shadowed.extend(adapter.creds.iter().map(|(_, c)| *c));
    let mut env: Vec<_> = inherited
        .filter(|(key, value)| {
            (inherited_allowed(adapter.harness, key)
                || (matches!(key.as_str(), "AWS_REGION" | "AWS_DEFAULT_REGION")
                    && placeholders
                        .keys()
                        .any(|provider| provider.starts_with("aws:"))))
                && !shadowed.contains(key.as_str())
                && !kepr_core::leak::looks_like_key(value.as_bytes())
        })
        .collect();
    for variable in adapter.env {
        let value = match variable.value {
            Value::Placeholder(credential) => adapter
                .creds
                .iter()
                .find(|(_, name)| *name == credential)
                .and_then(|(provider, _)| placeholders.get(*provider))
                .cloned(),
            Value::BaseUrl(provider, suffix) => placeholders
                .contains_key(provider)
                .then(|| format!("http://127.0.0.1:{port}/{provider}{suffix}")),
        };
        if let Some(value) = value {
            env.push((variable.name.to_string(), value));
        }
    }
    env
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// Only selected by explicit `--compatibility --no-sandbox`.
    Off,
    /// Explicit `--compatibility`: use the sandbox when available.
    Auto,
    /// Protected default: refuse to run without the sandbox.
    Required,
}

pub(super) fn after_probe(
    mode: SandboxMode,
    isolate_net: bool,
    result: Result<(), String>,
) -> Result<bool, String> {
    match result {
        Ok(()) => Ok(true),
        Err(error) if mode == SandboxMode::Auto && !isolate_net => {
            crate::cli_ui::warn(&format!(
                "compatibility mode: sandbox unavailable ({error}); running without it"
            ));
            Ok(false)
        }
        Err(error) => Err(format!(
            "agent sandbox unavailable: {error} (see `kepr doctor`); \
             protected launch was stopped"
        )),
    }
}

pub(super) fn decide_sandbox(mode: SandboxMode, isolate_net: bool) -> Result<bool, String> {
    validate_controls(
        mode,
        std::env::var("KEPR_LANDLOCK").ok().as_deref(),
        std::env::var("KEPR_SANDBOX_DBUS").ok().as_deref(),
    )?;
    if mode == SandboxMode::Off {
        return if isolate_net {
            Err("--isolate-net needs the sandbox; drop --no-sandbox".into())
        } else {
            Ok(false)
        };
    }
    after_probe(
        mode,
        isolate_net,
        crate::cli_agent_sandbox::probe(isolate_net),
    )
}

pub(super) fn validate_controls(
    mode: SandboxMode,
    landlock: Option<&str>,
    dbus: Option<&str>,
) -> Result<(), String> {
    if mode == SandboxMode::Required && (landlock == Some("0") || dbus == Some("allow")) {
        return Err("protected launch rejects disabled Landlock or desktop keyring isolation; remove the override or explicitly select --compatibility".into());
    }
    Ok(())
}

pub(super) fn confirm_privacy(
    requested: Option<kepr_core::privacy::Preset>,
    active: Option<kepr_core::privacy::Preset>,
) -> Result<(), String> {
    if requested.is_some() && requested != active {
        return Err("protected launch stopped: daemon/gate did not confirm the requested privacy preset; update both binaries before relaunching".into());
    }
    Ok(())
}

pub(super) fn harness_sandbox(harness: &str, mode: SandboxMode) -> Result<SandboxMode, String> {
    match (harness, mode) {
        ("codex", SandboxMode::Off) => {
            Err("Codex protection requires the sandbox; omit --no-sandbox".into())
        }
        ("codex", _) => Ok(SandboxMode::Required),
        _ => Ok(mode),
    }
}
