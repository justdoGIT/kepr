// cli_agent_run.rs — `kepr agent run HARNESS [--port N] [-- ARGV...]`
// (T1.13). Asks the daemon to start a kepr-gate for this process, then
// execs the harness with gate URLs and placeholders in place of keys.
// exec keeps the pid, so the gate's --owner-pid watch ends the gate
// when the harness exits.

use std::collections::{HashMap, HashSet};
use std::os::unix::process::CommandExt;
use std::process::Command;

use kepr_core::gate_protocol::{GateLimits, GateRoute};
use kepr_core::protocol::{Request, Response};

use crate::cli_agent_adapters::{self, Adapter, Value};
use crate::client;

/// The caller's sealed credentials.
pub fn sealed_creds() -> Result<Vec<kepr_core::protocol::CredInfo>, String> {
    match client::send_request(&Request::List)? {
        Response::ListOk { credentials, .. } => Ok(credentials
            .into_iter()
            .filter(|c| c.sealed == Some(true))
            .collect()),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

pub fn routes_for(
    adapter: &Adapter,
    available: &HashSet<String>,
) -> Result<Vec<GateRoute>, String> {
    let routes: Vec<GateRoute> = adapter
        .creds
        .iter()
        .filter(|(_, cred)| available.contains(*cred))
        .enumerate()
        .map(|(i, (provider, cred))| GateRoute {
            provider: provider.to_string(),
            cred: cred.to_string(),
            slot: i as u16,
            target: None,
        })
        .collect();
    if routes.is_empty() {
        let wanted: Vec<&str> = adapter.creds.iter().map(|(_, c)| *c).collect();
        return Err(format!(
            "no sealed credential for {} — store one first: kepr agent add {}",
            adapter.harness,
            wanted.join(" (or) ")
        ));
    }
    Ok(routes)
}

/// The harness environment: inherited env minus every variable the
/// adapter controls and every credential NAME it uses, plus gate URLs
/// and placeholders for the credentials that are available.
/// `placeholders` is keyed by provider (as returned in GateStarted).
pub fn build_env(
    adapter: &Adapter,
    port: u16,
    placeholders: &HashMap<String, String>,
    inherited: impl Iterator<Item = (String, String)>,
) -> Vec<(String, String)> {
    let mut drop: HashSet<&str> = adapter.env.iter().map(|v| v.name).collect();
    drop.extend(adapter.creds.iter().map(|(_, c)| *c));
    let mut env: Vec<(String, String)> = inherited
        .filter(|(k, _)| !drop.contains(k.as_str()))
        .collect();
    let provider_of = |cred: &str| {
        adapter
            .creds
            .iter()
            .find(|(_, c)| *c == cred)
            .map(|(p, _)| *p)
    };
    for v in adapter.env {
        let value = match v.value {
            Value::Placeholder(c) => provider_of(c).and_then(|p| placeholders.get(p)).cloned(),
            Value::BaseUrl(p, suffix) => placeholders
                .contains_key(p)
                .then(|| format!("http://127.0.0.1:{port}/{p}{suffix}")),
        };
        if let Some(val) = value {
            env.push((v.name.to_string(), val));
        }
    }
    env
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// `--no-sandbox`
    Off,
    /// default: sandbox when the kernel allows it, warn otherwise
    Auto,
    /// `--strict-sandbox`: refuse to run without it
    Required,
}

/// Decide whether to sandbox, probing the kernel first.
fn decide_sandbox(mode: SandboxMode, isolate_net: bool) -> Result<bool, String> {
    if mode == SandboxMode::Off {
        return if isolate_net {
            Err("--isolate-net needs the sandbox; drop --no-sandbox".into())
        } else {
            Ok(false)
        };
    }
    match crate::cli_agent_sandbox::probe(isolate_net) {
        Ok(()) => Ok(true),
        Err(e) if mode == SandboxMode::Auto && !isolate_net => {
            crate::cli_ui::warn(&format!(
                "agent sandbox unavailable ({e}); running without it. \
                 `kepr doctor` shows why; --strict-sandbox refuses instead"
            ));
            Ok(false)
        }
        Err(e) => Err(format!(
            "agent sandbox unavailable: {e} (see `kepr doctor`)"
        )),
    }
}

pub fn cmd_run(
    harness: &str,
    port: Option<u16>,
    argv: &[String],
    mode: SandboxMode,
    isolate_net: bool,
    limits: GateLimits,
    session: &crate::cli_gatex::SessionOpts,
) -> Response {
    let adapter = match cli_agent_adapters::lookup(harness) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    let sandbox = match decide_sandbox(mode, isolate_net) {
        Ok(s) => s,
        Err(e) => return Response::fail(e),
    };
    let routes = sealed_creds().and_then(|creds| {
        let names: HashSet<String> = creds.iter().map(|c| c.name.clone()).collect();
        let mut routes = routes_for(adapter, &names)?;
        routes.extend(crate::cli_agent_egress::extra_routes(&routes, &creds));
        routes.extend(crate::cli_aws::session::routes(&routes, &creds)); // T2.02
        let db = crate::cli_agent_db::routes(&routes, &creds);
        routes.extend(db);
        let tunnels = crate::cli_gatex::tunnel::routes(&routes, &session.tunnels)?;
        routes.extend(tunnels);
        crate::cli_gatex::grant::apply(&mut routes, &session.grants)?;
        Ok(routes)
    });
    let routes = match routes {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    let all_routes = routes.clone();
    let req = Request::StartGate {
        routes,
        port: port.or(adapter.port),
        limits,
        tunnel: !isolate_net,
        record: session.record,
    };
    let (gate_port, placeholders, ca_pem, db_ports) = match client::send_request(&req) {
        Ok(Response::GateStarted {
            port,
            placeholders,
            extras,
            ..
        }) => {
            session.announce(extras.session.as_deref());
            crate::cli_policy::label_session(extras.session.as_deref(), harness); // T9.07
            (port, placeholders, extras.ca_pem, extras.db_ports)
        }
        Ok(Response::Err { error }) => return Response::fail(error),
        Ok(_) => return Response::fail("unexpected daemon response"),
        Err(e) => return Response::fail(e),
    };
    // Egress proxy (P2.1): drop inherited proxy/CA settings and the real
    // tokens the egress placeholders replace, then add ours.
    let shadowed = crate::cli_agent_egress::shadowed(&placeholders);
    let (inherited, withheld) = keep_safe_env(std::env::vars().filter(|(k, _)| {
        k != "KEPR_GATE_URL"
            && k != "KEPR_AGENT_HARNESS"
            && !crate::cli_agent_egress::PROXY_VARS.contains(&k.as_str())
            && !crate::cli_agent_db::DB_VARS.contains(&k.as_str())
            && !shadowed.contains(&k.as_str())
            && !crate::cli_aws::session::shadowed(&placeholders, k)
    }));
    if !withheld.is_empty() {
        crate::cli_ui::warn(&format!(
            "not passed to the agent (they hold real keys): {}; store them with `kepr agent add`",
            withheld.join(", ")
        ));
    }
    let mut env = build_env(adapter, gate_port, &placeholders, inherited.into_iter());
    env.extend(crate::cli_agent_db::env(
        &all_routes,
        &placeholders,
        &db_ports,
    ));
    env.extend(crate::cli_gatex::tunnel::env(&db_ports));
    // Lets harness plugins (plugins/omp, plugins/grok) find the gate.
    env.push((
        "KEPR_GATE_URL".into(),
        format!("http://127.0.0.1:{gate_port}"),
    ));
    // T6.11: policy.toml `agent` / `harness` rules match on this.
    env.push(("KEPR_AGENT_HARNESS".into(), harness.to_string()));
    if let Some(pem) = ca_pem {
        match crate::cli_agent_egress::env(gate_port, &pem, &placeholders) {
            Ok(e) => env.extend(e),
            Err(e) => return Response::fail(e),
        }
    }
    let aws_env = crate::cli_aws::session::env(&placeholders, &env); // T2.02
    env.extend(aws_env);
    let default_argv = [adapter.program.to_string()];
    let argv = if argv.is_empty() {
        &default_argv[..]
    } else {
        argv
    };
    if sandbox {
        match crate::cli_agent_sandbox::Plan::new(argv, env, gate_port, isolate_net) {
            Ok(mut plan) => {
                // Database and tunnel ports are relayed into an isolated netns too.
                plan.extra_ports = db_ports.values().copied().collect();
                crate::cli_agent_sandbox::run(plan)
            }
            Err(e) => return Response::fail(e),
        }
    }
    let err = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .envs(env)
        .exec();
    Response::fail(format!("exec {} failed: {err}", argv[0]))
}

/// Split inherited variables into those passed on and the names of those
/// withheld because their value looks like a real API key or private key
/// (an `OPENAI_API_KEY` exported in ~/.bashrc must not reach a Claude
/// session just because Claude doesn't use it).
pub fn keep_safe_env(
    vars: impl Iterator<Item = (String, String)>,
) -> (Vec<(String, String)>, Vec<String>) {
    let (mut keep, mut withheld) = (Vec::new(), Vec::new());
    for (k, v) in vars {
        if kepr_core::leak::looks_like_key(v.as_bytes()) {
            withheld.push(k);
        } else {
            keep.push((k, v));
        }
    }
    withheld.sort();
    (keep, withheld)
}

#[cfg(test)]
mod tests {

    #[test]
    fn real_keys_in_the_environment_are_withheld() {
        let vars = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            (
                "OPENAI_API_KEY".to_string(),
                "sk-proj-abcdefghijklmnopqrstuvwx".to_string(),
            ),
            (
                "GH".to_string(),
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789".to_string(),
            ),
        ];
        let (keep, withheld) = keep_safe_env(vars.into_iter());
        assert_eq!(keep, vec![("PATH".to_string(), "/usr/bin".to_string())]);
        assert_eq!(
            withheld,
            vec!["GH".to_string(), "OPENAI_API_KEY".to_string()]
        );
    }
    use super::*;

    fn claude() -> &'static Adapter {
        cli_agent_adapters::lookup("claude").unwrap()
    }

    #[test]
    fn real_key_in_shell_is_replaced_by_placeholder() {
        let mut ph = HashMap::new();
        ph.insert("anthropic".to_string(), "kepr-ph-x".to_string());
        let inherited = vec![
            ("ANTHROPIC_API_KEY".to_string(), "sk-ant-real".to_string()),
            (
                "ANTHROPIC_BASE_URL".to_string(),
                "https://evil.example".to_string(),
            ),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ];
        let env = build_env(claude(), 7000, &ph, inherited.into_iter());
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("ANTHROPIC_API_KEY"), Some("kepr-ph-x"));
        assert_eq!(
            get("ANTHROPIC_BASE_URL"),
            Some("http://127.0.0.1:7000/anthropic")
        );
        assert_eq!(get("PATH"), Some("/usr/bin"));
        assert!(!env.iter().any(|(_, v)| v == "sk-ant-real"));
        assert_eq!(
            env.iter().filter(|(k, _)| k == "ANTHROPIC_API_KEY").count(),
            1
        );
    }

    #[test]
    fn missing_credential_drops_its_variables() {
        let env = build_env(claude(), 7000, &HashMap::new(), std::iter::empty());
        assert!(env.is_empty());
    }

    #[test]
    fn routes_need_a_sealed_credential() {
        let none = HashSet::new();
        assert!(routes_for(claude(), &none)
            .unwrap_err()
            .contains("kepr agent add ANTHROPIC_API_KEY"));
        let some: HashSet<String> = ["ANTHROPIC_API_KEY".to_string()].into();
        let r = routes_for(claude(), &some).unwrap();
        assert_eq!((r[0].provider.as_str(), r[0].slot), ("anthropic", 0));
    }
}
