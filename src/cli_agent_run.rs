// cli_agent_run.rs — `kepr agent run HARNESS [--workspace PATH] [--port N] [-- ARGV...]`
// (T1.13). Asks the daemon to start a kepr-gate for this process, then
// execs the harness with gate URLs and placeholders in place of keys.
// exec keeps the pid, so the gate's --owner-pid watch ends the gate
// when the harness exits.

use std::collections::{HashMap, HashSet};
use std::os::unix::process::CommandExt;
use std::process::Command;

use kepr_core::gate_protocol::{GateLimits, GateRoute};
use kepr_core::protocol::{Request, Response};

use crate::cli_agent_adapters::{self, Adapter};
use crate::client;

#[path = "cli_agent_launch.rs"]
mod launch;
pub(crate) use launch::reserved_environment_name;
pub use launch::{build_env, SandboxMode};
use launch::{decide_sandbox, harness_sandbox};

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

/// A protected workspace may run an explicitly supplied command even when no
/// usable model route exists. It receives no gate, credentials, or proxy; the
/// workspace sandbox remains the only execution surface.
fn run_workspace_command(
    private: crate::cli_workspace::launch::PreparedLaunch,
    adapter: &Adapter,
    harness: &str,
) -> ! {
    crate::cli_ui::warn(
        "protected workspace command: no provider gate was started; cloud credentials are unavailable",
    );
    let (inherited, withheld) = keep_safe_env(std::env::vars());
    if !withheld.is_empty() {
        crate::cli_ui::warn(&format!(
            "not passed to the workspace command (they hold real keys): {}",
            withheld.join(", ")
        ));
    }
    let mut env = build_env(adapter, 0, &HashMap::new(), inherited.into_iter());
    env.push(("KEPR_AGENT_HARNESS".into(), harness.into()));
    if let Err(error) = private.stage(harness, 0, None, &mut env) {
        eprintln!("kepr: {error}");
        std::process::exit(125);
    }
    if let Err(error) = launch::validate_final_env(&env, 0) {
        eprintln!("kepr: {error}");
        std::process::exit(125);
    }
    let argv = private.argv.clone();
    private.run(&argv, env, 0)
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
    let privacy = match crate::cli_privacy::config::for_launch(mode) {
        Ok(policy) => policy,
        Err(message) => return Response::fail(message),
    };
    let explicit_argv = !argv.is_empty();
    let default_argv = [adapter.program.to_string()];
    let argv = if argv.is_empty() {
        &default_argv[..]
    } else {
        argv
    };
    let private = match session.workspace_session.as_deref() {
        Some(id) if mode == SandboxMode::Required && isolate_net => {
            match crate::cli_workspace::launch::prepare(id, argv) {
                Ok(p) => Some(p),
                Err(e) => return Response::fail(e),
            }
        }
        Some(_) => return Response::fail("workspace session requires protected isolation"),
        None if mode == SandboxMode::Required => {
            return Response::fail("protected launch requires --workspace-session")
        }
        None => None,
    };
    let sandbox = if private.is_some() {
        true
    } else {
        match harness_sandbox(harness, mode).and_then(|m| decide_sandbox(m, isolate_net)) {
            Ok(s) => s,
            Err(e) => return Response::fail(e),
        }
    };
    let credentials = match sealed_creds() {
        Ok(credentials) => credentials,
        Err(_error) if private.is_some() && explicit_argv => {
            run_workspace_command(private.unwrap(), adapter, harness)
        }
        Err(error) => return Response::fail(error),
    };
    let codex = if harness == "codex" {
        match crate::cli_agent_codex::Config::load(argv) {
            Ok(c) => Some(c),
            Err(e) => return Response::fail(e),
        }
    } else {
        None
    };
    if mode == SandboxMode::Required
        && (!session.tunnels.is_empty()
            || !session.grants.is_empty()
            || !session.db_users.is_empty())
    {
        return Response::fail(
            "privacy sessions do not support uninspected database or tunnel routes",
        );
    }
    let routes: Result<Vec<GateRoute>, String> = (|| -> Result<Vec<GateRoute>, String> {
        let creds = &credentials;
        let names: HashSet<String> = creds.iter().map(|c| c.name.clone()).collect();
        let mut routes = if let Some(c) = &codex {
            c.routes(&names)?
        } else if harness == "omp" {
            if mode == SandboxMode::Required {
                crate::cli_agent_omp::privacy_routes(creds)?
            } else {
                crate::cli_agent_omp::routes(creds)?
            }
        } else {
            routes_for(adapter, &names)?
        };
        if mode != SandboxMode::Required {
            routes.extend(crate::cli_agent_egress::extra_routes(&routes, creds));
            routes.extend(crate::cli_aws::session::routes(&routes, creds)); // T2.02
            let db = crate::cli_agent_db::routes(&routes, creds);
            routes.extend(db);
            let kube = crate::cli_agent_kube::routes(&routes, creds); // T13.04
            routes.extend(kube);
            let tunnels = crate::cli_gatex::tunnel::routes(&routes, &session.tunnels)?;
            routes.extend(tunnels);
            crate::cli_gatex::grant::apply(&mut routes, &session.grants)?;
            crate::cli_gatex::dbuser::apply(&mut routes, &session.db_users)?; // T13.02
        }
        kepr_core::gate_protocol::validate_routes(&routes)?;
        Ok(routes)
    })();
    let routes = match routes {
        Ok(r) => r,
        Err(_error) if private.is_some() && explicit_argv => {
            run_workspace_command(private.unwrap(), adapter, harness)
        }
        Err(error) => return Response::fail(error),
    };
    let all_routes = routes.clone();
    let requested_privacy = privacy.as_ref().map(|p| p.preset);
    let req = Request::StartGate {
        routes,
        port: port.or(adapter.port),
        limits,
        tunnel: !isolate_net,
        record: session.record,
        harness: Some(adapter.harness.to_string()), // T7.10
        privacy,
    };
    let (gate_port, placeholders, ca_pem, db_ports) = match client::send_request(&req) {
        Ok(Response::GateStarted {
            port,
            placeholders,
            extras,
            ..
        }) => {
            if let Err(error) = launch::confirm_privacy(requested_privacy, extras.privacy) {
                return Response::fail(error);
            }
            session.announce(extras.session.as_deref());
            crate::cli_policy::label_session(extras.session.as_deref(), harness); // T9.07
            (port, placeholders, extras.ca_pem, extras.db_ports)
        }
        Ok(Response::Err { error }) if private.is_some() && explicit_argv => {
            let _ = error;
            run_workspace_command(private.unwrap(), adapter, harness)
        }
        Ok(Response::Err { error }) => return Response::fail(error),
        Ok(_) => return Response::fail("unexpected daemon response"),
        Err(error) => return Response::fail(error),
    };
    // Egress proxy (P2.1): drop inherited proxy/CA settings and the real
    // tokens the egress placeholders replace, then add ours.
    let shadowed = crate::cli_agent_egress::shadowed(&placeholders);
    let drop_var = |k: &str| {
        k == "KEPR_GATE_URL"
            || k == "KEPR_AGENT_HARNESS"
            || k.starts_with("KEPR_OMP_")
            || (harness == "omp" && all_routes.iter().any(|r| r.cred == k))
            || crate::cli_agent_egress::PROXY_VARS.contains(&k)
            || crate::cli_agent_db::DB_VARS.contains(&k)
            || shadowed.contains(&k)
            || crate::cli_aws::session::shadowed(&placeholders, k)
    };
    let (inherited, withheld) = keep_safe_env(std::env::vars().filter(|(k, _)| !drop_var(k)));
    if !withheld.is_empty() {
        crate::cli_ui::warn(&format!(
            "not passed to the agent (they hold real keys): {}; store them with `kepr agent add`",
            withheld.join(", ")
        ));
    }
    let mut env = build_env(adapter, gate_port, &placeholders, inherited.into_iter());
    if harness == "omp" && private.is_none() {
        let Some(home) = std::env::var_os("HOME") else {
            return Response::fail("HOME is required to locate OMP configuration");
        };
        let directory = crate::cli_agent_install::omp_agent_dir(
            std::path::Path::new(&home),
            std::env::var_os("PI_CODING_AGENT_DIR"),
            std::env::var_os("XDG_CONFIG_HOME"),
        );
        env.retain(|(name, _)| name != "PI_CODING_AGENT_DIR");
        env.push((
            "PI_CODING_AGENT_DIR".into(),
            directory.to_string_lossy().into_owned(),
        ));
    }
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
    if private.is_none() {
        if let Some(pem) = ca_pem.as_deref() {
            let kube = crate::cli_agent_kube::entries(&all_routes, &placeholders);
            match crate::cli_agent_egress::env(gate_port, pem, &placeholders, &kube) {
                Ok(e) => env.extend(e),
                Err(e) => return Response::fail(e),
            }
        }
    }
    let aws_env = crate::cli_aws::session::env(&placeholders, &env); // T2.02
    env.extend(aws_env);
    if harness == "omp" {
        match crate::cli_agent_omp::env(&all_routes, &placeholders) {
            Ok(vars) => env.extend(vars),
            Err(e) => return Response::fail(e),
        }
    }
    if let Some(private) = private.as_ref() {
        if let Err(e) = private.stage(harness, gate_port, ca_pem.as_deref(), &mut env) {
            return Response::fail(e);
        }
    }
    if let Err(error) = launch::validate_final_env(&env, gate_port) {
        return Response::fail(error);
    }
    let runtime_argv = private
        .as_ref()
        .map(|p| p.argv.clone())
        .unwrap_or_else(|| argv.to_vec());
    let configured_argv = codex.as_ref().map(|c| {
        if private.is_some() {
            c.private_argv(gate_port, &runtime_argv)
        } else {
            c.argv(gate_port, &runtime_argv)
        }
    });
    let argv = configured_argv.as_deref().unwrap_or(&runtime_argv);
    if let Some(private) = private {
        private.run(argv, env, gate_port);
    }
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
#[path = "cli_agent_run_tests.rs"]
mod tests;
