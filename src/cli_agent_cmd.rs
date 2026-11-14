// cli_agent_cmd.rs — `kepr agent add|run|install|ls|revoke` (agent vault
// P1). Parsed separately from the main argv parser because the verbs
// take their own flags.

use std::io::{BufRead, IsTerminal};

#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::Command;

use kepr_core::binding::Inject;
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::sigv4_req::AwsKey;

use crate::{cli_agent_detect, cli_agent_install, cli_agent_run, cli_input, cli_ui, client};

#[path = "cli_agent_cmd_launch.rs"]
mod launch;

const USAGE: &str = "usage: kepr agent add NAME [--for PROVIDER]... [--stdin|--from-clipboard] | run HARNESS [--workspace PATH | --workspace-session SESSION] [--window] [--security-preset private-cloud|local-only] [--compatibility [--no-sandbox]] [--port N] [--max-requests N] [--max-tokens N] [--rate N] [--max-requests-day N] [--max-tokens-day N] [-- ARGV] | install omp|grok|opencode|claude|codex|cursor|copilot | doctor [--port N] [--json] | shim HARNESS [--dir DIR] [--remove] | ls | revoke NAME";

#[path = "cli_agent_args.rs"]
mod args;
pub use args::{parse, AgentArgs};

fn read_value(from_stdin: bool, name: &str) -> ZeroString {
    if from_stdin || !std::io::stdin().is_terminal() {
        let mut s = zeroize::Zeroizing::new(String::new());
        let _ = std::io::stdin().lock().read_line(&mut s);
        return ZeroString::from_string(s.trim_end_matches(['\n', '\r']).to_string());
    }
    cli_input::read_masked(&format!("Paste {name} (input hidden): "))
}

fn cmd_add(a: &AgentArgs) -> Response {
    let Some(name) = a.target.as_deref().map(str::to_uppercase) else {
        return Response::fail(
            "kepr agent add needs a NAME, e.g. kepr agent add ANTHROPIC_API_KEY",
        );
    };
    let value = match a.from_clipboard {
        true => match crate::cli_copy::take_clipboard() {
            Ok(v) => v,
            Err(e) => return Response::fail(e),
        },
        false => read_value(a.stdin, &name),
    };
    if value.as_str().is_empty() {
        return Response::fail("empty value — nothing stored");
    }
    let specs: Vec<String> = if a.fors.is_empty() {
        match kepr_core::providers::detect(Some(&name), value.as_str()) {
            Some(p) => vec![p.name.to_string()],
            None => {
                return Response::fail(
                    "can't tell which provider this key is for; add --for PROVIDER",
                )
            }
        }
    } else {
        a.fors.clone()
    };
    let bindings = match specs
        .iter()
        .map(|s| cli_agent_detect::bindings_for(s)) // T2.04: presets may bind more hosts
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(b) => b.concat(),
        Err(e) => return Response::fail(e),
    };
    let sigv4 = bindings.iter().any(|b| b.inject == Inject::Sigv4); // T2.02
    if bindings
        .iter()
        .any(|b| b.inject == Inject::CloudflareGateway)
        && kepr_core::cloudflare::GatewayCredential::parse(value.as_str()).is_err()
    {
        return Response::fail(
            "cloudflare requires a structured AI Gateway login; use `kepr agent add-cloudflare` to convert the standard token entry",
        );
    }
    if let (true, Err(e)) = (sigv4, AwsKey::parse(value.as_str())) {
        return Response::fail(e);
    }
    let hosts: Vec<String> = bindings.iter().map(|b| b.host.clone()).collect();
    let req = Request::Set {
        name: name.clone(),
        value: Some(value),
        generate: None,
        ttl_secs: None,
        requires_consent: a.requires_consent.then_some(true),
        requires_fido2: None,
        sealed: Some(true),
        bindings: Some(bindings),
    };
    match client::send_request(&req) {
        Ok(r @ Response::SetOk { .. }) => {
            cli_ui::ok(&format!(
                "stored {name} (sealed, bound to {})",
                hosts.join(", ")
            ));
            cli_ui::info("it can no longer be read back; agents use it through `kepr agent run`");
            if a.from_clipboard {
                cli_ui::ok("clipboard cleared");
            }
            r
        }
        Ok(r) => r,
        Err(e) => Response::fail(e),
    }
}

/// Hint after a failed `kepr get`: a sealed key is write-only by design,
/// so pointing the user at `kepr set` would be misleading.
pub fn get_failure_hint(name: &str) -> String {
    let sealed = matches!(
        client::send_request(&Request::List),
        Ok(Response::ListOk { credentials, .. })
            if credentials.iter().any(|c| c.name == name && c.sealed == Some(true))
    );
    let ssh = matches!(
        client::send_request(&Request::SshList),
        Ok(Response::SshListOk { keys }) if keys.iter().any(|k| k.name == name)
    );
    if sealed {
        format!("{name} is sealed (write-only): agents use it through `kepr agent run`")
    } else if ssh {
        format!("{name} is an SSH key (sign-only): use it through `kepr ssh-agent`")
    } else {
        format!("Set it with: kepr set {name}")
    }
}

/// `kepr panic`: stop every running gate for this user and, if the store
/// is passphrase-protected, lock it.
pub fn cmd_panic() -> Response {
    match client::send_request(&Request::Panic) {
        Ok(
            r @ Response::PanicOk {
                gates_stopped,
                locked,
            },
        ) => {
            cli_ui::ok(&format!("stopped {gates_stopped} agent gate(s)"));
            if locked {
                cli_ui::ok("credential store locked; run `kepr unlock` to resume");
            } else {
                cli_ui::info(
                    "store not passphrase-protected, so it stays unlocked (see `kepr lock`)",
                );
            }
            r
        }
        Ok(r) => r,
        Err(e) => Response::fail(e),
    }
}

fn cmd_ls() -> Response {
    let resp = match client::send_request(&Request::List) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    let Response::ListOk { credentials, .. } = resp else {
        return resp;
    };
    let sealed: Vec<_> = credentials
        .into_iter()
        .filter(|c| c.sealed == Some(true))
        .collect();
    if sealed.is_empty() {
        cli_ui::info("no sealed credentials — add one with: kepr agent add NAME");
    }
    for c in &sealed {
        println!(
            "{:<32} {}",
            c.name,
            c.bound_hosts.clone().unwrap_or_default().join(", ")
        );
    }
    let count = sealed.len();
    Response::ListOk {
        credentials: sealed,
        count,
    }
}

fn cmd_revoke(a: &AgentArgs) -> Response {
    let Some(name) = a.target.as_deref().map(str::to_uppercase) else {
        return Response::fail("kepr agent revoke needs a NAME");
    };
    if !a.force {
        if !std::io::stdin().is_terminal() {
            return Response::fail("refusing to revoke without a terminal; pass --force");
        }
        eprint!("Delete sealed credential {name}? It cannot be recovered. [y/N] ");
        let mut answer = String::new();
        let _ = std::io::stdin().lock().read_line(&mut answer);
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            return Response::fail("not revoked");
        }
    }
    match client::send_request(&Request::Delete { name: name.clone() }) {
        Ok(r @ Response::DeleteOk { .. }) => {
            cli_ui::ok(&format!("revoked {name}"));
            r
        }
        Ok(r) => r,
        Err(e) => Response::fail(e),
    }
}

#[cfg(unix)]
fn open_window(a: &AgentArgs) -> Response {
    let Some(harness) = a.target.as_deref() else {
        return Response::fail("kepr agent run needs a HARNESS before --window");
    };
    let source = a.session.workspace_source.as_deref().unwrap_or(".");
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return Response::fail(format!("cannot locate kepr for Rio: {error}")),
    };
    let title = format!("kepr {harness}");
    let mut command = Command::new("rio");
    command
        .arg("--working-dir")
        .arg(source)
        .arg("--title-placeholder")
        .arg(&title)
        .arg("--command")
        .arg(executable)
        .args(["agent", "run", harness]);
    if a.compatibility {
        command.arg("--compatibility");
    } else if let Some(id) = a.session.workspace_session.as_deref() {
        command.args(["--workspace-session", id]);
    } else {
        command.args(["--workspace", source]);
    }
    if let Some(preset) = a.security_preset.as_deref() {
        command.args(["--security-preset", preset]);
    }
    if a.no_sandbox {
        command.arg("--no-sandbox");
    }
    if a.isolate_net && a.compatibility {
        command.arg("--isolate-net");
    }
    if let Some(port) = a.port {
        command.args(["--port", &port.to_string()]);
    }
    for (flag, value) in [
        ("--max-requests", a.limits.max_requests),
        ("--max-tokens", a.limits.max_tokens),
        ("--rate", a.limits.per_minute.map(u64::from)),
        ("--max-requests-day", a.limits.max_requests_day),
        ("--max-tokens-day", a.limits.max_tokens_day),
    ] {
        if let Some(value) = value {
            command.args([flag, &value.to_string()]);
        }
    }
    for tunnel in &a.session.tunnels {
        command.args(["--tunnel", tunnel]);
    }
    for grant in &a.session.grants {
        command.args(["--grant", grant]);
    }
    for db_user in &a.session.db_users {
        command.args(["--db-user", db_user]);
    }
    if a.session.record {
        command.arg("--record");
    }
    if !a.argv.is_empty() {
        command.arg("--").args(&a.argv);
    }
    let error = command.exec();
    Response::fail(format!("Rio window launch failed: {error}"))
}

#[cfg(not(unix))]
fn open_window(_: &AgentArgs) -> Response {
    Response::fail("--window is only supported with the Rio Unix terminal")
}

pub fn main(raw: &[String]) -> Response {
    match raw.first().map(String::as_str) {
        Some("add-cloudflare") => {
            return crate::cli_agent_cloudflare::cmd_add_cloudflare(&raw[1..])
        }
        Some("add-db") => return crate::cli_agent_db::cmd_add_db(&raw[1..]),
        Some("add-kube") => return crate::cli_agent_kube::cmd_add_kube(&raw[1..]),
        Some("rotate-db") => return crate::cli_agent_db_rotate::cmd_rotate_db(&raw[1..]),
        Some("doctor") => return crate::cli_agent_doctor::cmd_doctor(&raw[1..]),
        Some("shim") => return crate::cli_agent_shim::cmd_shim(&raw[1..]),
        _ => {}
    }
    if let Some(r) = crate::cli_gatex::agent_verb(raw) {
        return r;
    }
    let mut a = match parse(raw) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    if a.verb == "run" && a.open_window && a.target.is_some() {
        return open_window(&a);
    }
    if a.verb == "run"
        && a.target.is_some()
        && !a.compatibility
        && a.session.workspace_session.is_none()
        && a.security_preset.as_deref() != Some("local-only")
    {
        let source = a
            .session
            .workspace_source
            .clone()
            .unwrap_or_else(|| ".".into());
        let session = match crate::cli_workspace::prepare_source(&source) {
            Ok(session) => session,
            Err(error) => return Response::fail(format!("workspace prepare failed: {error}")),
        };
        a.session.workspace_session = Some(session);
    }
    match a.verb.as_str() {
        "add" => cmd_add(&a),
        "run" => match a.target.as_deref() {
            Some(h) => {
                if let Some(response) = launch::preflight(&a) {
                    return response;
                }
                let mode = launch::sandbox_mode(&a);
                let (net, s) = (a.isolate_net, &a.session);
                cli_agent_run::cmd_run(h, a.port, &a.argv, mode, net, a.limits, s)
            }
            None => Response::fail("kepr agent run needs a HARNESS, e.g. kepr agent run claude"),
        },
        "install" => match a.target.as_deref() {
            Some(h) => cli_agent_install::cmd_install(h, a.port),
            None => Response::fail("kepr agent install needs a HARNESS, e.g. omp or claude"),
        },
        "ls" | "list" => cmd_ls(),
        "adopt" => crate::cli_agent_adopt::cmd_adopt(&a.files, a.yes, a.remove),
        "revoke" => cmd_revoke(&a),
        other => Response::fail(format!("unknown agent command '{other}'\n{USAGE}")),
    }
}

#[cfg(test)]
#[path = "cli_agent_cmd_tests.rs"]
mod tests;
