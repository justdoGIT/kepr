// cli_agent_cmd.rs — `kepr agent add|run|install|ls|revoke` (agent vault
// P1). Parsed separately from the main argv parser because the verbs
// take their own flags.
//
//   kepr agent add NAME [--for PROVIDER|host[:port]:inject]... [--stdin|--from-clipboard] [--requires-consent]
//   kepr agent run HARNESS [--port N] [--no-sandbox|--strict-sandbox] [--isolate-net] [-- ARGV...]
//   kepr agent install omp|grok|opencode|claude|codex [--port N]
//   kepr agent adopt [FILE...] [--yes] [--remove]
//   kepr agent ls
//   kepr agent revoke NAME [--force]

use std::io::{BufRead, IsTerminal};

use kepr_core::binding::Inject;
use kepr_core::gate_protocol::GateLimits;
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::sigv4_req::AwsKey;

use crate::{cli_agent_detect, cli_agent_install, cli_agent_run, cli_input, cli_ui, client};

const USAGE: &str = "usage: kepr agent add NAME [--for PROVIDER]... [--stdin|--from-clipboard] | run HARNESS [--port N] [--max-requests N] [--max-tokens N] [--rate N] [--max-requests-day N] [--max-tokens-day N] [-- ARGV] | install omp|grok|opencode|claude|codex | ls | revoke NAME";

#[derive(Debug, Default, PartialEq)]
pub struct AgentArgs {
    pub verb: String,
    pub target: Option<String>,
    pub fors: Vec<String>,
    pub port: Option<u16>,
    pub stdin: bool,
    pub from_clipboard: bool,
    pub force: bool,
    pub requires_consent: bool,
    pub yes: bool,
    pub remove: bool,
    pub files: Vec<String>,
    pub no_sandbox: bool,
    pub strict_sandbox: bool,
    pub isolate_net: bool,
    pub limits: GateLimits,
    /// Gate-batch session flags (`--tunnel`, …), see cli_gatex.
    pub session: crate::cli_gatex::SessionOpts,
    pub argv: Vec<String>,
}

fn number<T: std::str::FromStr>(raw: &[String], i: usize, flag: &str) -> Result<T, String> {
    raw.get(i)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("{flag} needs a positive number"))
}

pub fn parse(raw: &[String]) -> Result<AgentArgs, String> {
    let mut a = AgentArgs {
        verb: raw.first().ok_or(USAGE)?.clone(),
        ..Default::default()
    };
    let mut i = 1;
    while i < raw.len() {
        match raw[i].as_str() {
            "--for" => {
                i += 1;
                a.fors.push(
                    raw.get(i)
                        .ok_or("--for needs a provider or binding")?
                        .clone(),
                );
            }
            "--port" => {
                i += 1;
                let p = raw.get(i).ok_or("--port needs a number")?;
                a.port = Some(
                    p.parse()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or("--port must be 1-65535")?,
                );
            }
            "--max-requests" => {
                i += 1;
                a.limits.max_requests = Some(number(raw, i, "--max-requests")?);
            }
            "--max-tokens" => {
                i += 1;
                a.limits.max_tokens = Some(number(raw, i, "--max-tokens")?);
            }
            "--rate" => {
                i += 1;
                a.limits.per_minute = Some(number(raw, i, "--rate")?);
            }
            "--max-requests-day" => {
                i += 1;
                a.limits.max_requests_day = Some(number(raw, i, "--max-requests-day")?);
            }
            "--max-tokens-day" => {
                i += 1;
                a.limits.max_tokens_day = Some(number(raw, i, "--max-tokens-day")?);
            }
            f if crate::cli_gatex::SessionOpts::FLAGS.contains(&f) => i = a.session.take(raw, i)?,
            "--stdin" => a.stdin = true,
            "--from-clipboard" => a.from_clipboard = true,
            "--force" | "-f" => a.force = true,
            "--requires-consent" => a.requires_consent = true,
            "--yes" | "-y" => a.yes = true,
            "--remove" => a.remove = true,
            "--no-sandbox" => a.no_sandbox = true,
            "--strict-sandbox" => a.strict_sandbox = true,
            "--isolate-net" => a.isolate_net = true,
            "--" => {
                a.argv = raw[i + 1..].to_vec();
                break;
            }
            s if !s.starts_with('-') && a.verb == "adopt" => a.files.push(s.to_string()),
            s if !s.starts_with('-') && a.target.is_none() => a.target = Some(s.to_string()),
            other => return Err(format!("unexpected argument: {other}\n{USAGE}")),
        }
        i += 1;
    }
    if a.stdin && a.from_clipboard {
        return Err("use one of --stdin or --from-clipboard".into());
    }
    Ok(a)
}

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

pub fn main(raw: &[String]) -> Response {
    if raw.first().map(String::as_str) == Some("add-db") {
        return crate::cli_agent_db::cmd_add_db(&raw[1..]);
    }
    if raw.first().map(String::as_str) == Some("rotate-db") {
        return crate::cli_agent_db_rotate::cmd_rotate_db(&raw[1..]);
    }
    if let Some(r) = crate::cli_gatex::agent_verb(raw) {
        return r;
    }
    let a = match parse(raw) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    match a.verb.as_str() {
        "add" => cmd_add(&a),
        "run" => match a.target.as_deref() {
            Some(h) => {
                let mode = match (a.no_sandbox, a.strict_sandbox) {
                    (true, true) => {
                        return Response::fail("--no-sandbox and --strict-sandbox conflict")
                    }
                    (true, false) => cli_agent_run::SandboxMode::Off,
                    (false, true) => cli_agent_run::SandboxMode::Required,
                    (false, false) => cli_agent_run::SandboxMode::Auto,
                };
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
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_each_form() {
        let a = parse(&v(&[
            "add",
            "k",
            "--for",
            "xai",
            "--for",
            "h.example.com:bearer",
            "--stdin",
        ]))
        .unwrap();
        assert_eq!(
            (a.target.as_deref(), a.fors.len(), a.stdin),
            (Some("k"), 2, true)
        );
        let r = parse(&v(&[
            "run", "claude", "--port", "9000", "--", "claude", "-p", "hi",
        ]))
        .unwrap();
        assert_eq!(r.port, Some(9000));
        assert_eq!(r.argv, v(&["claude", "-p", "hi"]));
        assert!(parse(&v(&["run", "claude", "--port", "0"])).is_err());
        assert!(parse(&v(&["add", "a", "b"])).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn from_clipboard_parses_and_excludes_stdin() {
        let a = parse(&v(&["add", "K", "--from-clipboard"])).unwrap();
        assert!(a.from_clipboard && !a.stdin);
        let e = parse(&v(&["add", "K", "--from-clipboard", "--stdin"])).unwrap_err();
        assert_eq!(e, "use one of --stdin or --from-clipboard");
    }

    #[test]
    fn daily_caps_parse() {
        let r = parse(&v(&[
            "run",
            "claude",
            "--max-requests-day",
            "500",
            "--max-tokens-day",
            "200000",
        ]))
        .unwrap();
        assert_eq!(
            (r.limits.max_requests_day, r.limits.max_tokens_day),
            (Some(500), Some(200_000))
        );
        assert!(parse(&v(&["run", "claude", "--max-tokens-day", "lots"])).is_err());
    }

    #[test]
    fn unknown_verb_is_an_error() {
        match main(&v(&["frobnicate"])) {
            Response::Err { error } => assert!(error.contains("unknown agent command")),
            other => panic!("{other:?}"),
        }
    }
}
