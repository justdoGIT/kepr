// cli_agent_cmd.rs — `kepr agent add|run|install|ls|revoke` (agent vault
// P1). Parsed separately from the main argv parser because the verbs
// take their own flags.
//
//   kepr agent add NAME [--for PROVIDER|host[:port]:inject]... [--stdin]
//   kepr agent run HARNESS [--port N] [--no-sandbox|--strict-sandbox] [--isolate-net] [-- ARGV...]
//   kepr agent install omp|grok [--port N]
//   kepr agent ls
//   kepr agent revoke NAME [--force]

use std::io::{BufRead, IsTerminal};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};

use crate::{cli_agent_detect, cli_agent_install, cli_agent_run, cli_input, cli_ui, client};

const USAGE: &str = "usage: kepr agent add NAME [--for PROVIDER]... | run HARNESS [--port N] [-- ARGV] | install omp|grok | ls | revoke NAME";

#[derive(Debug, Default, PartialEq)]
pub struct AgentArgs {
    pub verb: String,
    pub target: Option<String>,
    pub fors: Vec<String>,
    pub port: Option<u16>,
    pub stdin: bool,
    pub force: bool,
    pub no_sandbox: bool,
    pub strict_sandbox: bool,
    pub isolate_net: bool,
    pub argv: Vec<String>,
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
            "--stdin" => a.stdin = true,
            "--force" | "-f" => a.force = true,
            "--no-sandbox" => a.no_sandbox = true,
            "--strict-sandbox" => a.strict_sandbox = true,
            "--isolate-net" => a.isolate_net = true,
            "--" => {
                a.argv = raw[i + 1..].to_vec();
                break;
            }
            s if !s.starts_with('-') && a.target.is_none() => a.target = Some(s.to_string()),
            other => return Err(format!("unexpected argument: {other}\n{USAGE}")),
        }
        i += 1;
    }
    Ok(a)
}

fn read_value(from_stdin: bool, name: &str) -> ZeroString {
    if from_stdin || !std::io::stdin().is_terminal() {
        let mut s = String::new();
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
    let value = read_value(a.stdin, &name);
    if value.as_str().is_empty() {
        return Response::fail("empty value — nothing stored");
    }
    let specs: Vec<String> = if a.fors.is_empty() {
        match cli_agent_detect::detect(value.as_str()) {
            Some(p) => vec![p.to_string()],
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
        .map(|s| cli_agent_detect::binding_for(s))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(b) => b,
        Err(e) => return Response::fail(e),
    };
    let hosts: Vec<String> = bindings.iter().map(|b| b.host.clone()).collect();
    let req = Request::Set {
        name: name.clone(),
        value: Some(value),
        generate: None,
        ttl_secs: None,
        requires_consent: None,
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
                cli_agent_run::cmd_run(h, a.port, &a.argv, mode, a.isolate_net)
            }
            None => Response::fail("kepr agent run needs a HARNESS, e.g. kepr agent run claude"),
        },
        "install" => match a.target.as_deref() {
            Some(h) => cli_agent_install::cmd_install(h, a.port),
            None => Response::fail("kepr agent install needs omp or grok"),
        },
        "ls" | "list" => cmd_ls(),
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
    fn unknown_verb_is_an_error() {
        match main(&v(&["frobnicate"])) {
            Response::Err { error } => assert!(error.contains("unknown agent command")),
            other => panic!("{other:?}"),
        }
    }
}
