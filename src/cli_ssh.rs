// cli_ssh.rs — `kepr ssh generate|import|list` (agent vault P2.4).
// Keys live in the daemon and are sign-only; `kepr ssh-agent`
// (cli_ssh_agent.rs) lets ssh/git use them.
//
//   kepr ssh generate NAME [--type ed25519|ecdsa] [--comment C] [--requires-consent]
//   kepr ssh import NAME FILE [--requires-consent]   (Ed25519 or ECDSA P-256)
//   kepr ssh list            (authorized_keys lines)
//   kepr ssh rotate NAME --host [USER@]HOST   (T11.21, cli_session/ssh_rotate.rs)

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::ssh_wire_ecdsa;

use crate::{cli_mode, cli_ui, client};

fn send(req: &Request) -> Response {
    client::send_request(req).unwrap_or_else(Response::fail)
}

fn print_key(r: Response) -> Response {
    if cli_mode::json_mode() {
        return r;
    }
    if let Response::SshKeyOk { public_line, .. } = &r {
        println!("{public_line}");
    }
    r
}

/// The words that are not flags or flag values.
fn positional(args: &[String]) -> Vec<&String> {
    let mut skip = false;
    args.iter()
        .filter(|a| {
            if skip {
                skip = false;
                return false;
            }
            skip = *a == "--comment" || *a == "--type";
            !a.starts_with('-')
        })
        .collect()
}

pub fn cmd_ssh(args: &[String]) -> Response {
    let flag = |f: &str| args.iter().any(|a| a == f);
    let consent = flag("--requires-consent").then_some(true);
    let value = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let comment = value("--comment");
    // T12.11: the daemon refuses anything but ed25519 / ecdsa.
    let key_type = value("--type").map(|t| t.to_lowercase());
    match positional(args).as_slice() {
        [verb, ..] if verb.as_str() == "rotate" => crate::cli_session::ssh_rotate::cmd(&args[1..]),
        [verb, name] if verb.as_str() == "generate" => {
            let comment = comment.unwrap_or_else(|| format!("kepr:{}", name.to_uppercase()));
            print_key(send(&Request::SshGenerate {
                name: name.to_uppercase(),
                comment,
                requires_consent: consent,
                key_type,
            }))
        }
        [verb, name, file] if verb.as_str() == "import" => {
            let pem = match std::fs::read_to_string(file.as_str()) {
                Ok(s) => ZeroString::from_string(s),
                Err(e) => return Response::fail(format!("{file}: {e}")),
            };
            let r = print_key(send(&Request::SshImport {
                name: name.to_uppercase(),
                private_key: pem,
                requires_consent: consent,
            }));
            if matches!(r, Response::SshKeyOk { .. }) {
                cli_ui::warn(&format!(
                    "{file} still holds the private key; delete it once you've checked the import"
                ));
            }
            r
        }
        [verb] if verb.as_str() == "list" => match send(&Request::SshList) {
            Response::SshListOk { keys } if cli_mode::json_mode() => Response::SshListOk { keys },
            Response::SshListOk { keys } => {
                for k in &keys {
                    let kind = ssh_wire_ecdsa::type_of_b64(&k.public_b64);
                    let line = format!("{kind} {} {}", k.public_b64, k.comment);
                    println!("{}  # {}", line.trim_end(), k.name);
                }
                if keys.is_empty() {
                    cli_ui::info("no SSH keys; create one with: kepr ssh generate NAME");
                }
                Response::SshListOk { keys }
            }
            other => other,
        },
        _ => Response::fail(
            "usage: kepr ssh generate NAME [--type ed25519|ecdsa] [--comment C] | import NAME FILE | list \
                 | rotate NAME --host [USER@]HOST",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_and_comment_values_are_not_positional() {
        let args: Vec<String> = ["generate", "K", "--type", "ecdsa", "--comment", "me", "-x"]
            .map(String::from)
            .to_vec();
        let pos: Vec<&str> = positional(&args).into_iter().map(String::as_str).collect();
        assert_eq!(pos, ["generate", "K"]);
    }
}
