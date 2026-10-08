// cli_leaked.rs — `kepr leaked NAME [--yes]` (agent vault P9.8): a key is
// known to be exposed. The daemon stops every agent gate of this user,
// deletes the credential and its history, and records an incident in
// the audit chain. kepr can't revoke most keys at the provider, so this
// says where to do it; `--rotate` (T9.09) replaces an AWS IAM key through
// the IAM API instead (see cli_aws/leaked.rs).

use std::io::{BufRead, IsTerminal};

use kepr_core::protocol::{Request, Response};
use kepr_core::providers;

use crate::{cli_mode, cli_ui, client};

fn confirmed(name: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("Delete {name} and stop all agent sessions? [y/N] ");
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    matches!(line.trim(), "y" | "Y" | "yes")
}

pub fn cmd_leaked(name: &str, yes: bool, rotate: bool) -> Response {
    let name = name.to_uppercase();
    if !yes && !confirmed(&name) {
        return Response::fail("not confirmed (pass --yes)");
    }
    // T9.09: `--rotate` reads what it needs before the value is deleted.
    let plan = rotate.then(|| crate::cli_aws::leaked::plan(&name));
    let r = client::send_request(&Request::Leaked { name }).unwrap_or_else(Response::fail);
    let after = match (&r, plan) {
        (Response::LeakedOk { name, hosts, .. }, Some(p)) => {
            Some(crate::cli_aws::leaked::finish_for(name, p, hosts))
        }
        _ => None,
    };
    let failed = after
        .as_ref()
        .and_then(|a| a.error.as_ref())
        .map(|e| Response::fail(format!("deleted from kepr, but {e}")));
    if cli_mode::json_mode() {
        return failed.unwrap_or(r);
    }
    if let Response::LeakedOk {
        name,
        gates_stopped,
        hosts,
    } = &r
    {
        cli_ui::ok(&format!(
            "{name} deleted with its history; {gates_stopped} agent session(s) stopped; incident recorded"
        ));
        let urls: Vec<&str> = match &after {
            Some(a) => {
                if let Some(done) = &a.rotated {
                    cli_ui::ok(&format!(
                        "{name} rotated at the provider: new key {} stored; old key {} deleted",
                        crate::cli_aws::rotate_iam::short(&done.new_id),
                        crate::cli_aws::rotate_iam::short(&done.old_id)
                    ));
                    return r;
                }
                if let Some(n) = &a.note {
                    cli_ui::info(n);
                }
                a.revoke_urls.clone()
            }
            None => hosts
                .iter()
                .filter_map(|h| providers::by_host(h))
                .map(|p| p.keys_url)
                .collect(),
        };
        if urls.is_empty() {
            cli_ui::warn("now revoke the key with the service that issued it");
        } else {
            cli_ui::warn(&format!("now revoke the key at: {}", urls.join(", ")));
        }
        cli_ui::info(&format!(
            "then store the new one (kepr agent add {name} or kepr set {name}); \
             past use: journalctl -t kepr-daemon KEPR_NAME={name}"
        ));
    }
    failed.unwrap_or(r)
}
