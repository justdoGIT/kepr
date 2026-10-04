// cli_leaked.rs — `kepr leaked NAME [--yes]` (agent vault P9.8): a key is
// known to be exposed. The daemon stops every agent gate of this user,
// deletes the credential and its history, and records an incident in
// the audit chain. kepr can't revoke a key at the provider, so this
// says where to do it.

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

pub fn cmd_leaked(name: &str, yes: bool) -> Response {
    let name = name.to_uppercase();
    if !yes && !confirmed(&name) {
        return Response::fail("not confirmed (pass --yes)");
    }
    let r = client::send_request(&Request::Leaked { name }).unwrap_or_else(Response::fail);
    if cli_mode::json_mode() {
        return r;
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
        let urls: Vec<&str> = hosts
            .iter()
            .filter_map(|h| providers::by_host(h))
            .map(|p| p.keys_url)
            .collect();
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
    r
}
