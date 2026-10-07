// cli_policy/ — the `policy` ticket batch, CLI side: `kepr policy`
// (T6.11), `kepr report access` (T6.12). Registered in cli_more.rs.

mod policy;
mod report;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_policy::PolicyRequest;

pub const VERBS: &[&str] = &["policy", "report"];

pub const HELP: &str = "  policy test FILE                     run the [[test]] cases of a policy.toml (allow / deny per case)
  policy status | policy reload        the policy the daemon enforces (~/.config/kepr/policy.toml or
                                       /etc/kepr/policy.toml); deny by default once the file exists
  report access KEY                    every path KEY can take: gate bindings, shares sent, agent
                                       gates and reads (audit log), aliases, sync devices, policy
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "policy" => policy::cmd_policy(args),
        "report" => report::cmd_report(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}

fn send(req: PolicyRequest) -> Response {
    crate::client::send_request(&Request::Policy(req)).unwrap_or_else(Response::fail)
}

/// Arguments without the global output flags (`--json`, `--color`, …).
fn plain_args(args: &[String]) -> Vec<&str> {
    args.iter()
        .map(String::as_str)
        .filter(|a| !matches!(*a, "--json" | "--color" | "--no-color"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_lines_are_indented_and_end_in_newline() {
        assert!(HELP.ends_with('\n'));
        assert!(HELP.lines().all(|l| l.starts_with("  ")));
        for v in VERBS {
            assert!(HELP.contains(v), "{v} missing from help");
            assert!(!crate::cli_extra::VERBS.contains(v), "{v} collides");
        }
    }
}
