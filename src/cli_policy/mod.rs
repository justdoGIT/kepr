// cli_policy/ — the `policy` ticket batch, CLI side: `kepr policy`
// (T6.11), `kepr report access` (T6.12), webhooks (`notify`) and
// `kepr health --notify` (T6.08), `kepr audit forward` (T7.14),
// `kepr alerts` (T7.15), `kepr anomaly` (T7.13).
// Registered in cli_more.rs.

mod alerts;
mod alerts_cmd;
mod anomaly;
mod anomaly_cmd;
mod forward;
mod health;
mod notify;
mod policy;
mod report;
mod siem;
mod tail;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_policy::{PolicyRequest, PolicyResponse};

pub const VERBS: &[&str] = &["policy", "report", "audit", "alerts", "anomaly"];

pub const HELP: &str = "  policy test FILE                     run the [[test]] cases of a policy.toml (allow / deny per case)
  policy status | policy reload        the policy the daemon enforces (~/.config/kepr/policy.toml or
                                       /etc/kepr/policy.toml); deny by default once the file exists
  report access KEY                    every path KEY can take: gate bindings, shares sent, agent
                                       gates and reads (audit log), aliases, sync devices, policy
  audit forward --to TARGET [--once]   stream audit events (op, name, uid, result, time; never values)
                                       to jsonl:PATH, syslog:udp://HOST[:PORT] or otlp:URL; resumes
                                       after a restart [--interval SECS] [--state FILE]
  alerts check | alerts run [--once]   post audit events matching ~/.config/kepr/alerts.toml rules
                                       to Slack / Teams / Discord / ntfy webhooks, throttled per rule
                                       [--file F] [--interval SECS] [--state FILE]
  anomaly check | anomaly run --journal FILE|-   gate journal anomalies (~/.config/kepr/rules.toml): new
                                       path, volume spike, off hours, error burst → webhook, optional
                                       kepr panic [--rules F] [--once] [--interval SECS] [--state FILE]
  health … --notify URL [--format F]   post findings (names and flags only) to a webhook; F: slack,
                                       teams, discord, ntfy or json (guessed from URL); URL may be kepr:NAME
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "policy" => policy::cmd_policy(args),
        "report" => report::cmd_report(args),
        "audit" => forward::cmd_audit(args),
        "alerts" => alerts_cmd::cmd_alerts(args),
        "anomaly" => anomaly_cmd::cmd_anomaly(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}

/// `kepr health` hook (T6.08): `--notify URL [--format F]`, checked
/// before the health run.
pub use health::{after as after_health, parse as health_notify, rest as health_rest};

/// A CLI-local success: printed here (unless --json), returned for main.
fn done(message: String) -> Response {
    if !crate::cli_mode::json_mode() {
        crate::cli_ui::ok(&message);
    }
    Response::Policy(PolicyResponse::PolicyDone { message })
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
