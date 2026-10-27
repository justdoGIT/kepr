// cli_usage.rs — `kepr usage [--days N]` (agent vault P9.6): how often
// each credential was used or refused, and when it was last used, from
// the daemon's hash-chained audit log. Never-used keys are flagged so
// they can be revoked.

use kepr_core::protocol::{Request, Response};

use crate::{cli_mode, cli_ui, client};

pub fn cmd_usage(days: Option<u32>) -> Response {
    let r = client::send_request(&Request::Usage { days }).unwrap_or_else(Response::fail);
    if cli_mode::json_mode() {
        return r;
    }
    let Response::UsageOk {
        since,
        chain_intact,
        gate_sessions,
        keys,
    } = &r
    else {
        return r;
    };
    if !chain_intact {
        cli_ui::warn("audit log failed verification; run `kepr audit-verify`");
    }
    let window = since
        .as_deref()
        .map_or("all time".to_string(), |s| format!("since {s} UTC"));
    cli_ui::info(&format!("{window}: {gate_sessions} agent gate session(s)"));
    let width = keys.iter().map(|k| k.name.len()).max().unwrap_or(4).max(4);
    println!(
        "{:width$}  {:>6}  {:>7}  LAST USED",
        "NAME", "USES", "REFUSED"
    );
    for k in keys {
        println!(
            "{:width$}  {:>6}  {:>7}  {}",
            k.name,
            k.uses,
            k.refused,
            k.last_used.as_deref().unwrap_or("never")
        );
    }
    let never: Vec<&str> = keys
        .iter()
        .filter(|k| k.last_used.is_none())
        .map(|k| k.name.as_str())
        .collect();
    if !never.is_empty() {
        cli_ui::info(&format!(
            "never used: {} (remove unneeded keys with `kepr delete NAME`)",
            never.join(", ")
        ));
    }
    r
}
