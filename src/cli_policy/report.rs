// cli_policy/report.rs — `kepr report access NAME` (T6.12): where a
// credential can go (gate bindings, aliases, sync devices, policy rules)
// and where it went (shares, agent gates, reads), from the daemon.

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{PolicyRequest, PolicyResponse};

use crate::{cli_mode, cli_ui};

pub fn cmd_report(args: &[String]) -> Response {
    let a = super::plain_args(args);
    if let Some((&"compliance", rest)) = a.split_first() {
        return super::compliance::cmd_compliance(rest);
    }
    let ["access", name] = a.as_slice() else {
        return Response::fail("usage: kepr report access NAME | compliance --framework F");
    };
    let r = super::send(PolicyRequest::ReportAccess {
        name: name.to_string(),
    });
    if cli_mode::json_mode() {
        return r;
    }
    if let Response::Policy(PolicyResponse::AccessReportOk { name, rows }) = &r {
        if rows.is_empty() {
            cli_ui::info(&format!(
                "{name}: stored only; no recorded use, binding or share"
            ));
        }
        let width = rows.iter().map(|r| r.kind.len()).max().unwrap_or(4).max(4);
        for row in rows {
            println!("{:width$}  {}", row.kind, row.detail);
        }
    }
    r
}
