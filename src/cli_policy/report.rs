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
    let usage = "usage: kepr report access NAME [--kind K,..] [--filter F] [--save-filter F] | \
                 report access --filters | report compliance --framework F";
    let ["access", rest @ ..] = a.as_slice() else {
        return Response::fail(usage);
    };
    let opts = match super::report_filters::Options::parse(rest) {
        Ok(o) => o,
        Err(e) => return Response::fail(format!("{e}\n{usage}")),
    };
    if opts.list {
        return super::report_filters::print_saved();
    }
    let Some(name) = opts.name.clone() else {
        return Response::fail(usage);
    };
    let kinds = match opts.resolve() {
        Ok(k) => k,
        Err(e) => return Response::fail(e),
    };
    let r = super::send(PolicyRequest::ReportAccess { name });
    let r = match r {
        Response::Policy(PolicyResponse::AccessReportOk { name, rows }) => {
            Response::Policy(PolicyResponse::AccessReportOk {
                name,
                rows: super::report_filters::keep(rows, &kinds),
            })
        }
        other => other,
    };
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
