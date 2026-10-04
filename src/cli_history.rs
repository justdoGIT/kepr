// cli_history.rs — `kepr history NAME` and `kepr restore NAME --version N`
// (agent vault P5.3). The daemon keeps the last few replaced values,
// encrypted; neither command ever prints a value.

use kepr_core::protocol::{Request, Response};

use crate::{cli_mode, cli_ui, client};

fn send(req: &Request) -> Response {
    client::send_request(req).unwrap_or_else(Response::fail)
}

pub fn cmd_history(name: &str) -> Response {
    let r = send(&Request::History {
        name: name.to_uppercase(),
    });
    if cli_mode::json_mode() {
        return r;
    }
    if let Response::HistoryOk { name, versions } = &r {
        if versions.is_empty() {
            cli_ui::info(&format!("{name} has no saved previous values"));
        }
        for v in versions {
            let sealed = if v.sealed == Some(true) {
                "  sealed"
            } else {
                ""
            };
            println!("{:>3}  {}  {} bytes{sealed}", v.version, v.saved_at, v.size);
        }
    }
    r
}

pub fn cmd_restore(name: &str, version: u32) -> Response {
    let r = send(&Request::Restore {
        name: name.to_uppercase(),
        version,
    });
    if cli_mode::json_mode() {
        return r;
    }
    if let Response::RestoreOk { name, version } = &r {
        cli_ui::ok(&format!(
            "{name}: version {version} restored (the replaced value is now version 1)"
        ));
    }
    r
}
