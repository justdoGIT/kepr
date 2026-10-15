// cli_store/verify.rs — `kepr doctor --verify` (T11.10): the daemon's
// deep store check, shown as problems first, then a one-line summary.

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_store::StoreRequest;

use crate::cli_ui;

pub fn cmd_verify(json: bool) -> Response {
    let r = crate::client::send_request(&Request::Store(StoreRequest::VerifyStore))
        .unwrap_or_else(Response::fail);
    if json {
        return r;
    }
    match &r {
        Response::CheckOk {
            results,
            count,
            all_ok,
        } => {
            let mut bad: Vec<(&String, &String)> =
                results.iter().filter(|(_, s)| *s != "ok").collect();
            bad.sort();
            for (name, problem) in &bad {
                cli_ui::err(&format!("{name}: {problem}"));
            }
            if *all_ok {
                cli_ui::ok(&format!("{count} stored item(s) verified"));
            } else {
                cli_ui::warn(&format!(
                    "{} of {count} stored item(s) have problems",
                    bad.len()
                ));
            }
        }
        Response::Err { error } => cli_ui::err(error),
        _ => cli_ui::err("unexpected response"),
    }
    r
}
