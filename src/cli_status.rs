// cli_status.rs — `kepr status`: store lock state plus the crypto backend
// line (T7.16). Split out of cli_cmds.rs to keep that file under its ceiling.

use crate::cli_args::Args;
use crate::cli_cmds::dispatch;
use crate::cli_ui::{err, info};
use kepr_core::protocol::{Request, Response};

pub fn cmd_status(a: &Args) -> Response {
    let resp = dispatch(a, &Request::Status);
    if !a.json {
        match &resp {
            Response::StatusOk {
                locked,
                password_protected,
            } => info(&format!(
                "Store: {} ({})",
                if *locked { "locked" } else { "unlocked" },
                if *password_protected {
                    "password protected"
                } else {
                    "local key protection"
                }
            )),
            Response::Err { error } => err(error),
            _ => err("unexpected response"),
        }
        crate::cli_eco::print_status_crypto(&resp); // T7.16
        crate::cli_sharing::print_status(); // T6.14 escrow, T6.06 emergency requests
    }
    resp
}
