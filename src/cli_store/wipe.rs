// cli_store/wipe.rs — `kepr delete --all --yes` (T11.9).

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_store::{StoreRequest, StoreResponse};

use crate::cli_args::Args;
use crate::cli_ui;

pub fn cmd_delete_all(a: &Args) -> Response {
    let r = if a.name.is_some() {
        Response::fail("--all takes no NAME")
    } else if !a.store.yes {
        Response::fail(
            "`kepr delete --all` deletes every credential you own, sealed ones, \
             history and the trash included: add --yes",
        )
    } else {
        crate::client::send_request(&Request::Store(StoreRequest::DeleteAll { confirm: true }))
            .unwrap_or_else(Response::fail)
    };
    if !a.json {
        match &r {
            Response::Store(StoreResponse::DeleteAllOk { deleted }) => {
                cli_ui::ok(&format!("Deleted {deleted} credential(s) and aliases"))
            }
            Response::Err { error } => cli_ui::err(error),
            _ => {}
        }
    }
    r
}
