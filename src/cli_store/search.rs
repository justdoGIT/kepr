// cli_store/search.rs — `kepr search PATTERN [--json]` (T11.1). The
// daemon matches; this prints names and what matched (never values).

use kepr_core::protocol::Response;
use kepr_core::protocol_store::{StoreRequest, StoreResponse};

use super::{plain_args, send};
use crate::{cli_mode, cli_ui};

pub fn cmd_search(args: &[String]) -> Response {
    let [pattern] = plain_args(args)[..] else {
        return Response::fail("usage: kepr search PATTERN   (substring, or /regex/)");
    };
    let r = send(StoreRequest::Search {
        pattern: pattern.to_string(),
    });
    if cli_mode::json_mode() {
        return r;
    }
    if let Response::Store(StoreResponse::SearchOk { hits }) = &r {
        if hits.is_empty() {
            cli_ui::info("no matches");
        }
        for h in hits {
            println!(
                "  {:<40} {}",
                cli_ui::color("1", &h.name),
                cli_ui::color("2", &h.matched.join(", "))
            );
        }
    }
    r
}
