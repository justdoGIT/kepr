// cli_store/dupes.rs — `kepr dupes [--merge KEEP]` (T11.4). The daemon
// compares values; only names come back.

use kepr_core::protocol::Response;
use kepr_core::protocol_store::{StoreRequest, StoreResponse};

use super::{plain_args, send};
use crate::{cli_mode, cli_ui};

pub fn cmd_dupes(args: &[String]) -> Response {
    let r = match plain_args(args)[..] {
        [] => send(StoreRequest::Dupes),
        ["--merge", keep] => send(StoreRequest::DupesMerge {
            keep: keep.to_uppercase(),
        }),
        _ => return Response::fail("usage: kepr dupes [--merge KEEP]"),
    };
    if cli_mode::json_mode() {
        return r;
    }
    match &r {
        Response::Store(StoreResponse::DupesOk { groups }) => {
            if groups.is_empty() {
                cli_ui::info("No two credentials hold the same value.");
            }
            for g in groups {
                println!("  {}", g.join(" = "));
            }
            if let Some(g) = groups.first() {
                cli_ui::info(&format!(
                    "keep one and alias the rest: kepr dupes --merge {}",
                    g[0]
                ));
            }
        }
        Response::Store(StoreResponse::DupesMergeOk { keep, aliased }) => {
            cli_ui::ok(&format!(
                "{} now alias{} {keep} (old values are in the trash)",
                aliased.join(", "),
                if aliased.len() == 1 { "es" } else { "" }
            ));
        }
        _ => {}
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(matches!(cmd_dupes(&v(&["--merge"])), Response::Err { .. }));
        assert!(matches!(cmd_dupes(&v(&["x", "y"])), Response::Err { .. }));
    }
}
