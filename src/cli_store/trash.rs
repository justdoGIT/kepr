// cli_store/trash.rs — `kepr trash [ls] | restore NAME | purge [NAME]`
// and the `kepr rm` wrapper: plain `rm` moves to the trash (daemon side),
// `rm --force` deletes at once (T11.2).

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_store::{StoreRequest, StoreResponse};

use super::{plain_args, send};
use crate::cli_args::Args;
use crate::{cli_mode, cli_ui};

pub fn cmd_trash(args: &[String]) -> Response {
    let words = plain_args(args);
    let yes = words.iter().any(|w| *w == "--yes" || *w == "-y");
    let words: Vec<&str> = words.into_iter().filter(|w| !w.starts_with('-')).collect();
    match words.as_slice() {
        [] | ["ls"] | ["list"] => show_list(send(StoreRequest::TrashList)),
        ["restore", name] => {
            let r = send(StoreRequest::TrashRestore {
                name: name.to_uppercase(),
            });
            if let (false, Response::Store(StoreResponse::TrashRestoreOk { name })) =
                (cli_mode::json_mode(), &r)
            {
                cli_ui::ok(&format!("Restored: {name}"));
            }
            r
        }
        ["purge", rest @ ..] if rest.len() <= 1 => {
            if rest.is_empty() && !yes {
                return Response::fail("`kepr trash purge` empties the whole trash: add --yes");
            }
            let r = send(StoreRequest::TrashPurge {
                name: rest.first().map(|n| n.to_uppercase()),
            });
            if let (false, Response::Store(StoreResponse::TrashPurgeOk { purged })) =
                (cli_mode::json_mode(), &r)
            {
                cli_ui::ok(&format!("Purged {purged} trash entr{}", plural(*purged)));
            }
            r
        }
        _ => Response::fail(
            "usage: kepr trash [ls] | trash restore NAME | trash purge [NAME] [--yes]",
        ),
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        "y"
    } else {
        "ies"
    }
}

fn show_list(r: Response) -> Response {
    if cli_mode::json_mode() {
        return r;
    }
    if let Response::Store(StoreResponse::TrashListOk { items }) = &r {
        if items.is_empty() {
            cli_ui::info("The trash is empty.");
        }
        for i in items {
            let mut tail = format!("deleted {}  purged {}", i.trashed_at, i.purge_at);
            if i.sealed == Some(true) {
                tail.push_str("  sealed");
            }
            if let Some(t) = &i.record_type {
                tail.push_str(&format!("  [{t}]"));
            }
            println!(
                "  {:<40} {}",
                cli_ui::color("1", &i.name),
                cli_ui::color("2", &tail)
            );
        }
    }
    r
}

/// `kepr rm NAME [--force]`: `--force` also skips the trash.
pub fn cmd_delete(a: &Args) -> Response {
    if let (false, Some(n)) = (a.json, &a.name) {
        super::alias::warn_aliases(n);
    }
    let Some(name) = a.name.clone().filter(|_| a.force) else {
        let r = crate::cli_cmds::cmd_delete(a);
        if let (false, Response::DeleteOk { name }) = (a.json, &r) {
            trash_hint(name);
        }
        return r;
    };
    let r = crate::client::send_request(&Request::Store(StoreRequest::DeleteNow { name }))
        .unwrap_or_else(Response::fail);
    match &r {
        Response::DeleteOk { name } if !a.json => cli_ui::ok(&format!("Deleted: {name}")),
        Response::Err { error } if !a.json => cli_ui::err(error),
        _ => {}
    }
    r
}

/// After a plain `rm`: say how to undo it, if the daemon kept it.
fn trash_hint(name: &str) {
    if let Response::Store(StoreResponse::TrashListOk { items }) = send(StoreRequest::TrashList) {
        if let Some(i) = items.iter().rev().find(|i| i.name == name) {
            cli_ui::info(&format!(
                "In the trash until {}: kepr trash restore {name}",
                i.purge_at
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn usage_and_purge_all_needs_yes() {
        assert!(cmd_trash(&v(&["restore"]))
            .err_msg()
            .unwrap()
            .contains("usage"));
        assert!(cmd_trash(&v(&["purge"]))
            .err_msg()
            .unwrap()
            .contains("--yes"));
        assert!(cmd_trash(&v(&["bogus"]))
            .err_msg()
            .unwrap()
            .contains("usage"));
    }
}
