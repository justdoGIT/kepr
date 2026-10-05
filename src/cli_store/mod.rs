// cli_store/ — the `store` ticket batch, CLI side: `kepr tag`, `kepr mv`
// and `kepr ls --tag/--folder` (T5.01), `kepr search` (T11.1), `kepr trash`
// and the `kepr rm` wrapper (T11.2), `kepr ln` (T11.5), `rm --all` (T11.9),
// `kepr dupes` (T11.4), `kepr doctor --verify` (T11.10), `kepr history
// --diff` (T11.3, routed from cli_extra.rs).
// Registered in cli_more.rs; flags on core verbs are parsed by
// cli_args.rs through `FLAGS` / `StoreFlags`.

mod alias;
mod diff;
mod dupes;
mod flags;
mod list;
mod organize;
mod search;
mod trash;
mod verify;
mod wipe;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_store::StoreRequest;

pub use diff::cmd_history_diff;
pub use flags::{StoreFlags, FLAGS};
pub use list::{filter_list, list_tail};
pub use trash::cmd_delete;
pub use verify::cmd_verify;

pub const VERBS: &[&str] = &["tag", "mv", "search", "trash", "ln", "dupes"];

pub const HELP: &str = "\
  tag KEY [+TAG|-TAG]...               add / remove tags (a-z 0-9 _ -, up to 16); no TAG: show
  mv KEY FOLDER                        file KEY under FOLDER (a/b/c); `mv KEY /` clears it
  ls --tag TAG --folder FOLDER         only keys with TAG / in FOLDER or below (`/`: no folder)
  search PATTERN                       find keys by name, tag, folder, record type, username/url/host
                                       (substring, or /regex/ with . * ^ $ [a-z]); never values
  trash [ls] | trash restore KEY       `rm` keeps keys in the trash for KEPR_TRASH_DAYS (30) days;
  trash purge [KEY] [--yes]            `rm --force` skips it; purge empties it (all: --yes)
  ln ALIAS KEY                         ALIAS reads KEY (get/exec/inject) under KEY's policy;
                                       `rm ALIAS` removes only the alias
  delete --all --yes                   delete every key you own (sealed too), history, trash, aliases
  dupes [--merge KEEP]                 keys holding the same value (not sealed / gated ones);
                                       --merge: the others become aliases of KEEP (values to the trash)
  doctor --verify                      decrypt-check every stored value, parse every .meta, find
                                       orphaned history / metadata and dangling aliases
  history KEY --diff A B               record fields added / removed / changed from version A to B
                                       (0 = current); names only, never values
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "tag" => organize::cmd_tag(args),
        "mv" => organize::cmd_mv(args),
        "search" => search::cmd_search(args),
        "trash" => trash::cmd_trash(args),
        "ln" => alias::cmd_ln(args),
        "dupes" => dupes::cmd_dupes(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}

fn send(req: StoreRequest) -> Response {
    crate::client::send_request(&Request::Store(req)).unwrap_or_else(Response::fail)
}

/// Arguments without the global output flags (`--json`, `--color`, …).
fn plain_args(args: &[String]) -> Vec<&str> {
    args.iter()
        .map(String::as_str)
        .filter(|a| !matches!(*a, "--json" | "--color" | "--no-color"))
        .collect()
}
