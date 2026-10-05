// cli_store/ — the `store` ticket batch, CLI side: `kepr tag`, `kepr mv`
// and `kepr ls --tag/--folder` (T5.01). Registered in cli_more.rs; the
// `ls` flags are parsed by cli_args.rs through `FLAGS` / `StoreFlags`.

mod flags;
mod list;
mod organize;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_store::StoreRequest;

pub use flags::{StoreFlags, FLAGS};
pub use list::{filter_list, list_tail};

pub const VERBS: &[&str] = &["tag", "mv"];

pub const HELP: &str = "\
  tag KEY [+TAG|-TAG]...               add / remove tags (a-z 0-9 _ -, up to 16); no TAG: show
  mv KEY FOLDER                        file KEY under FOLDER (a/b/c); `mv KEY /` clears it
  ls --tag TAG --folder FOLDER         only keys with TAG / in FOLDER or below (`/`: no folder)
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "tag" => organize::cmd_tag(args),
        "mv" => organize::cmd_mv(args),
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
