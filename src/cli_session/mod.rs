// cli_session/ — the `session` ticket batch, CLI side: `kepr reauth` and
// `kepr set --reauth` (T11.14), `kepr --profile` (T11.16, applied first
// thing in main.rs), `kepr batch` (T11.18). Registered in cli_more.rs;
// flags on core verbs are parsed by cli_args.rs (`FLAGS` / `SessionFlags`).

pub mod batch;
pub mod profile;
pub mod reauth;

use kepr_core::protocol::Response;

pub use reauth::{SessionFlags, FLAGS};

pub const VERBS: &[&str] = &["reauth", "batch"];

pub const HELP: &str = "\
  set KEY --reauth                     revealing KEY (get, copy, exec, record show --reveal) asks
                                       for the store passphrase; one answer is good for 60 s
  reauth KEY [--on|--off]              enter the passphrase now (KEY readable for 60 s, e.g. for
                                       scripts); --on / --off: turn the requirement on / off
  batch FILE [--keep-going]            run one kepr command per line (# comments, quotes); stops at
                                       the first error; values never on a line (--generate, kepr://)
  --profile NAME COMMAND               run COMMAND on profile NAME: its own store, state and
                                       daemon (same as KEPR_PROFILE=NAME)
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    let args = plain_args(args);
    match verb {
        "reauth" => reauth::cmd_reauth(&args),
        "batch" => batch::cmd_batch(&args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}

/// Arguments without the global output flags (`--json`, `--color`, …).
fn plain_args(args: &[String]) -> Vec<&str> {
    args.iter()
        .map(String::as_str)
        .filter(|a| !matches!(*a, "--json" | "--color" | "--no-color"))
        .collect()
}
