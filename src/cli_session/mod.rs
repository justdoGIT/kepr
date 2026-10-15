// cli_session/ — the `session` ticket batch, CLI side: `kepr reauth` and
// `kepr set --reauth` (T11.14), `kepr --profile` (T11.16, applied first
// thing in main.rs), `kepr batch` (T11.18), `kepr discover` rules
// (T11.20, called from cli_discover.rs), `kepr ssh rotate` (T11.21, from
// cli_ssh.rs), `kepr serve` (T11.19), `kepr exec --pull` (T3.06, from
// cli_activity.rs). Registered in cli_more.rs;
// flags on core verbs are parsed by cli_args.rs (`FLAGS` / `SessionFlags`).

pub mod batch;
pub mod discover_rules;
pub mod profile;
pub mod pull;
pub mod reauth;
pub mod serve;
pub mod serve_route;
pub mod ssh_rotate;

use kepr_core::protocol::Response;

pub use reauth::{SessionFlags, FLAGS};

pub const VERBS: &[&str] = &["reauth", "batch", "serve"];

pub const HELP: &str = "\
  set KEY --reauth                     revealing KEY (get, copy, exec, record show --reveal) asks
                                       for the store passphrase; one answer is good for 60 s
  reauth KEY [--on|--off]              enter the passphrase now (KEY readable for 60 s, e.g. for
                                       scripts); --on / --off: turn the requirement on / off
  batch FILE [--keep-going]            run one kepr command per line (# comments, quotes); stops at
                                       the first error; values never on a line (--generate, kepr://)
  discover                             also applies ~/.config/kepr/discover.toml rules:
                                       [[rule]] match = \"aws:*prod*\" action = \"add|ignore|ask\"
  ssh rotate KEY --host [USER@]HOST [--port N]
                                       new key on the host (logged in with the old one), checks
                                       a login with it, removes the old line, replaces KEY
  serve --listen 127.0.0.1:PORT|--socket PATH --allow list,get [--rate N]
                                       local REST API: GET /v1/secrets[/NAME]; bearer token from
                                       KEPR_SERVE_TOKEN_FILE; loopback only; never sealed/SSH keys
  exec --pull KEY[,KEY…] -- CMD        CMD fetches each KEY itself, when needed, as a sealed fd
                                       (names in KEPR_PULL; kepr_core::fdfetch) that its own
                                       children never inherit
  --profile NAME COMMAND               run COMMAND on profile NAME: its own store, state and
                                       daemon (same as KEPR_PROFILE=NAME)
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    let args = plain_args(args);
    match verb {
        "reauth" => reauth::cmd_reauth(&args),
        "batch" => batch::cmd_batch(&args),
        "serve" => serve::cmd_serve(&args),
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
