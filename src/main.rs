// main.rs — credman user CLI entry point.
//
// Thin client. Speaks to credman-daemon over a Unix socket; never calls the
// credential backend directly, never needs root/sudo. The `credman` group
// membership is the only access control — see ARCHITECTURE.md.

mod protocol;
mod generate;
mod framing;
mod client;
mod cli_ui;
mod cli_input;
mod cli_args;
mod cli_cmds;
mod cli_activity;

use cli_args::parse_args;
use cli_ui::{err, json_mode, print_json};
use protocol::Response;

fn main() {
    // Unknown verbs are rejected inside CliActivity::parse (called from
    // parse_args), so when parse_args succeeds, `command` is always one
    // of the five canonical activities — dispatch can't fall through.
    //
    // On parse failure: honour --json mode, if it was already seen on
    // argv, by emitting a Response::Err on stdout with no stderr noise.
    let args = match parse_args() {
        Ok(a)  => a,
        Err(e) => {
            if json_mode() {
                print_json(&Response::fail(e));
            } else {
                err(&format!("{e}"));
            }
            std::process::exit(1);
        }
    };

    let resp = args.command.dispatch(&args);

    if args.json { print_json(&resp); }
    if !resp.is_success() { std::process::exit(1); }
}
