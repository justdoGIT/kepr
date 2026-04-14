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
use cli_ui::{err, print_json};

fn main() {
    // Unknown verbs are rejected inside CliActivity::parse (called from
    // parse_args), so this binding's `command` field is always one of
    // the five canonical activities — dispatch can't fall through.
    let args = match parse_args() {
        Ok(a)  => a,
        Err(e) => { err(&format!("{e}")); std::process::exit(1); }
    };

    let resp = args.command.dispatch(&args);

    if args.json { print_json(&resp); }
    if !resp.is_success() { std::process::exit(1); }
}
