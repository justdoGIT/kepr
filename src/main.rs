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

use cli_args::parse_args;
use cli_ui::{err, print_json};
use protocol::Response;

fn main() {
    let args = match parse_args() {
        Ok(a)  => a,
        Err(e) => { err(&format!("{e}")); std::process::exit(1); }
    };

    let resp = match args.command.as_str() {
        "set"          => cli_cmds::cmd_set(&args),
        "get"          => cli_cmds::cmd_get(&args),
        "list" | "ls"  => cli_cmds::cmd_list(&args),
        "delete"|"rm"  => cli_cmds::cmd_delete(&args),
        "check"        => cli_cmds::cmd_check(&args),
        other => {
            let msg = format!("unknown command: {other}");
            if !args.json {
                err(&msg);
                err("try: credman --help");
            }
            Response::fail(&msg)
        }
    };

    if args.json { print_json(&resp); }
    if !resp.ok  { std::process::exit(1); }
}
