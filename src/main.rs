// main.rs — kepr user CLI entry point.
//
// Thin client. Speaks to kepr-daemon over a Unix socket; never calls the
// credential backend directly, never needs root/sudo. The `kepr` group
// membership is the only access control — see DOCS.md.

mod cli_activity;
mod cli_agent;
mod cli_agent_adapters;
mod cli_agent_adopt;
mod cli_agent_cmd;
mod cli_agent_detect;
mod cli_agent_egress;
mod cli_agent_install;
mod cli_agent_run;
mod cli_agent_sandbox;
mod cli_args;
mod cli_cmds;
mod cli_copy;
mod cli_discover;
mod cli_doctor;
mod cli_doctor_hardening;
mod cli_envdump;
mod cli_exec;
mod cli_extra;
mod cli_fido2;
mod cli_health;
mod cli_help;
mod cli_history;
mod cli_import;
mod cli_import_parse;
mod cli_inject;
mod cli_input;
mod cli_leaked;
mod cli_manifest;
mod cli_mask;
mod cli_mcp;
mod cli_mode;
mod cli_record;
mod cli_recovery;
mod cli_rotate;
mod cli_sandbox_seccomp;
mod cli_sandbox_sys;
mod cli_scan;
mod cli_ssh;
mod cli_ssh_agent;
mod cli_totp;
mod cli_ui;
mod cli_usage;
mod client;
mod sync;
mod sync_aws_sigv4;
mod sync_aws_sm;
mod sync_gcp_sm;
mod sync_vault;

use cli_args::parse_args;
use cli_ui::{err, json_mode, print_json};
use kepr_core::protocol::Response;

fn main() {
    // Unknown verbs are rejected inside CliActivity::parse (called from
    // parse_args), so when parse_args succeeds, `command` is always one
    // of the five canonical activities — dispatch can't fall through.
    //
    // On parse failure: honour --json mode, if it was already seen on
    // argv, by emitting a Response::Err on stdout with no stderr noise.
    // Verbs with their own small parsers (cli_extra.rs).
    let raw: Vec<String> = std::env::args().collect();
    if let Some(pos) = raw.iter().skip(1).position(|a| !a.starts_with("--")) {
        if cli_extra::VERBS.contains(&raw[pos + 1].as_str()) {
            cli_mode::init_from_argv(&raw);
            let resp = cli_extra::dispatch(&raw[pos + 1], &raw[pos + 2..]);
            if raw[1..=pos].iter().any(|a| a == "--json") {
                print_json(&resp);
            } else if let Response::Err { error } = &resp {
                err(error);
            }
            std::process::exit(if resp.is_success() { 0 } else { 1 });
        }
    }

    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if json_mode() {
                print_json(&Response::fail(e));
            } else {
                err(&e);
            }
            std::process::exit(1);
        }
    };

    let resp = args.command.dispatch(&args);

    if args.json {
        print_json(&resp);
    }
    if !resp.is_success() {
        std::process::exit(1);
    }
}
