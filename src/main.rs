// main.rs — kepr user CLI entry point.
//
// Thin client. Speaks to kepr-daemon over a Unix socket; never calls the
// credential backend directly, never needs root/sudo. The `kepr` group
// membership is the only access control — see DOCS.md.

mod cli_activity;
mod cli_agent_adapters;
mod cli_agent_adopt;
mod cli_agent_cmd;
mod cli_agent_db;
mod cli_agent_db_rotate;
mod cli_agent_detect;
mod cli_agent_egress;
mod cli_agent_install;
mod cli_agent_plugin;
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
mod cli_hook;
mod cli_import;
mod cli_import_parse;
mod cli_inject;
mod cli_input;
mod cli_leaked;
mod cli_manifest;
mod cli_mask;
mod cli_mcp;
mod cli_mode;
mod cli_more;
mod cli_record;
mod cli_recovery;
mod cli_rotate;
mod cli_sandbox_relay;
mod cli_sandbox_seccomp;
mod cli_sandbox_sys;
mod cli_scan;
mod cli_share;
mod cli_ssh;
mod cli_ssh_agent;
mod cli_totp;
mod cli_ui;
mod cli_usage;
mod client;
mod sync;
mod sync_aws_sm;
mod sync_gcp_sm;
mod sync_http;
mod sync_vault;

// ── P2–P11 ticket batches (2026-10-05): one `cli_<batch>` directory module
// per batch, declared under its own marker (registered in cli_more.rs).
// batch: vault
mod cli_vault;
// batch: seal
// batch: store
mod cli_store;
// batch: records
// batch: share
mod cli_sharing;
// batch: sync
// batch: policy
// batch: gate
mod cli_gatex;
// batch: aws
// batch: eco
mod cli_eco;
// batch: platform
// batch: session
// end of batches

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
        // Harness hooks speak exit codes, not Responses.
        if raw[pos + 1] == "hook" {
            std::process::exit(cli_hook::cmd_hook(&raw[pos + 2..]));
        }
        let verb = raw[pos + 1].as_str();
        if cli_extra::VERBS.contains(&verb) || cli_more::is_verb(verb) {
            cli_mode::init_from_argv(&raw);
            let resp = if cli_more::is_verb(verb) {
                cli_more::dispatch(verb, &raw[pos + 2..])
            } else {
                cli_extra::dispatch(verb, &raw[pos + 2..])
            };
            // `init_from_argv` takes `--json` anywhere on the line, and the
            // handlers skip their human output in JSON mode: print it here
            // whatever its position (recovery shares, share envelopes).
            if json_mode() {
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
