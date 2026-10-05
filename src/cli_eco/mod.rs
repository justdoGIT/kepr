// cli_eco — P8 ecosystem verbs (batch `eco`, 2026-10-05).
//
//   kepr shell        interactive prompt that runs kepr verbs (shell.rs)

mod shell;

use kepr_core::protocol::Response;

pub const VERBS: &[&str] = &["shell"];

pub const HELP: &str = "  shell                                interactive prompt for kepr verbs (no `kepr` prefix);\n                                       history in memory only, values only at masked prompts\n";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "shell" => shell::cmd_shell(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}
