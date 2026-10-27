// cli_eco — P8 ecosystem verbs (batch `eco`, 2026-10-05).
//
//   kepr shell        interactive prompt that runs kepr verbs (shell.rs)
//   kepr ui           full-screen credential list (tui.rs + tui_term.rs)
//   kepr status       its `Crypto:` line (crypto.rs, T7.16)

mod crypto;
mod shell;
mod tui;
mod tui_term;

pub use crypto::print_status_crypto;
use kepr_core::protocol::Response;
pub use shell::split_words; // also `kepr batch` (T11.18)

pub const VERBS: &[&str] = &["shell", "ui"];

pub const HELP: &str = "  shell                                interactive prompt for kepr verbs (no `kepr` prefix);\n                                       history in memory only, values only at masked prompts\n  ui                                   full-screen credential list: search, copy, delete (never shows values)\n";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "shell" => shell::cmd_shell(args),
        "ui" => tui_term::cmd_ui(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}
