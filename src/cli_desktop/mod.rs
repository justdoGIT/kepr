// cli_desktop/ — the `desktop` ticket batch, CLI side (T13.28): kepr as
// the Secret Service provider (org.freedesktop.secrets) of a desktop
// session, replacing GNOME Keyring / KWallet for libsecret clients.
// batch: desktop
//
//   dbus/   a small hand-written D-Bus client library
//   ss/     the Secret Service server, its tools and its tests

#![allow(dead_code)] // filled in as the pieces land

pub mod bus;
pub mod dbus;
pub mod import;
pub mod secret_tool;
pub mod ss;
pub mod ss_client;
pub mod ss_cmd;
pub mod takeover;
pub mod takeover_files;

use kepr_core::protocol::Response;

pub const VERBS: &[&str] = &["secret-service", "secret"];

pub const HELP: &str = "  secret-service run [--replace]       kepr as the desktop's Secret Service (org.freedesktop.secrets):
                                       libsecret programs, browsers, NetworkManager and git helpers
                                       keep their passwords in kepr, not GNOME Keyring or KWallet;
                                       an unlock dialog when locked, a log of who read what
  secret-service takeover [--now] [--no-import]
                                       import the current keyring's items, then make the bus start
                                       kepr for the Secret Service (user files only; `restore` undoes)
  secret-service status|import [--dry-run] [--overwrite]|log [-n N]|policy [check EXE [OP]]|restore
                                       policy: ~/.config/kepr/secret-service.toml (per program, per
                                       operation; sandboxed callers); `kepr agent run` hides the bus
                                       (KEPR_SANDBOX_DBUS=allow keeps it)
  secret store [--label L] [--collection C] ATTR VALUE…   (secret on stdin; like secret-tool)
  secret lookup|clear ATTR VALUE…      the secret to stdout / delete the matches
  secret search [--all] [--secrets] ATTR VALUE…  |  secret ls [--collection C]
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    let args: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !matches!(*a, "--json" | "--color" | "--no-color"))
        .collect();
    match verb {
        "secret-service" => ss_cmd::cmd(&args),
        "secret" => secret_tool::cmd(&args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}
