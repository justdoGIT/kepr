// cli_platform/ — the `platform` ticket batch (P10), CLI side.
// batch: platform
//
//   args           the small flag parser the verbs below share
//   systemd_cred   `kepr systemd-cred` (T10.06)

mod args;
mod systemd_cred;

use kepr_core::protocol::Response;

pub const VERBS: &[&str] = &["systemd-cred"];

pub const HELP: &str = "  systemd-cred KEY [--name CRED] [--tpm2]
                                       print a SetCredentialEncrypted= line for a unit file (value
                                       piped to systemd-creds encrypt on stdin; never sealed keys)
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "systemd-cred" => systemd_cred::cmd_systemd_cred(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}
