// cli_platform/ — the `platform` ticket batch (P10), CLI side.
// batch: platform
//
//   args           the small flag parser the verbs below share
//   systemd_cred   `kepr systemd-cred` (T10.06)
//   keyring        `kepr keyring add` (T10.05)

mod args;
mod keyring;
mod systemd_cred;

use kepr_core::protocol::Response;

pub const VERBS: &[&str] = &["systemd-cred", "keyring"];

pub const HELP: &str = "  systemd-cred KEY [--name CRED] [--tpm2]
                                       print a SetCredentialEncrypted= line for a unit file (value
                                       piped to systemd-creds encrypt on stdin; never sealed keys)
  keyring add KEY --desc SUBTYPE:REST [--keyring @u|@s|@us|SERIAL] [--decode hex|base64]
                                       add KEY to a kernel keyring as a `logon` key (usable by
                                       fscrypt, dm-crypt, cifs; unreadable from userspace)
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "systemd-cred" => systemd_cred::cmd_systemd_cred(args),
        "keyring" => keyring::cmd_keyring(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}
