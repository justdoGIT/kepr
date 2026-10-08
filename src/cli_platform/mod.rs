// cli_platform/ — the `platform` ticket batch (P10), CLI side.
// batch: platform
//
//   args           the small flag parser the verbs below share
//   systemd_cred   `kepr systemd-cred` (T10.06)
//   keyring        `kepr keyring add` (T10.05)
//   fingerprint    `kepr unlock --fingerprint`, doctor's fprintd check (T10.03)
//   exe            `kepr set --exe`, `kepr exe` binary-identity bindings (T10.09)

mod args;
pub mod exe;
pub mod fingerprint;
mod keyring;
mod systemd_cred;

use kepr_core::protocol::Response;

pub use fingerprint::{PlatformFlags, FLAGS};

pub const VERBS: &[&str] = &["systemd-cred", "keyring", "exe"];

pub const HELP: &str = "  systemd-cred KEY [--name CRED] [--tpm2]
                                       print a SetCredentialEncrypted= line for a unit file (value
                                       piped to systemd-creds encrypt on stdin; never sealed keys)
  keyring add KEY --desc SUBTYPE:REST [--keyring @u|@s|@us|SERIAL] [--decode hex|base64]
                                       add KEY to a kernel keyring as a `logon` key (usable by
                                       fscrypt, dm-crypt, cifs; unreadable from userspace)
  unlock --fingerprint                 reopen a store the idle timer / sleep watcher locked, after a
                                       polkit prompt (fprintd); daemon opt-in KEPR_FINGERPRINT_UNLOCK=8h
  set KEY … --exe PATH [--exe PATH]    only these programs (SHA-256 / fs-verity of the binary that
                                       connects: kepr itself for get/exec, or your SDK program) may read it
  exe KEY [--allow PATH]... [--clear]  show, replace or drop KEY's program binding (changing it needs
                                       an allowed program; otherwise delete and re-create KEY)
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "systemd-cred" => systemd_cred::cmd_systemd_cred(args),
        "keyring" => keyring::cmd_keyring(args),
        "exe" => exe::cmd_exe(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}
