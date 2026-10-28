// cli_platform/ — the `platform` ticket batch (P10), CLI side.
// batch: platform
//
//   args           the small flag parser the verbs below share
//   systemd_cred   `kepr systemd-cred` (T10.06)
//   keyring        `kepr keyring add` (T10.05)
//   fingerprint    `kepr unlock --fingerprint`, doctor's fprintd check (T10.03)
//   exe            `kepr set --exe`, `kepr exe` binary-identity bindings (T10.09)
//   pki            `kepr pki init|ca|issue|ls` local CA (T10.10)
//   svid           `kepr pki svid|tpm-enroll` SPIFFE SVIDs, TPM2 quotes (T10.11)
//   kdbx*          `kepr import vault.kdbx` KeePass KDBX 4 (T10.02)
//   fuse, mount*   `kepr mount DIR --file NAME=KEYS` read-only FUSE files (T10.01)

mod args;
pub mod exe;
pub mod fingerprint;
mod fuse;
pub mod kdbx;
mod kdbx_keys;
mod kdbx_xml;
mod keyring;
mod mount;
mod mount_os;
mod pam_unlock;
mod pki;
mod svid;
mod systemd_cred;

use kepr_core::protocol::Response;

pub use fingerprint::{PlatformFlags, FLAGS};

pub const VERBS: &[&str] = &[
    "systemd-cred",
    "keyring",
    "exe",
    "pki",
    "mount",
    "pam-unlock",
];

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
  pki init [--days N] [--force]        local CA (P-256); its key is sealed in the store, never shown
  pki ca                               print the CA certificate, to add to trust stores
  pki issue NAME... [--days 30] [--out DIR] [--force]
                                       NAME.crt (leaf + CA) and NAME.key (0600) for DNS names / IPs
  pki ls                               the CA and issued certificates; health warns 14 days ahead
  pki svid spiffe://TD/PATH [--ttl 1h] [--out DIR] [--force] [--ak HANDLE|CTX]
                                       X.509 SVID (URI SAN, at most 24 h): svid.pem, svid_key.pem,
                                       svid_bundle.pem; with a TPM enrolled, --ak quotes PCR 7 first
  pki tpm-enroll --ak-pub ak.pem --ak HANDLE|CTX
                                       SVIDs only while PCR 7 (Secure Boot state) matches, via tpm2_quote
  import vault.kdbx [--prefix P] [--seal] [--overwrite] [--yes]
                                       KeePass KDBX 4 (asks for its password; Argon2 KDF, AES-256 or
                                       ChaCha20; key files not supported)
  pam-unlock                           (run by pam_kepr.so after login) read the login password from stdin and
                                       unlock the store in the background; only if it is the store passphrase
  mount DIR --file NAME=KEY1,KEY2 [--file ...] [--exe PATH]... [--consent]
                                       read-only FUSE files (*.json object, .env lines, or one bare
                                       value), fetched per open for your processes only; --exe limits
                                       the reading programs, --consent asks polkit each time
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "systemd-cred" => systemd_cred::cmd_systemd_cred(args),
        "keyring" => keyring::cmd_keyring(args),
        "exe" => exe::cmd_exe(args),
        "pki" => pki::cmd_pki(args),
        "mount" => mount_os::cmd_mount(args),
        "pam-unlock" => pam_unlock::cmd_pam_unlock(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}
