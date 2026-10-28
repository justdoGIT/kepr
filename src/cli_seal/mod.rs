// cli_seal/ — the `seal` ticket batch, CLI side: how the master key is
// protected and recovered. Mostly flags on existing verbs, plus the
// `recovery-key` verb (T12.31); HELP documents them in `kepr --help`.
// batch: seal
//
//   qr      terminal QR codes with half-block characters (T4.10)
//   words   `kepr recovery-kit create|restore --words` (T4.10)
//   fido2   `kepr lock --fido2` and the security-key side of `kepr
//           unlock` / passphrase prompts (T4.09)
//   recovery_key `kepr recovery-key enrol` (T12.31) and `unlock` (T12.32)

pub mod fido2;
pub mod qr;
pub mod recovery_key;
pub mod words;

use kepr_core::protocol::Response;

pub const VERBS: &[&str] = &["recovery-key"];

pub const HELP: &str = "\
  recovery-kit create --words          print the master key as 24 words (EFF list, ~310 bits)
                                       and a terminal QR code of them
  recovery-kit restore --words         rebuild a lost master key from its 24 words
  lock --fido2                         unlocking also needs a touch of this security key
                                       (hmac-secret; libfido2 tools, KEPR_FIDO2_DEVICE)
  recovery-key enrol [--replace]       a sealed store: print a recovery key once (24 words
                                       and a QR code) that the daemon keeps the master key
                                       wrapped under
  recovery-key unlock                  the sealed key did not unseal at start-up: open the
                                       store with the recovery key and seal it again for
                                       this boot state (only on a machine you trust)
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "recovery-key" => recovery_key::dispatch(args),
        _ => Response::fail(format!("unknown command: {verb}")),
    }
}

/// `--words` on `kepr recovery-kit create|restore`.
pub fn wants_words(args: &[String]) -> bool {
    args.iter().any(|a| a == "--words")
}
