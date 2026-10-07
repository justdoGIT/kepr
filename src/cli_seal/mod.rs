// cli_seal/ — the `seal` ticket batch, CLI side: how the master key is
// protected and recovered. It adds flags to existing verbs rather than
// verbs of its own; HELP documents them in `kepr --help`.
// batch: seal
//
//   qr      terminal QR codes with half-block characters (T4.10)
//   words   `kepr recovery-kit create|restore --words` (T4.10)

pub mod qr;
pub mod words;

use kepr_core::protocol::Response;

pub const VERBS: &[&str] = &[];

pub const HELP: &str = "\
  recovery-kit create --words          print the master key as 24 words (EFF list, ~310 bits)
                                       and a terminal QR code of them
  recovery-kit restore --words         rebuild a lost master key from its 24 words
";

pub fn dispatch(verb: &str, _args: &[String]) -> Response {
    Response::fail(format!("unknown command: {verb}"))
}

/// `--words` on `kepr recovery-kit create|restore`.
pub fn wants_words(args: &[String]) -> bool {
    args.iter().any(|a| a == "--words")
}
