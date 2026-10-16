// cli_seal/recovery_key.rs — `kepr recovery-key enrol [--replace]`
// (T12.31): a recovery key for a sealed master key.
//
// The key is 32 random bytes made here and sent to the daemon as 24
// recovery words; the daemon keeps the master key wrapped under them and
// answers only the master key's fingerprint. The words are printed after
// the daemon confirms, once, with a QR code (as `recovery-kit create
// --words` does); with --json they are the reply's `words`. `--replace`
// first asks for the enrolled key's words, masked.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_seal::{SealRequest, SealResponse};
use kepr_core::recovery_words;
use zeroize::Zeroizing;

use crate::cli_input::read_masked;
use crate::{cli_mode, cli_ui, client};

const USAGE: &str = "usage: kepr recovery-key enrol [--replace]";

#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    Enrol { replace: bool },
}

pub fn parse(args: &[String]) -> Result<Cmd, String> {
    let args: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !matches!(*a, "--json" | "--color" | "--no-color"))
        .collect();
    match args.as_slice() {
        ["enrol"] => Ok(Cmd::Enrol { replace: false }),
        ["enrol", "--replace"] => Ok(Cmd::Enrol { replace: true }),
        _ => Err(USAGE.into()),
    }
}

pub fn dispatch(args: &[String]) -> Response {
    match parse(args) {
        Ok(Cmd::Enrol { replace }) => enrol(replace),
        Err(e) => Response::fail(e),
    }
}

/// A fresh recovery key, as its 24 words.
fn new_words() -> Result<ZeroString, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut()).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(recovery_words::encode(&key))
}

fn enrol(replace: bool) -> Response {
    let current = if replace {
        let w = read_masked("  Current recovery words (24, in order): ");
        // Report a typo by position here, before the daemon's check.
        if let Err(e) = recovery_words::decode(w.as_str()) {
            return Response::fail(e);
        }
        Some(w)
    } else {
        None
    };
    let words = match new_words() {
        Ok(w) => w,
        Err(e) => return Response::fail(e),
    };
    let r = client::send_request(&Request::Seal(SealRequest::RecoveryKeyEnrol {
        words: ZeroString::from(words.as_str()),
        current,
    }))
    .unwrap_or_else(Response::fail);
    let Response::Seal(SealResponse::RecoveryKeyEnrolled { fingerprint }) = r else {
        return r;
    };
    if cli_mode::json_mode() {
        return Response::Seal(SealResponse::RecoveryKeyWords { fingerprint, words });
    }
    print!("{}", crate::cli_seal::words::grid(words.as_str()));
    // Upper case: QR alphanumeric mode, a smaller code. Unlock ignores case.
    let upper = ZeroString::from_string(words.as_str().to_uppercase());
    match crate::cli_seal::qr::render(upper.as_str()) {
        Ok(q) => print!("\n{q}"),
        Err(e) => cli_ui::warn(&e),
    }
    cli_ui::einfo(&format!(
        "recovery key enrolled for master key {fingerprint}. It is shown only now. Anyone \
         with these 24 words and the key files can open the store: keep them offline, \
         never next to the machine. If the sealed key stops unsealing, \
         `kepr recovery-key unlock` opens the store with them."
    ));
    Response::Pong
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn enrol_and_replace_parse_and_the_rest_is_usage() {
        assert_eq!(parse(&args(&["enrol"])), Ok(Cmd::Enrol { replace: false }));
        assert_eq!(
            parse(&args(&["enrol", "--replace", "--json"])),
            Ok(Cmd::Enrol { replace: true })
        );
        for bad in [
            &[][..],
            &["enroll"],
            &["enrol", "--force"],
            &["enrol", "x"],
            &["--replace"],
        ] {
            assert_eq!(parse(&args(bad)), Err(USAGE.into()), "{bad:?}");
        }
    }

    #[test]
    fn new_words_are_a_fresh_recovery_key() {
        let (a, b) = (new_words().unwrap(), new_words().unwrap());
        assert_ne!(a.as_str(), b.as_str());
        assert_eq!(a.split_whitespace().count(), recovery_words::WORDS);
        assert!(recovery_words::decode(a.as_str()).is_ok());
    }
}
