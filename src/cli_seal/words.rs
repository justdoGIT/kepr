// cli_seal/words.rs — `kepr recovery-kit create|restore --words` (T4.10).
//
//   create --words   asks for the store passphrase, prints the master key
//                    as 24 numbered words and a QR code of them (stdout
//                    only; with --json, just the reply)
//   restore --words  reads the 24 words (masked), checks them here first
//                    so a typo is reported by position, then a new
//                    passphrase; the daemon rebuilds and proves the key

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_seal::{SealRequest, SealResponse};
use kepr_core::recovery_words;

use crate::cli_input::read_masked;
use crate::{cli_mode, cli_ui, client};

fn send(r: SealRequest) -> Response {
    client::send_request(&Request::Seal(r)).unwrap_or_else(Response::fail)
}

/// The words as 6 rows of 4 numbered columns, for writing down.
pub fn grid(words: &str) -> String {
    let list: Vec<&str> = words.split_whitespace().collect();
    let mut out = String::new();
    for row in list.chunks(4).enumerate() {
        let (r, chunk) = row;
        for (c, w) in chunk.iter().enumerate() {
            out.push_str(&format!("{:>4}. {w:<10}", r * 4 + c + 1));
        }
        out.truncate(out.trim_end().len());
        out.push('\n');
    }
    out
}

pub fn create() -> Response {
    let password = read_masked("  Store passphrase: ");
    let r = send(SealRequest::RecoveryWordsCreate { password });
    let Response::Seal(SealResponse::RecoveryWordsOk { fingerprint, words }) = &r else {
        return r;
    };
    if cli_mode::json_mode() {
        return r;
    }
    print!("{}", grid(words.as_str()));
    // Upper case: QR alphanumeric mode, a smaller code. Restore ignores case.
    let upper = ZeroString::from_string(words.as_str().to_uppercase());
    match crate::cli_seal::qr::render(upper.as_str()) {
        Ok(q) => print!("\n{q}"),
        Err(e) => cli_ui::warn(&e),
    }
    cli_ui::einfo(&format!(
        "recovery key {fingerprint}: these 24 words are your master key. Anyone who has them \
         and the credential files can read every secret: keep them offline, never next to the \
         machine. Restore with `kepr recovery-kit restore --words`."
    ));
    Response::Pong
}

pub fn restore() -> Response {
    let words = read_masked("  Recovery words (24, in order): ");
    if let Err(e) = recovery_words::decode(words.as_str()) {
        return Response::fail(e);
    }
    let first = read_masked("  New store passphrase: ");
    let second = read_masked("  Confirm passphrase: ");
    if first.as_str() != second.as_str() {
        return Response::fail("passphrases do not match");
    }
    let r = send(SealRequest::RecoveryWordsRestore {
        words,
        new_password: first,
    });
    if let Response::RecoveryRestoreOk {
        fingerprint,
        credentials_opened,
    } = &r
    {
        if !cli_mode::json_mode() {
            cli_ui::ok(&format!(
                "restored key {fingerprint}: it opens {credentials_opened} credential file(s); \
                 the store is now protected by the new passphrase"
            ));
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_numbers_every_word_in_order() {
        let words = recovery_words::encode(&[3u8; 32]);
        let g = grid(words.as_str());
        assert_eq!(g.lines().count(), 6);
        let back: Vec<&str> = g.split_whitespace().filter(|t| !t.ends_with('.')).collect();
        assert_eq!(back.join(" "), words.as_str());
        assert!(g.starts_with("   1. "));
        assert!(g.contains("  24. "));
        // What's printed decodes as is (numbers are skipped).
        assert_eq!(*recovery_words::decode(&g).unwrap(), [3u8; 32]);
    }
}
