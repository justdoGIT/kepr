//! Recognized encoded private data is refused, never rewritten on the wire.

use super::{detect, MAX_TEXT_BYTES};
use base64::{engine::general_purpose as b64, Engine};
use zeroize::Zeroizing;

const MAX_DEPTH: usize = 3;
const MAX_ATTEMPTS: usize = 65_536;

struct Budget {
    remaining: usize,
    attempts: usize,
}

impl Budget {
    fn charge(&mut self, bytes: usize) -> Result<(), &'static str> {
        if bytes > self.remaining || self.attempts >= MAX_ATTEMPTS {
            return Err("privacy decoding budget reached");
        }
        self.remaining -= bytes;
        self.attempts += 1;
        Ok(())
    }
}

pub(super) fn check(text: &str, identifiers: &[String]) -> Result<(), &'static str> {
    let mut budget = Budget {
        remaining: MAX_TEXT_BYTES * 4,
        attempts: 0,
    };
    budget.charge(text.len())?;
    inspect(text, identifiers, 0, &mut budget)
}

fn decoded(
    bytes: &[u8],
    source: &str,
    identifiers: &[String],
    depth: usize,
    budget: &mut Budget,
) -> Result<(), &'static str> {
    if bytes == source.as_bytes() {
        return Ok(());
    }
    budget.charge(bytes.len())?;
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(());
    };
    if depth >= MAX_DEPTH {
        return Err("privacy encoding depth limit reached");
    }
    if detect::has_url_userinfo(text)
        || !detect::spans(text, identifiers)?.is_empty()
        || crate::leak::looks_like_key(bytes)
    {
        return Err("encoded private data requires local processing");
    }
    inspect(text, identifiers, depth + 1, budget)
}

fn inspect(
    text: &str,
    identifiers: &[String],
    depth: usize,
    budget: &mut Budget,
) -> Result<(), &'static str> {
    for decoder in [
        crate::text_decode::unescape_json,
        crate::text_decode::unescape_percent,
    ] {
        if let Some(bytes) = decoder(text.as_bytes()) {
            decoded(&bytes, text, identifiers, depth, budget)?;
        }
    }
    for token in text
        .as_bytes()
        .split(|b| !b.is_ascii_alphanumeric() && !b"+/=_-".contains(b))
    {
        if token.len() < 3 || token.len() % 4 == 1 {
            continue;
        }
        budget.charge(token.len())?;
        for engine in [
            &b64::STANDARD,
            &b64::STANDARD_NO_PAD,
            &b64::URL_SAFE,
            &b64::URL_SAFE_NO_PAD,
        ] {
            // Keep failed attempts in a wiped buffer as well as successful ones.
            let mut bytes = Zeroizing::new(Vec::new());
            if engine.decode_vec(token, &mut bytes).is_ok() {
                // A token may be only one word within a larger text.
                let source = std::str::from_utf8(token).unwrap();
                decoded(&bytes, source, identifiers, depth, budget)?;
                break;
            }
        }
    }
    Ok(())
}
