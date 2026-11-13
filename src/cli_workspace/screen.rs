//! Shared key shapes, with bounded recognized decoding; findings stay local.

use super::paths::MAX_FILE_BYTES;
use base64::{engine::general_purpose as b64, Engine};
use zeroize::Zeroizing;

const SCREEN_ERROR: &str = "workspace input contains credential-shaped content";

struct Budget {
    bytes: usize,
    attempts: usize,
}

impl Budget {
    fn charge(&mut self, bytes: usize) -> Result<(), &'static str> {
        if bytes > self.bytes || self.attempts >= 65_536 {
            return Err("workspace credential-screening limit reached");
        }
        self.bytes -= bytes;
        self.attempts += 1;
        Ok(())
    }
}

pub(super) fn check(bytes: &[u8]) -> Result<(), &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "workspace inputs must be UTF-8 text")?;
    check_text(text)
}

pub(super) fn source(bytes: &[u8]) -> Result<bool, &'static str> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(false);
    };
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Ok(false);
    }
    check_text(text)?;
    Ok(true)
}

fn check_text(text: &str) -> Result<(), &'static str> {
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err("workspace input contains unsupported control characters");
    }
    let mut budget = Budget {
        bytes: MAX_FILE_BYTES * 8,
        attempts: 0,
    };
    inspect(text, 0, &mut budget)
}

fn decoded(
    bytes: &[u8],
    source: &str,
    depth: usize,
    budget: &mut Budget,
) -> Result<(), &'static str> {
    if bytes == source.as_bytes() {
        return Ok(());
    }
    budget.charge(bytes.len())?;
    if kepr_core::leak::looks_like_key(bytes) {
        return Err(SCREEN_ERROR);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if depth >= 3 {
            return Err("workspace credential-decoding depth limit reached");
        }
        inspect(text, depth + 1, budget)?;
    }
    Ok(())
}

fn inspect(text: &str, depth: usize, budget: &mut Budget) -> Result<(), &'static str> {
    budget.charge(text.len())?;
    if kepr_core::leak::looks_like_key(text.as_bytes()) {
        return Err(SCREEN_ERROR);
    }
    for decoder in [
        kepr_core::text_decode::unescape_json,
        kepr_core::text_decode::unescape_percent,
    ] {
        if let Some(bytes) = decoder(text.as_bytes()) {
            decoded(&bytes, text, depth, budget)?;
        }
    }
    for token in text
        .as_bytes()
        .split(|b| !b.is_ascii_alphanumeric() && !b"+/=_-".contains(b))
    {
        if token.len() < 8 || token.len() % 4 == 1 {
            continue;
        }
        budget.charge(token.len())?;
        for engine in [
            &b64::STANDARD,
            &b64::STANDARD_NO_PAD,
            &b64::URL_SAFE,
            &b64::URL_SAFE_NO_PAD,
        ] {
            let mut bytes = Zeroizing::new(Vec::new());
            if engine.decode_vec(token, &mut bytes).is_ok() {
                decoded(
                    &bytes,
                    std::str::from_utf8(token).map_err(|_| SCREEN_ERROR)?,
                    depth,
                    budget,
                )?;
                break;
            }
        }
    }
    Ok(())
}
