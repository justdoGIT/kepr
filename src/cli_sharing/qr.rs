// cli_sharing/qr.rs — terminal QR codes for share links (T6.04) and
// envelopes (T11.15). Long text is split into numbered chunks
// `KQ<i>/<n>:<part>`; `join` puts them back together on the receiving
// side, in any order.

use qrcode::render::unicode::Dense1x2;
use qrcode::{EcLevel, QrCode};

/// Characters per chunk: small enough for a readable terminal code.
pub const CHUNK: usize = 600;
/// More chunks than any envelope needs; bounds what `join` allocates.
const MAX_CHUNKS: usize = 100;

pub fn render(text: &str) -> Result<String, String> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L)
        .map_err(|e| format!("cannot make a QR code: {e}"))?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

/// `text` as numbered chunks of at most `size` characters each.
pub fn chunks(text: &str, size: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let parts: Vec<String> = chars
        .chunks(size.max(1))
        .map(|c| c.iter().collect())
        .collect();
    let n = parts.len();
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| format!("KQ{}/{n}:{p}", i + 1))
        .collect()
}

/// Rebuild text from scanned chunks (one per line, any order). Input
/// without chunk headers comes back unchanged.
pub fn join(input: &str) -> Result<String, String> {
    let lines: Vec<&str> = input
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if !lines.first().is_some_and(|l| l.starts_with("KQ")) {
        return Ok(input.trim().to_string());
    }
    let mut parts: Vec<Option<&str>> = Vec::new();
    for l in lines {
        let bad = || {
            format!(
                "not a kepr QR chunk: {}",
                l.chars().take(12).collect::<String>()
            )
        };
        let (head, body) = l
            .strip_prefix("KQ")
            .and_then(|r| r.split_once(':'))
            .ok_or_else(bad)?;
        let (i, n) = head.split_once('/').ok_or_else(bad)?;
        let (i, n): (usize, usize) = (i.parse().map_err(|_| bad())?, n.parse().map_err(|_| bad())?);
        if n > MAX_CHUNKS {
            return Err("too many QR chunks".into());
        }
        if parts.is_empty() {
            parts = vec![None; n];
        }
        if n != parts.len() || i == 0 || i > n {
            return Err("the QR chunks don't belong together".into());
        }
        parts[i - 1] = Some(body);
    }
    let missing: Vec<String> = (1..=parts.len())
        .filter(|i| parts[i - 1].is_none())
        .map(|i| i.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(format!("QR chunk(s) {} missing", missing.join(", ")));
    }
    Ok(parts.into_iter().flatten().collect())
}

/// Print `text` as one or more QR codes on stderr.
pub fn print(text: &str) -> Result<(), String> {
    let all = if text.len() <= CHUNK {
        vec![text.to_string()]
    } else {
        chunks(text, CHUNK)
    };
    let n = all.len();
    for (i, c) in all.iter().enumerate() {
        if n > 1 {
            eprintln!("QR {}/{n}:", i + 1);
        }
        eprintln!("{}", render(c)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_round_trip_in_any_order() {
        let text = "kepr-share2-".to_string() + &"A".repeat(1500);
        let mut c = chunks(&text, CHUNK);
        assert_eq!(c.len(), 3);
        assert!(c[0].starts_with("KQ1/3:"));
        c.reverse();
        assert_eq!(join(&c.join("\n")).unwrap(), text);
        assert!(join(&c[..2].join("\n")).unwrap_err().contains("missing"));
        assert_eq!(join("  kepr-share2-x \n").unwrap(), "kepr-share2-x");
        assert!(join("KQ1/2:a\nKQ1/3:b").is_err());
        assert!(join("KQ1/4000000000:a").unwrap_err().contains("too many"));
        let wide = chunks("ééé", 2);
        assert_eq!(wide, ["KQ1/2:éé", "KQ2/2:é"]);
    }

    #[test]
    fn renders_a_link() {
        let q = render("kepr://share/0123456789abcdef0123456789abcdef#key").unwrap();
        assert!(q.lines().count() > 10);
    }
}
