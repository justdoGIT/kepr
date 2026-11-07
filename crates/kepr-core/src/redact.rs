//! Redaction for conversation text. Uses the gate's key shapes, and keeps
//! source offsets when scanning JSON escapes so surrounding code stays intact.

use std::borrow::Cow;

use crate::leak;

fn ranges(text: &[u8]) -> Vec<(usize, usize, &'static str)> {
    leak::find_all(text)
        .into_iter()
        .map(|h| {
            let mut end = h.offset + h.len;
            if h.kind == "private key" {
                let label = &text[h.offset + 11..end - 5];
                let marker = [b"-----END ".as_slice(), label, b"-----"].concat();
                // A complete PEM block includes its payload. For an unfinished
                // block, withhold the remainder only if a payload line follows.
                if let Some(n) = memchr::memmem::find(&text[end..], &marker) {
                    end += n + marker.len();
                } else if text[end..].starts_with(b"\n") || text[end..].starts_with(b"\r\n") {
                    end = text.len();
                }
            }
            (h.offset, end, h.kind)
        })
        .collect()
}

/// Decode a single source unit; source offsets are reconstructed only for hits.
fn unit(text: &[u8], start: usize, buf: &mut [u8; 4]) -> (usize, usize) {
    if text[start] != b'\\' || start + 1 == text.len() {
        buf[0] = text[start];
        return (start + 1, 1);
    }
    let e = text[start + 1];
    if e == b'u' {
        if let Some(cp) = text
            .get(start + 2..start + 6)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u32::from_str_radix(h, 16).ok())
        {
            let n = char::from_u32(cp)
                .unwrap_or('\u{fffd}')
                .encode_utf8(buf)
                .len();
            return (start + 6, n);
        }
    }
    buf[0] = match e {
        b'n' => b'\n',
        b'r' => b'\r',
        b't' => b'\t',
        b'b' => 8,
        b'f' => 12,
        other => other,
    };
    (start + 2, 1)
}

fn escaped_ranges(text: &[u8]) -> Vec<(usize, usize, &'static str)> {
    let mut plain = Vec::with_capacity(text.len());
    let (mut i, mut buf) = (0, [0; 4]);
    while i < text.len() {
        let (next, n) = unit(text, i, &mut buf);
        plain.extend_from_slice(&buf[..n]);
        i = next;
    }
    let mut hits = ranges(&plain);
    // Only match endpoints need source positions: O(matches), not O(input bytes).
    let mut ends: Vec<_> = hits
        .iter()
        .enumerate()
        .flat_map(|(id, &(a, b, _))| [(a, id, false), (b, id, true)])
        .collect();
    ends.sort_unstable();
    let (mut source, mut decoded) = (0, 0);
    for (target, id, end) in ends {
        while decoded < target {
            let (next, n) = unit(text, source, &mut buf);
            if decoded + n > target {
                break;
            }
            source = next;
            decoded += n;
        }
        let offset = if decoded == target || !end {
            source
        } else {
            unit(text, source, &mut buf).0
        };
        if end {
            hits[id].1 = offset;
        } else {
            hits[id].0 = offset;
        }
    }
    hits
}

/// Replace key shapes (including JSON-escaped ones) and entire PEM blocks.
/// Counts replacements, never returns the matched values separately.
pub fn text(text: &str) -> (Cow<'_, str>, usize) {
    let mut hits = ranges(text.as_bytes());
    if text.contains('\\') {
        hits.extend(escaped_ranges(text.as_bytes()));
    }
    if hits.is_empty() {
        return (Cow::Borrowed(text), 0);
    }
    hits.sort_by_key(|&(a, b, _)| (a, std::cmp::Reverse(b)));
    let (mut out, mut at, mut count) = (String::new(), 0, 0);
    for (start, end, kind) in hits {
        if start < at {
            if end > at {
                at = end;
            }
            continue;
        }
        out.push_str(&text[at..start]);
        out.push_str(&format!("[{kind} removed by kepr]"));
        at = end;
        count += 1;
    }
    out.push_str(&text[at..]);
    (Cow::Owned(out), count)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clean_text_is_borrowed_even_with_many_escapes() {
        for text in ["safe", r"\n\n\u0061 safe λ"] {
            assert!(matches!(super::text(text), (Cow::Borrowed(_), 0)));
        }
    }

    #[test]
    fn complete_and_truncated_pem_payloads_are_removed() {
        let header = format!("-----BEGIN {}-----", "PRIVATE KEY");
        let footer = format!("-----END {}-----", "PRIVATE KEY");
        for separator in ["\n", "\\n", "\r\n"] {
            let input =
                format!("before {header}{separator}private-test-payload{separator}{footer} after");
            assert_eq!(
                text(&input),
                ("before [private key removed by kepr] after".into(), 1)
            );
        }
        let input = format!("{header}\npayload");
        let (out, count) = text(&input);
        assert_eq!(count, 1);
        assert!(!out.contains("payload"));
    }

    #[test]
    fn escaped_keys_preserve_surrounding_source_and_unicode() {
        let key = format!("sk-proj-{}", "a".repeat(24));
        let escaped: String = key
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect();
        let input = format!("é {{\"value\":\"{escaped}\"}} λ");
        assert_eq!(
            text(&input),
            (
                "é {\"value\":\"[OpenAI project key removed by kepr]\"} λ".into(),
                1
            )
        );
        let safe = r#"kepr-ph-example \\n \"safe\" λ"#;
        assert_eq!(text(safe), (safe.into(), 0));
        assert_eq!(text(&text(&input).0).1, 0);
    }
}
