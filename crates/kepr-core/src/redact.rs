//! Redaction for conversation text. Uses the gate's key shapes, and keeps
//! source offsets when scanning JSON escapes so surrounding code stays intact.

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

/// Decode one layer for inspection only, retaining each byte's source span.
fn decoded(text: &[u8]) -> (Vec<u8>, Vec<(usize, usize)>) {
    let (mut out, mut spans) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < text.len() {
        let start = i;
        let mut buf = [0u8; 4];
        let bytes: &[u8] = if text[i] == b'\\' && i + 1 < text.len() {
            let e = text[i + 1];
            i += 2;
            let cp = (e == b'u')
                .then(|| text.get(i..i + 4))
                .flatten()
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u32::from_str_radix(h, 16).ok());
            if let Some(cp) = cp {
                i += 4;
                char::from_u32(cp)
                    .unwrap_or('\u{fffd}')
                    .encode_utf8(&mut buf)
                    .as_bytes()
            } else {
                buf[0] = match e {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'b' => 8,
                    b'f' => 12,
                    other => other,
                };
                &buf[..1]
            }
        } else {
            i += 1;
            &text[start..i]
        };
        out.extend_from_slice(bytes);
        spans.extend(std::iter::repeat_n((start, i), bytes.len()));
    }
    (out, spans)
}

/// Replace key shapes (including JSON-escaped ones) and entire PEM blocks.
/// Counts replacements, never returns the matched values separately.
pub fn text(text: &str) -> (String, usize) {
    let mut hits = ranges(text.as_bytes());
    if text.contains('\\') {
        let (plain, spans) = decoded(text.as_bytes());
        hits.extend(
            ranges(&plain)
                .into_iter()
                .map(|(a, b, kind)| (spans[a].0, spans[b - 1].1, kind)),
        );
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
    (out, count)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (out, count) = text(&format!("{header}\npayload"));
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
