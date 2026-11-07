//! Prompt DLP (T9.02): block requests to an LLM provider that contain a
//! stored secret or something that looks like an API key. Conversation
//! text may first be redacted by prompt.rs; stored values are always blocked.

use kepr_core::generate::ZeroString;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    /// Contains the value of this stored credential NAME.
    StoredSecret(String),
    LooksLikeKey,
}

/// Values shorter than this are not scanned for, to avoid blocking on
/// short common strings.
pub(crate) const MIN_SECRET_LEN: usize = 8;

/// Why a request must not leave, or `None`. Covers the body (raw and
/// JSON-decoded), the path and query, and header values; a compressed
/// body can't be scanned, so it is refused.
pub fn check(
    parts: &hyper::http::request::Parts,
    body: &[u8],
    secrets: &[(String, ZeroString)],
) -> Option<String> {
    let encoded = parts
        .headers
        .get(hyper::header::CONTENT_ENCODING)
        .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
    if encoded {
        return Some("kepr blocked this request: compressed request bodies can't be checked for secrets; send it uncompressed.".into());
    }
    let mut meta = zeroize::Zeroizing::new(parts.uri.to_string().into_bytes());
    for (_, v) in &parts.headers {
        meta.push(b'\n');
        meta.extend_from_slice(v.as_bytes());
    }
    let verdict = match scan(body, secrets) {
        Verdict::Clean => scan(&meta, secrets),
        v => v,
    };
    match verdict {
        Verdict::Clean => None,
        Verdict::StoredSecret(n) => Some(format!(
            "kepr blocked this request: it contains the stored secret {n}. Remove it and retry."
        )),
        Verdict::LooksLikeKey => Some(
            "kepr blocked this request: it contains what looks like an API key. Remove it and retry."
                .to_string(),
        ),
    }
}

/// Scan `body` as sent and, when it has JSON escapes, as decoded: a
/// serializer escapes `"` and `\\` in a value, and `\\u0073…` spells
/// any text at all, so a raw byte match alone misses both.
pub fn scan(body: &[u8], secrets: &[(String, ZeroString)]) -> Verdict {
    let raw = scan_raw(body, secrets);
    if matches!(raw, Verdict::StoredSecret(_)) {
        return raw;
    }
    let decoded = unescape_json(body).map(|b| scan_raw(&b, secrets));
    match decoded {
        Some(v @ Verdict::StoredSecret(_)) => v,
        Some(v) if raw == Verdict::Clean => v,
        _ => raw,
    }
}

/// JSON string escapes decoded in place (`\\uXXXX`, `\\"`, `\\n`, …);
/// `None` when there are none. Not a JSON parser: it decodes escapes
/// wherever they are, which is what a scan wants.
pub(crate) fn unescape_json(body: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    memchr::memchr(b'\\', body)?;
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(body.len()));
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'\\' || i + 1 >= body.len() {
            out.push(body[i]);
            i += 1;
            continue;
        }
        let e = body[i + 1];
        i += 2;
        match e {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'u' => {
                let hex = body.get(i..i + 4).and_then(|h| std::str::from_utf8(h).ok());
                match hex.and_then(|h| u32::from_str_radix(h, 16).ok()) {
                    Some(cp) => {
                        let c = char::from_u32(cp).unwrap_or('\u{fffd}');
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                        i += 4;
                    }
                    None => out.extend_from_slice(b"\\u"),
                }
            }
            other => out.push(other), // \" \\ \/ and anything else
        }
    }
    Some(out)
}

fn scan_raw(body: &[u8], secrets: &[(String, ZeroString)]) -> Verdict {
    for (name, v) in secrets {
        let needle = v.as_str().as_bytes();
        if needle.len() >= MIN_SECRET_LEN && memchr::memmem::find(body, needle).is_some() {
            return Verdict::StoredSecret(name.clone());
        }
    }
    if looks_like_key(body) {
        return Verdict::LooksLikeKey;
    }
    Verdict::Clean
}

pub fn looks_like_key(body: &[u8]) -> bool {
    kepr_core::leak::looks_like_key(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> Vec<(String, ZeroString)> {
        vec![(
            "MY_KEY".into(),
            ZeroString::from_string("s3cr3t-value-123".into()),
        )]
    }

    #[test]
    fn stored_secret_detected() {
        let body = br#"{"messages":[{"content":"here: s3cr3t-value-123"}]}"#;
        assert_eq!(
            scan(body, &secrets()),
            Verdict::StoredSecret("MY_KEY".into())
        );
    }

    #[test]
    fn patterns_detected() {
        assert!(looks_like_key(b"x AKIAABCDEFGHIJKLMNOP y"));
        assert!(looks_like_key(b"sk-ant-api03-abcdefghijklmnopqrstu"));
        assert!(looks_like_key(b"ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(!looks_like_key(b"AKIA too short"));
        assert!(!looks_like_key(
            b"kepr-ph-0123456789abcdef-0000-0123456789abcdef"
        ));
    }

    #[test]
    fn escaped_secrets_are_found() {
        let quoted = vec![(
            "Q".into(),
            ZeroString::from_string(r#"pa"ss\word-1"#.into()),
        )];
        let body = br#"{"content":"pa\"ss\\word-1"}"#;
        assert_eq!(scan(body, &quoted), Verdict::StoredSecret("Q".into()));
        // \u escapes spelling the stored value out.
        let spelled: String = "s3cr3t-value-123"
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect();
        let body = format!(r#"{{"content":"{spelled}"}}"#);
        assert_eq!(
            scan(body.as_bytes(), &secrets()),
            Verdict::StoredSecret("MY_KEY".into())
        );
    }

    #[test]
    fn a_raw_key_shape_does_not_hide_an_escaped_stored_secret() {
        let key = format!("sk-proj-{}", "a".repeat(24));
        let escaped: String = "s3cr3t-value-123"
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect();
        let body = format!(r#"{{"input":"{key} {escaped}"}}"#);
        assert_eq!(
            scan(body.as_bytes(), &secrets()),
            Verdict::StoredSecret("MY_KEY".into())
        );
    }

    #[test]
    fn clean_body_and_short_secrets_pass() {
        assert_eq!(scan(b"hello world", &secrets()), Verdict::Clean);
        let short = vec![("S".into(), ZeroString::from_string("abc".into()))];
        assert_eq!(scan(b"abc abc", &short), Verdict::Clean);
    }
}
