//! Prompt DLP (T9.02): block requests to an LLM provider that contain a
//! stored secret or something that looks like an API key. Conversation
//! text may first be redacted by prompt.rs; stored values are always blocked.

use kepr_core::generate::ZeroString;
pub(crate) use kepr_core::text_decode::{unescape_json, unescape_percent};

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
        .get_all(hyper::header::CONTENT_ENCODING)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
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

/// Screen session values, their secret fields, and the encodings used by
/// response masking. Decode JSON and percent escapes in either order once;
/// transformations are bounded and never resolve additional vault values.
pub fn scan(body: &[u8], secrets: &[(String, ZeroString)]) -> Verdict {
    let forms: Vec<_> = secrets
        .iter()
        .flat_map(|(name, value)| {
            let mut forms = crate::mask::forms(value.as_str());
            // Keep the existing whole-record protection as well as its fields.
            if value.len() >= MIN_SECRET_LEN && !forms.iter().any(|v| v.as_str() == value.as_str())
            {
                forms.extend(crate::mask::encoded_forms(value.as_str()));
                forms.push(ZeroString::from(value.as_str()));
            }
            forms.into_iter().map(move |v| (name.clone(), v))
        })
        .collect();
    let raw = scan_raw(body, &forms);
    if matches!(raw, Verdict::StoredSecret(_)) {
        return raw;
    }
    let json = unescape_json(body);
    let percent = unescape_percent(body);
    let json_percent = json.as_deref().and_then(|b| unescape_percent(b));
    let percent_json = percent.as_deref().and_then(|b| unescape_json(b));
    let mut verdict = raw;
    for decoded in [
        json.as_deref(),
        percent.as_deref(),
        json_percent.as_deref(),
        percent_json.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        match scan_raw(decoded, &forms) {
            v @ Verdict::StoredSecret(_) => return v,
            Verdict::LooksLikeKey if verdict == Verdict::Clean => verdict = Verdict::LooksLikeKey,
            _ => {}
        }
    }
    verdict
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
#[path = "dlp_regressions.rs"]
mod regressions;

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
