//! Prompt DLP (T9.02): block requests to an LLM provider that contain a
//! stored secret or something that looks like an API key. Decision 5:
//! block and tell the agent; never redact silently.

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
const MIN_SECRET_LEN: usize = 8;

pub fn scan(body: &[u8], secrets: &[(String, ZeroString)]) -> Verdict {
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
    fn clean_body_and_short_secrets_pass() {
        assert_eq!(scan(b"hello world", &secrets()), Verdict::Clean);
        let short = vec![("S".into(), ZeroString::from_string("abc".into()))];
        assert_eq!(scan(b"abc abc", &short), Verdict::Clean);
    }
}
