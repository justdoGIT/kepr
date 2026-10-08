//! Shapes of well-known API keys and private keys. Shared by kepr-gate's
//! prompt DLP and `kepr scan`, so both agree on what "looks like a key".
//! Matching is byte-level (memchr's SIMD substring search per prefix),
//! linear in the input, so the gate can run it on every request body.

/// One key shape: literal prefix, allowed body characters, body length.
pub struct Pattern {
    pub kind: &'static str,
    pub prefix: &'static [u8],
    pub body: fn(u8) -> bool,
    pub min: usize,
    /// `true` = the body must be exactly `min` long.
    pub exact: bool,
}

fn key_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn upper_digit(b: u8) -> bool {
    b.is_ascii_digit() || b.is_ascii_uppercase()
}

fn pem_tail(b: u8) -> bool {
    b.is_ascii_uppercase() || b == b' '
}

pub const PATTERNS: &[Pattern] = &[
    Pattern {
        kind: "Anthropic API key",
        prefix: b"sk-ant-",
        body: key_char,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "OpenAI project key",
        prefix: b"sk-proj-",
        body: key_char,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "OpenAI service-account key",
        prefix: b"sk-svcacct-",
        body: key_char,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "OpenAI admin key",
        prefix: b"sk-admin-",
        body: key_char,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "OpenRouter key",
        prefix: b"sk-or-",
        body: key_char,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "xAI API key",
        prefix: b"xai-",
        body: alnum,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "Groq API key",
        prefix: b"gsk_",
        body: alnum,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "Google API key",
        prefix: b"AIza",
        body: key_char,
        min: 35,
        exact: true,
    },
    Pattern {
        kind: "AWS access key id",
        prefix: b"AKIA",
        body: upper_digit,
        min: 16,
        exact: true,
    },
    Pattern {
        kind: "GitHub token",
        prefix: b"ghp_",
        body: alnum,
        min: 36,
        exact: true,
    },
    Pattern {
        kind: "GitHub OAuth token",
        prefix: b"gho_",
        body: alnum,
        min: 36,
        exact: true,
    },
    Pattern {
        kind: "GitHub user-to-server token",
        prefix: b"ghu_",
        body: alnum,
        min: 36,
        exact: true,
    },
    Pattern {
        kind: "GitHub app token",
        prefix: b"ghs_",
        body: alnum,
        min: 36,
        exact: true,
    },
    Pattern {
        kind: "GitHub fine-grained token",
        prefix: b"github_pat_",
        body: key_char,
        min: 40,
        exact: false,
    },
    Pattern {
        kind: "GitLab token",
        prefix: b"glpat-",
        body: key_char,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "Slack token",
        prefix: b"xoxb-",
        body: key_char,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "Slack user token",
        prefix: b"xoxp-",
        body: key_char,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "Stripe live key",
        prefix: b"sk_live_",
        body: alnum,
        min: 20,
        exact: false,
    },
    // T2.04 (batch: aws): the CLI presets' key shapes.
    Pattern {
        kind: "Stripe test key",
        prefix: b"sk_test_",
        body: alnum,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "Stripe restricted key",
        prefix: b"rk_live_",
        body: alnum,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "Stripe restricted test key",
        prefix: b"rk_test_",
        body: alnum,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "npm token",
        prefix: b"npm_",
        body: alnum,
        min: 36,
        exact: true,
    },
    Pattern {
        kind: "Google OAuth access token",
        prefix: b"ya29.",
        body: key_char,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "Docker access token",
        prefix: b"dckr_pat_",
        body: key_char,
        min: 20,
        exact: false,
    },
    Pattern {
        kind: "private key",
        prefix: b"-----BEGIN ",
        body: pem_tail,
        min: 11,
        exact: false,
    },
];

/// A match: byte offset, total length (prefix + body), and its kind.
#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub offset: usize,
    pub len: usize,
    pub kind: &'static str,
}

fn matches_at(p: &Pattern, text: &[u8], i: usize) -> Option<usize> {
    let rest = &text[i + p.prefix.len()..];
    let n = rest.iter().take_while(|b| (p.body)(**b)).count();
    if p.kind == "private key" {
        // "-----BEGIN [A-Z ]*PRIVATE KEY-----"
        let tail = &rest[..n];
        let ok = tail.ends_with(b"PRIVATE KEY") && rest[n..].starts_with(b"-----");
        return ok.then_some(p.prefix.len() + n + 5);
    }
    let ok = if p.exact { n == p.min } else { n >= p.min };
    ok.then_some(p.prefix.len() + n)
}

/// Every key-shaped substring in `text`.
pub fn find_all(text: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for p in PATTERNS {
        for i in memchr::memmem::find_iter(text, p.prefix) {
            if let Some(len) = matches_at(p, text, i) {
                hits.push(Hit {
                    offset: i,
                    len,
                    kind: p.kind,
                });
            }
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits
}

pub fn looks_like_key(text: &[u8]) -> bool {
    !find_all(text).is_empty()
}

#[cfg(test)]
mod tests {

    /// Every key prefix in the provider table has a leak shape, so the
    /// gate's DLP, `kepr scan` and the harness hooks know every key kepr
    /// can store.
    #[test]
    fn every_provider_prefix_has_a_pattern() {
        for p in crate::providers::PROVIDERS {
            for prefix in p.prefixes {
                assert!(
                    PATTERNS.iter().any(|pat| pat.prefix == prefix.as_bytes()),
                    "{} prefix {prefix} has no leak pattern",
                    p.name
                );
            }
        }
    }
    use super::*;

    #[test]
    fn cli_preset_shapes() {
        for k in [
            "sk_test_51HabcdefghijklmnopqrstUV",
            "rk_live_51HabcdefghijklmnopqrstUV",
            "npm_abcdefghijklmnopqrstuvwxyz0123456789",
            "ya29.a0AfB_byCabcdefghijklmnop",
            "dckr_pat_abcdefghijklmnopqrstu",
        ] {
            assert!(looks_like_key(format!("x {k} y").as_bytes()), "{k}");
        }
        assert!(!looks_like_key(b"npm_install"));
        assert!(!looks_like_key(b"ya29.short"));
    }

    #[test]
    fn known_shapes() {
        assert!(looks_like_key(b"x AKIAABCDEFGHIJKLMNOP y"));
        assert!(looks_like_key(b"sk-ant-api03-abcdefghijklmnopqrstu"));
        assert!(looks_like_key(b"ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(looks_like_key(b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc"));
        assert!(looks_like_key(b"-----BEGIN PRIVATE KEY-----"));
        assert!(!looks_like_key(b"-----BEGIN CERTIFICATE-----"));
        assert!(!looks_like_key(b"AKIA too short"));
        assert!(!looks_like_key(
            b"kepr-ph-0123456789abcdef-0000-0123456789abcdef"
        ));
    }

    #[test]
    fn hits_have_offsets_and_kinds() {
        let t = b"a=xai-abcdefghijklmnopqrstuv\nb=AKIAABCDEFGHIJKLMNOP";
        let h = find_all(t);
        assert_eq!(h.len(), 2);
        assert_eq!((h[0].offset, h[0].kind), (2, "xAI API key"));
        assert_eq!(
            &t[h[1].offset..h[1].offset + h[1].len],
            b"AKIAABCDEFGHIJKLMNOP"
        );
    }
}
