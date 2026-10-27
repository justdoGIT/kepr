//! Honeytokens (T9.08): decoy keys in a provider's real format, and the
//! fingerprint the daemon keeps of each so the gate can ask "is this
//! key-shaped string a planted canary?" without holding the list.
//!
//! A decoy is random characters in the provider's key alphabet behind
//! its real prefix, at a real key's length; it passes kepr's own format
//! checks (`providers::detect`, the `leak` shapes) and authenticates
//! nowhere.

use sha2::{Digest, Sha256};

/// One provider's key shape: `prefix`, `body` random characters (with
/// `infix` spliced in at `infix.0`), then `suffix`.
pub struct Shape {
    pub provider: &'static str,
    /// The variable a decoy is planted as by default.
    pub var: &'static str,
    prefix: &'static str,
    body: usize,
    alphabet: &'static [u8],
    infix: Option<(usize, &'static str)>,
    suffix: &'static str,
}

const KEY: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &[u8] = b"0123456789abcdef";

pub const SHAPES: &[Shape] = &[
    Shape {
        provider: "anthropic",
        var: "ANTHROPIC_API_KEY",
        prefix: "sk-ant-api03-",
        body: 93,
        alphabet: KEY,
        infix: None,
        suffix: "AA",
    },
    Shape {
        provider: "openai",
        var: "OPENAI_API_KEY",
        prefix: "sk-proj-",
        body: 148,
        alphabet: KEY,
        infix: Some((74, "T3BlbkFJ")),
        suffix: "",
    },
    Shape {
        provider: "xai",
        var: "XAI_API_KEY",
        prefix: "xai-",
        body: 80,
        alphabet: ALNUM,
        infix: None,
        suffix: "",
    },
    Shape {
        provider: "google",
        var: "GEMINI_API_KEY",
        prefix: "AIza",
        body: 35,
        alphabet: KEY,
        infix: None,
        suffix: "",
    },
    Shape {
        provider: "groq",
        var: "GROQ_API_KEY",
        prefix: "gsk_",
        body: 52,
        alphabet: ALNUM,
        infix: None,
        suffix: "",
    },
    Shape {
        provider: "openrouter",
        var: "OPENROUTER_API_KEY",
        prefix: "sk-or-v1-",
        body: 64,
        alphabet: HEX,
        infix: None,
        suffix: "",
    },
    Shape {
        provider: "github",
        var: "GITHUB_TOKEN",
        prefix: "ghp_",
        body: 36,
        alphabet: ALNUM,
        infix: None,
        suffix: "",
    },
];

pub fn shape(provider: &str) -> Option<&'static Shape> {
    SHAPES.iter().find(|s| s.provider == provider)
}

/// The providers kepr can make decoys for.
pub fn supported() -> Vec<&'static str> {
    SHAPES.iter().map(|s| s.provider).collect()
}

/// `n` characters drawn uniformly from `alphabet` (rejection sampling).
fn random_from(alphabet: &[u8], n: usize) -> Result<String, String> {
    let limit = 256 - 256 % alphabet.len();
    let mut out = String::with_capacity(n);
    let mut buf = [0u8; 64];
    while out.len() < n {
        getrandom::fill(&mut buf).map_err(|e| format!("CSPRNG failure: {e}"))?;
        for b in buf.iter().map(|b| *b as usize).filter(|b| *b < limit) {
            if out.len() < n {
                out.push(alphabet[b % alphabet.len()] as char);
            }
        }
    }
    Ok(out)
}

/// A fresh decoy key for `provider`.
pub fn make(provider: &str) -> Result<String, String> {
    let s = shape(provider).ok_or_else(|| {
        format!(
            "no decoy format for `{provider}` (one of: {})",
            supported().join(", ")
        )
    })?;
    let mut body = random_from(s.alphabet, s.body)?;
    if let Some((at, infix)) = s.infix {
        body.insert_str(at, infix);
    }
    Ok(format!("{}{body}{}", s.prefix, s.suffix))
}

/// What the daemon keeps of a canary and the gate sends for every
/// key-shaped string it sees: SHA-256 over a fixed label and the value.
pub fn fingerprint(value: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"kepr-canary-v1\0");
    h.update(value);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoys_pass_the_providers_format_checks() {
        for s in SHAPES {
            let v = make(s.provider).unwrap();
            let p = crate::providers::detect(None, &v).expect(s.provider);
            assert_eq!(p.name, s.provider);
            let hits = crate::leak::find_all(v.as_bytes());
            assert_eq!(hits.len(), 1, "{v}");
            assert_eq!((hits[0].offset, hits[0].len), (0, v.len()), "{v}");
            assert_ne!(make(s.provider).unwrap(), v, "random");
        }
        assert!(make("mistral").unwrap_err().contains("anthropic"));
        let o = make("openai").unwrap();
        assert_eq!(&o[8 + 74..8 + 82], "T3BlbkFJ");
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        assert_eq!(fingerprint(b"a"), fingerprint(b"a"));
        assert_ne!(fingerprint(b"a"), fingerprint(b"b"));
        assert_eq!(fingerprint(b"a").len(), 64);
    }
}
