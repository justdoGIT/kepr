// generate.rs — CSPRNG secret generation
//
// All randomness from /dev/urandom directly.
// No modulo bias — uses rejection sampling.
// Returns ZeroString — memory zeroed on drop.

use std::fs;
use std::io::Read;
use zeroize::Zeroize;

// ── ZeroString ────────────────────────────────────────────────────────────────

/// A String that zeroes its memory on drop.
/// Used for all secret values throughout kepr.
pub struct ZeroString(pub String);

impl Drop for ZeroString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::ops::Deref for ZeroString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

// Debug must never leak the inner value: secret material is the entire
// reason this type exists. The redacting impl lets the type appear in
// `Result<ZeroString, _>::expect_err`, dbg!() during incident response,
// or any other context where Debug is structurally required, without
// any path through which the secret can land in a log line.
impl std::fmt::Debug for ZeroString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZeroString(<redacted>)")
    }
}

// Display intentionally DOES print the inner value. The CLI's
// `kepr get` is the legitimate use site (`println!("{value}")` and
// `eval "$(kepr get … --export)"`); without Display the call sites
// would have to reach for `value.as_str()` and lose the type's
// guarantee that any rendering path goes through one place we
// audit. Anyone wanting a redacted form must use Debug explicitly.
impl std::fmt::Display for ZeroString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// Serialise as a plain JSON string so the wire format is unchanged
// from the previous `value: String`. Old daemons still talk to new
// clients and vice versa. The deserializer accepts a String and
// moves it into a ZeroString; the bytes inside the resulting
// ZeroString get zeroized on drop, which closes the gap the public
// review flagged about secret values lingering in serde-allocated
// buffers on the client side.
impl serde::Serialize for ZeroString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ZeroString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(ZeroString::from_string(s))
    }
}

// Convenience conversions so call sites and tests can use the
// ergonomic `"v".into()` idiom rather than `from_string("v".into())`.
impl From<String> for ZeroString {
    fn from(s: String) -> Self {
        ZeroString::from_string(s)
    }
}

impl From<&str> for ZeroString {
    fn from(s: &str) -> Self {
        ZeroString::from_string(s.to_string())
    }
}

impl ZeroString {
    pub fn from_string(s: String) -> Self {
        Self(s)
    }
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    /// Borrow the inner string as `&str`. Mirrors `String::as_str` but on
    /// stable Rust (the upstream `str::as_str` was added behind the
    /// `str_as_str` unstable feature gate). Use this rather than `.deref()`
    /// in test assertions and call sites that just need a comparison view.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn to_owned_string(&self) -> String {
        self.0.clone()
    }
}

// ── Gen kind ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub enum GenKind {
    Hex,
    Base62,
    Pass,
    Uuid,
    /// Diceware passphrase (P5.6): 6 words from the EFF large wordlist,
    /// ~77.5 bits.
    Words,
}

/// The EFF large wordlist (7776 words, one per line; CC BY 3.0, Electronic
/// Frontier Foundation).
const EFF_WORDS: &str = include_str!("eff_large_wordlist.txt");
const PASSPHRASE_WORDS: usize = 6;

impl GenKind {
    // We want Option<Self> here so callers can chain via .and_then on
    // an Option<&str> (see daemon_handlers::handle_set). Implementing
    // std::str::FromStr would force a Result with an associated Err
    // type, which loses that ergonomic and means three callsites
    // change shape for no real benefit.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "hex" => Some(Self::Hex),
            "base62" => Some(Self::Base62),
            "pass" => Some(Self::Pass),
            "uuid" => Some(Self::Uuid),
            "words" => Some(Self::Words),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Base62 => "base62",
            Self::Pass => "pass",
            Self::Uuid => "uuid",
            Self::Words => "words",
        }
    }
}

// ── RNG ───────────────────────────────────────────────────────────────────────

struct UrandomRng;

impl UrandomRng {
    fn bytes(n: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; n];
        let mut f =
            fs::File::open("/dev/urandom").map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
        f.read_exact(&mut buf)
            .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
        Ok(buf)
    }

    /// Rejection sampling — uniform distribution, no modulo bias.
    fn sample(alphabet: &[u8], len: usize) -> Result<Vec<u8>, String> {
        let max = (256 / alphabet.len()) * alphabet.len();
        let mut result = Vec::with_capacity(len);
        while result.len() < len {
            let batch = Self::bytes(len * 3)?;
            for &b in &batch {
                if result.len() >= len {
                    break;
                }
                if (b as usize) < max {
                    result.push(alphabet[b as usize % alphabet.len()]);
                }
            }
        }
        Ok(result)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn generate_secret(kind: GenKind) -> Result<ZeroString, String> {
    let s = match kind {
        GenKind::Hex => {
            let bytes = UrandomRng::bytes(32)?;
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        }

        GenKind::Base62 => {
            const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            String::from_utf8(UrandomRng::sample(ALPHA, 48)?)
                .map_err(|e| format!("base62 generation: invalid UTF-8: {e}"))?
        }

        GenKind::Pass => {
            const ALPHA: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
            loop {
                let bytes = UrandomRng::sample(ALPHA, 32)?;
                let s = String::from_utf8(bytes)
                    .map_err(|e| format!("pass generation: invalid UTF-8: {e}"))?;
                if s.bytes().any(|b| b.is_ascii_uppercase())
                    && s.bytes().any(|b| b.is_ascii_lowercase())
                    && s.bytes().any(|b| b.is_ascii_digit())
                    && s.bytes().any(|b| b"!@#$%^&*-_=+".contains(&b))
                {
                    break s;
                }
            }
        }

        GenKind::Words => {
            let words: Vec<&str> = EFF_WORDS.lines().collect();
            let n = words.len();
            let max = (65_536 / n) * n; // rejection bound: no modulo bias
            let mut out = Vec::with_capacity(PASSPHRASE_WORDS);
            while out.len() < PASSPHRASE_WORDS {
                for pair in UrandomRng::bytes(32)?.chunks_exact(2) {
                    let v = u16::from_le_bytes([pair[0], pair[1]]) as usize;
                    if v < max && out.len() < PASSPHRASE_WORDS {
                        out.push(words[v % n]);
                    }
                }
            }
            out.join("-")
        }

        GenKind::Uuid => {
            let b = UrandomRng::bytes(16)?;
            // v4 third group is exactly 4 chars: literal '4' + 3 hex digits
            // (nibble from b[6] + full byte b[7]). {:x} on a masked nibble
            // emits one hex char; {:02x} on b[7] emits two.
            format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                b[0],b[1],b[2],b[3],
                b[4],b[5],
                b[6]&0x0f, b[7],
                (b[8]&0x3f)|0x80, b[9],
                b[10],b[11],b[12],b[13],b[14],b[15]
            )
        }
    };

    Ok(ZeroString(s))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_the_eff_large_list() {
        let words: Vec<&str> = EFF_WORDS.lines().collect();
        assert_eq!(words.len(), 7776);
        let unique: std::collections::HashSet<&&str> = words.iter().collect();
        assert_eq!(unique.len(), 7776);
        assert_eq!((words[0], words[7775]), ("abacus", "zoom"));
        let p = generate_secret(GenKind::Words).unwrap();
        let parts: Vec<&str> = p.as_str().split('-').collect();
        assert_eq!(parts.len(), PASSPHRASE_WORDS);
        assert!(parts.iter().all(|w| unique.contains(w)));
    }

    #[test]
    fn zero_string_debug_does_not_leak_value() {
        // Pin the contract: Debug formatting of a ZeroString must never
        // print the inner value, so any code path that logs a Debug
        // representation (panic messages, dbg! macros, error reports)
        // is safe by construction.
        let z = ZeroString::from_string("super-secret-totp-seed".to_string());
        let dbg = format!("{:?}", z);
        assert!(!dbg.contains("super-secret"), "leaked: {dbg}");
        assert!(!dbg.contains("totp"), "leaked: {dbg}");
        assert_eq!(dbg, "ZeroString(<redacted>)");
    }

    #[test]
    fn gen_kind_roundtrip() {
        for kind in [
            GenKind::Hex,
            GenKind::Base62,
            GenKind::Pass,
            GenKind::Uuid,
            GenKind::Words,
        ] {
            let s = kind.as_str();
            let parsed = GenKind::from_str(s)
                .unwrap_or_else(|| panic!("as_str {s:?} must roundtrip through from_str"));
            // GenKind is Copy so we can compare via as_str
            assert_eq!(parsed.as_str(), s);
        }
        assert!(GenKind::from_str("garbage").is_none());
        assert!(GenKind::from_str("").is_none());
        assert!(
            GenKind::from_str("HEX").is_none(),
            "case-sensitive on the wire"
        );
    }

    #[test]
    fn hex_format() {
        let s = generate_secret(GenKind::Hex).unwrap();
        assert_eq!(s.len(), 64, "hex secret is 32 bytes as hex");
        assert!(
            s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "hex secret must use [0-9a-f] only",
        );
    }

    #[test]
    fn base62_format() {
        let s = generate_secret(GenKind::Base62).unwrap();
        assert_eq!(s.len(), 48);
        assert!(
            s.bytes().all(|b| b.is_ascii_alphanumeric()),
            "base62 secret must be alphanumeric",
        );
    }

    #[test]
    fn pass_format() {
        // Every sample must satisfy upper/lower/digit/symbol because the
        // `GenKind::Pass` branch retries until the sample meets all four
        // requirements. If that retry loop is ever removed, this test becomes
        // probabilistic — see the `loop { … }` inside `generate_secret`.
        for _ in 0..8 {
            let s = generate_secret(GenKind::Pass).unwrap();
            assert_eq!(s.len(), 32);
            assert!(s.bytes().any(|b| b.is_ascii_uppercase()), "needs upper");
            assert!(s.bytes().any(|b| b.is_ascii_lowercase()), "needs lower");
            assert!(s.bytes().any(|b| b.is_ascii_digit()), "needs digit");
            assert!(
                s.bytes().any(|b| b"!@#$%^&*-_=+".contains(&b)),
                "needs symbol",
            );
        }
    }

    #[test]
    fn uuid_v4_format() {
        let s = generate_secret(GenKind::Uuid).unwrap();
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 36, "uuid is 36 chars");
        // 8-4-4-4-12 dash positions
        for i in [8, 13, 18, 23] {
            assert_eq!(bytes[i], b'-', "expected dash at index {i}");
        }
        // Version nibble (index 14) must be '4'
        assert_eq!(bytes[14], b'4', "uuid version must be 4");
        // Variant nibble (index 19) must be one of 8|9|a|b
        assert!(
            matches!(bytes[19], b'8' | b'9' | b'a' | b'b'),
            "uuid variant bits wrong",
        );
        // Every non-dash position must be lowercase hex
        for (i, &b) in bytes.iter().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                continue;
            }
            assert!(
                matches!(b, b'0'..=b'9' | b'a'..=b'f'),
                "non-hex char at {i}",
            );
        }
    }

    #[test]
    fn zero_string_helpers() {
        // Covers only the public API surface; `Drop` zeroization is not
        // verified here — doing so requires `unsafe` peeks at freed memory,
        // out of scope for this suite. The `Drop` impl delegates to
        // `zeroize::Zeroize::zeroize`, which is itself tested upstream.
        let z = ZeroString::from_string("hello".to_string());
        assert_eq!(z.len(), 5);
        assert!(!z.is_empty());
        assert_eq!(z.to_owned_string(), "hello");
        assert_eq!(z.as_bytes(), b"hello");
        assert_eq!(&*z, "hello"); // Deref<Target=str>

        let empty = ZeroString::from_string(String::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }
}
