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
/// Used for all secret values throughout credman.
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

impl ZeroString {
    pub fn from_string(s: String) -> Self {
        Self(s)
    }
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
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
}

impl GenKind {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "hex" => Some(Self::Hex),
            "base62" => Some(Self::Base62),
            "pass" => Some(Self::Pass),
            "uuid" => Some(Self::Uuid),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Base62 => "base62",
            Self::Pass => "pass",
            Self::Uuid => "uuid",
        }
    }
}

// ── RNG ───────────────────────────────────────────────────────────────────────

struct UrandomRng;

impl UrandomRng {
    fn bytes(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        let mut f = fs::File::open("/dev/urandom").expect("cannot open /dev/urandom");
        f.read_exact(&mut buf).expect("cannot read /dev/urandom");
        buf
    }

    /// Rejection sampling — uniform distribution, no modulo bias.
    fn sample(alphabet: &[u8], len: usize) -> Vec<u8> {
        let max = (256 / alphabet.len()) * alphabet.len();
        let mut result = Vec::with_capacity(len);
        while result.len() < len {
            let batch = Self::bytes(len * 3);
            for &b in &batch {
                if result.len() >= len {
                    break;
                }
                if (b as usize) < max {
                    result.push(alphabet[b as usize % alphabet.len()]);
                }
            }
        }
        result
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn generate_secret(kind: GenKind) -> ZeroString {
    let s = match kind {
        GenKind::Hex => {
            let bytes = UrandomRng::bytes(32);
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        }

        GenKind::Base62 => {
            const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            String::from_utf8(UrandomRng::sample(ALPHA, 48)).unwrap()
        }

        GenKind::Pass => {
            const ALPHA: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
            loop {
                let bytes = UrandomRng::sample(ALPHA, 32);
                let s = String::from_utf8(bytes).unwrap();
                if s.bytes().any(|b| b.is_ascii_uppercase())
                    && s.bytes().any(|b| b.is_ascii_lowercase())
                    && s.bytes().any(|b| b.is_ascii_digit())
                    && s.bytes().any(|b| b"!@#$%^&*-_=+".contains(&b))
                {
                    break s;
                }
            }
        }

        GenKind::Uuid => {
            let b = UrandomRng::bytes(16);
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

    ZeroString(s)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_kind_roundtrip() {
        for kind in [GenKind::Hex, GenKind::Base62, GenKind::Pass, GenKind::Uuid] {
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
        let s = generate_secret(GenKind::Hex);
        assert_eq!(s.len(), 64, "hex secret is 32 bytes as hex");
        assert!(
            s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "hex secret must use [0-9a-f] only",
        );
    }

    #[test]
    fn base62_format() {
        let s = generate_secret(GenKind::Base62);
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
            let s = generate_secret(GenKind::Pass);
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
        let s = generate_secret(GenKind::Uuid);
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
