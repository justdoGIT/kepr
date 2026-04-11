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
    fn deref(&self) -> &str { &self.0 }
}

impl ZeroString {
    pub fn from_string(s: String) -> Self { Self(s) }
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
    pub fn len(&self) -> usize { self.0.len() }
    pub fn to_owned_string(&self) -> String { self.0.clone() }
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
            "hex"    => Some(Self::Hex),
            "base62" => Some(Self::Base62),
            "pass"   => Some(Self::Pass),
            "uuid"   => Some(Self::Uuid),
            _        => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hex    => "hex",
            Self::Base62 => "base62",
            Self::Pass   => "pass",
            Self::Uuid   => "uuid",
        }
    }
}

// ── RNG ───────────────────────────────────────────────────────────────────────

struct UrandomRng;

impl UrandomRng {
    fn bytes(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        let mut f = fs::File::open("/dev/urandom")
            .expect("cannot open /dev/urandom");
        f.read_exact(&mut buf)
            .expect("cannot read /dev/urandom");
        buf
    }

    /// Rejection sampling — uniform distribution, no modulo bias.
    fn sample(alphabet: &[u8], len: usize) -> Vec<u8> {
        let max = (256 / alphabet.len()) * alphabet.len();
        let mut result = Vec::with_capacity(len);
        while result.len() < len {
            let batch = Self::bytes(len * 3);
            for &b in &batch {
                if result.len() >= len { break; }
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
            bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        }

        GenKind::Base62 => {
            const ALPHA: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            String::from_utf8(UrandomRng::sample(ALPHA, 48)).unwrap()
        }

        GenKind::Pass => {
            const ALPHA: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
            loop {
                let bytes = UrandomRng::sample(ALPHA, 32);
                let s = String::from_utf8(bytes).unwrap();
                if s.bytes().any(|b| b.is_ascii_uppercase()) &&
                   s.bytes().any(|b| b.is_ascii_lowercase()) &&
                   s.bytes().any(|b| b.is_ascii_digit())     &&
                   s.bytes().any(|b| b"!@#$%^&*-_=+".contains(&b)) {
                    break s;
                }
            }
        }

        GenKind::Uuid => {
            let b = UrandomRng::bytes(16);
            format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
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
