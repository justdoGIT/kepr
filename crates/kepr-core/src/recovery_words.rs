// recovery_words.rs — a 32-byte key as 24 words (T4.10).
//
// The words come from the EFF large list (7776 words, ~12.9 bits each;
// the same list as `generate::GenKind::Words`), so 24 words carry ~310
// bits:
//
//   words  1–20  the key, a 256-bit big-endian number written in base
//                7776 (7776^20 ≈ 2^258.5, so every key fits);
//   words 21–24  a checksum: the first 8 bytes of
//                SHA-256("kepr-recovery-words-v1" ‖ key) mod 7776^4
//                (~51.7 bits), so a mistyped or swapped word is caught.
//
// Errors name a word's position, never the word: the daemon audits
// failures, and a misspelt word is still most of a word of the key.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::generate::ZeroString;

/// Words in a recovery key.
pub const WORDS: usize = 24;
const KEY_WORDS: usize = 20;
const CHECK_WORDS: usize = WORDS - KEY_WORDS;
const BASE: u32 = 7776;
const LIST: &str = include_str!("eff_large_wordlist.txt");
const DOMAIN: &[u8] = b"kepr-recovery-words-v1";
const MISMATCH: &str = "the words do not check out: one is wrong or out of order";

fn list() -> &'static [&'static str] {
    static WORDLIST: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    WORDLIST.get_or_init(|| LIST.lines().collect())
}

/// The checksum digits (most significant first).
fn checksum(key: &[u8; 32]) -> [u32; CHECK_WORDS] {
    let d = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(key)
        .finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&d[..8]);
    let mut c = u64::from_be_bytes(head) % u64::from(BASE).pow(CHECK_WORDS as u32);
    let mut out = [0u32; CHECK_WORDS];
    for slot in out.iter_mut().rev() {
        *slot = (c % u64::from(BASE)) as u32;
        c /= u64::from(BASE);
    }
    out
}

/// `key` as 24 lowercase words separated by single spaces.
pub fn encode(key: &[u8; 32]) -> ZeroString {
    let mut n = Zeroizing::new(*key);
    let mut digits = Zeroizing::new([0u32; WORDS]);
    // Long division of the big-endian number by 7776, least significant
    // digit first.
    for i in (0..KEY_WORDS).rev() {
        let mut rem = 0u32;
        for b in n.iter_mut() {
            let cur = rem * 256 + u32::from(*b);
            *b = (cur / BASE) as u8;
            rem = cur % BASE;
        }
        digits[i] = rem;
    }
    digits[KEY_WORDS..].copy_from_slice(&checksum(key));
    let words = list();
    let mut out = String::with_capacity(WORDS * 10);
    for (i, d) in digits.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(words[*d as usize]);
    }
    ZeroString::from_string(out)
}

/// Rebuild the key from the words. Case, extra whitespace and position
/// numbers (`1`, `1.`, `1)`) are ignored.
pub fn decode(text: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let words = list();
    let mut digits = Zeroizing::new(Vec::with_capacity(WORDS));
    for token in text.split_whitespace() {
        let bare = token.trim_end_matches(['.', ')']);
        if !bare.is_empty() && bare.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let pos = digits.len() + 1;
        if pos > WORDS {
            return Err(format!("expected {WORDS} words, got more"));
        }
        let lower = Zeroizing::new(token.to_ascii_lowercase());
        let d = words
            .binary_search(&lower.as_str())
            .map_err(|_| format!("word {pos} is not in the recovery word list"))?;
        digits.push(d as u32);
    }
    if digits.len() != WORDS {
        return Err(format!("expected {WORDS} words, got {}", digits.len()));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    for d in &digits[..KEY_WORDS] {
        let mut carry = *d;
        for b in key.iter_mut().rev() {
            let v = u32::from(*b) * BASE + carry;
            *b = v as u8;
            carry = v >> 8;
        }
        // Too big for 256 bits: a word is wrong or out of order too.
        if carry != 0 {
            return Err(MISMATCH.into());
        }
    }
    if checksum(&key)[..] != digits[KEY_WORDS..] {
        return Err(MISMATCH.into());
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = seed.wrapping_mul(31).wrapping_add(i as u8 * 7);
        }
        k
    }

    #[test]
    fn words_round_trip_bytes() {
        for k in [[0u8; 32], [0xff; 32], key(1), key(2), key(200)] {
            let w = encode(&k);
            assert_eq!(w.as_str().split(' ').count(), WORDS);
            assert_eq!(*decode(w.as_str()).unwrap(), k);
        }
        // ~310 bits: 24 words of a 7776-word list.
        assert_eq!(list().len(), 7776);
        assert!(WORDS as f64 * (BASE as f64).log2() > 310.0);
    }

    #[test]
    fn decode_ignores_case_spacing_and_numbering() {
        let k = key(9);
        let w = encode(&k);
        let numbered: Vec<String> = w
            .as_str()
            .split(' ')
            .enumerate()
            .map(|(i, w)| format!("{}. {}", i + 1, w.to_uppercase()))
            .collect();
        assert_eq!(*decode(&numbered.join("\n  ")).unwrap(), k);
    }

    #[test]
    fn a_wrong_word_reports_its_position() {
        let w = encode(&key(3));
        let mut parts: Vec<&str> = w.as_str().split(' ').collect();
        parts[6] = "notaword";
        let e = decode(&parts.join(" ")).unwrap_err();
        assert_eq!(e, "word 7 is not in the recovery word list");
        assert!(!e.contains("notaword"));
    }

    #[test]
    fn checksum_catches_swaps_and_substitutions() {
        let w = encode(&key(4));
        let mut parts: Vec<&str> = w.as_str().split(' ').collect();
        parts.swap(0, 1);
        assert!(decode(&parts.join(" ")).unwrap_err().contains("check out"));
        let mut parts: Vec<&str> = w.as_str().split(' ').collect();
        parts[23] = if parts[23] == "zoom" {
            "abacus"
        } else {
            "zoom"
        };
        assert!(decode(&parts.join(" ")).unwrap_err().contains("check out"));
        assert!(decode("abacus abacus").unwrap_err().contains("got 2"));
        let long = format!("{} zoom", w.as_str());
        assert!(decode(&long).unwrap_err().contains("got more"));
        // The largest 20-word number doesn't fit in 256 bits.
        let big = ["zoom"; WORDS].join(" ");
        assert_eq!(decode(&big).unwrap_err(), MISMATCH);
    }
}
