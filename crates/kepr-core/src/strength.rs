// strength.rs — T5.04 password strength estimate (`kepr strength`).
//
// bits = min(charset entropy, cheapest pattern parse). The pattern parse
// splits the value into pieces, each costed as the bits an attacker who
// guesses that kind of piece needs, and keeps the cheapest split (a
// shortest path over positions):
//
//   one character          log2 of the value's alphabet (the union of the
//                          classes it uses, as for the charset entropy)
//   EFF word (3-9 letters) log2(7776), +1 bit if capitalised
//   common password        log2(list size), +1 bit if capitalised
//   year 1900-2099         log2(200)
//   run of one character   that character + log2(run length)
//   sequence (abc, 4321)   log2(26 or 10) + log2(length) + 1
//   keyboard row (asdf)    log2(80) + log2(length)
//   repeat of the previous piece   log2(length) + 1
//
// Notes name the kinds of pieces used, never the value.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::generate::eff_words;

const COMMON: &[&str] = &[
    "password", "passw0rd", "123456", "12345678", "qwerty", "letmein", "admin", "welcome",
    "iloveyou", "monkey", "dragon", "changeme", "secret", "abc123", "default", "test", "football",
    "baseball", "master", "shadow", "sunshine", "princess", "trustno1", "login", "hello",
    "freedom", "whatever", "superman", "starwars", "access", "michael", "pass",
];
const ROWS: &[&str] = &["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];
/// Only the first this many characters are parsed; the rest count at
/// their charset entropy.
const MAX_PARSE: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub struct Strength {
    pub bits: f64,
    pub notes: Vec<&'static str>,
}

impl Strength {
    pub fn rating(&self) -> &'static str {
        match self.bits {
            b if b < 28.0 => "very weak",
            b if b < 36.0 => "weak",
            b if b < 60.0 => "fair",
            b if b < 80.0 => "strong",
            _ => "very strong",
        }
    }
}

fn eff() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| eff_words().collect())
}

fn pool(c: char) -> f64 {
    match c {
        'a'..='z' | 'A'..='Z' => 26.0,
        '0'..='9' => 10.0,
        c if c.is_ascii_punctuation() || c == ' ' => 33.0,
        _ => 100.0,
    }
}

/// Length × log2 of the union of the classes the value uses.
pub fn charset_bits(chars: &[char]) -> f64 {
    chars.len() as f64 * alphabet_bits(chars)
}

/// log2 of the union of the classes `chars` uses (0 if none).
fn alphabet_bits(chars: &[char]) -> f64 {
    let mut total = 0.0;
    let has = |f: fn(&char) -> bool| chars.iter().any(f);
    for (present, size) in [
        (has(char::is_ascii_lowercase), 26.0),
        (has(char::is_ascii_uppercase), 26.0),
        (has(char::is_ascii_digit), 10.0),
        (has(|c| c.is_ascii_punctuation() || *c == ' '), 33.0),
        (has(|c| !c.is_ascii()), 100.0),
    ] {
        if present {
            total += size;
        }
    }
    if total == 0.0 {
        return 0.0;
    }
    f64::log2(total)
}

/// Extra bits for capitals in a word: none, a leading one, or all.
fn case_bits(word: &[char]) -> f64 {
    let uppers = word.iter().filter(|c| c.is_ascii_uppercase()).count();
    match uppers {
        0 => 0.0,
        n if n == word.len() || (n == 1 && word[0].is_ascii_uppercase()) => 1.0,
        n => n as f64,
    }
}

/// Length of the run from `s[0]` where each next char follows by `step`.
fn run(s: &[char], step: impl Fn(char, char) -> bool) -> usize {
    1 + s.windows(2).take_while(|w| step(w[0], w[1])).count()
}

/// Cheapest parse of `chars`, a character costing `char_bits`: (bits, notes).
fn parse(chars: &[char], char_bits: f64) -> (f64, Vec<&'static str>) {
    let n = chars.len();
    let lower: Vec<char> = chars.iter().map(char::to_ascii_lowercase).collect();
    let mut best: Vec<(f64, usize, &'static str)> = vec![(f64::INFINITY, 0, ""); n + 1];
    best[0].0 = 0.0;
    for i in 0..n {
        let base = best[i].0;
        let mut relax = |end: usize, cost: f64, note: &'static str| {
            if base + cost < best[end].0 {
                best[end] = (base + cost, i, note);
            }
        };
        relax(i + 1, char_bits, "");
        for len in 3..=9.min(n - i) {
            let w: String = lower[i..i + len].iter().collect();
            let case = case_bits(&chars[i..i + len]);
            if COMMON.contains(&w.as_str()) {
                relax(
                    i + len,
                    f64::log2(COMMON.len() as f64) + case,
                    "a common password",
                );
            } else if eff().contains(w.as_str()) {
                relax(i + len, f64::log2(7776.0) + case, "dictionary words");
            }
        }
        if i + 4 <= n {
            let y: String = chars[i..i + 4].iter().collect();
            if y.parse::<u32>().is_ok_and(|y| (1900..2100).contains(&y)) {
                relax(i + 4, f64::log2(200.0), "a year");
            }
        }
        let same = run(&chars[i..], |a, b| a == b);
        for len in 3..=same {
            relax(
                i + len,
                f64::log2(pool(chars[i])) + f64::log2(len as f64),
                "repeated characters",
            );
        }
        for dir in [1i32, -1] {
            let seq = run(&lower[i..], |a, b| {
                (a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric())
                    && (a.is_ascii_digit() == b.is_ascii_digit())
                    && b as i32 - a as i32 == dir
            });
            for len in 3..=seq {
                let cost = f64::log2(pool(chars[i])) + f64::log2(len as f64) + 1.0;
                relax(i + len, cost, "a sequence");
            }
        }
        for len in 4..=(n - i).min(10) {
            let s: String = lower[i..i + len].iter().collect();
            let rev: String = s.chars().rev().collect();
            if ROWS.iter().any(|r| r.contains(&s) || r.contains(&rev)) {
                relax(
                    i + len,
                    f64::log2(80.0) + f64::log2(len as f64),
                    "a keyboard pattern",
                );
            }
        }
        for k in 2..=i.min(n - i) {
            if chars[i..i + k] == chars[i - k..i] {
                relax(i + k, f64::log2(k as f64) + 1.0, "repeated characters");
            }
        }
    }
    let mut notes = Vec::new();
    let mut at = n;
    while at > 0 {
        let (_, prev, note) = best[at];
        if !note.is_empty() && !notes.contains(&note) {
            notes.push(note);
        }
        at = prev;
    }
    notes.reverse();
    (best[n].0, notes)
}

pub fn estimate(value: &str) -> Strength {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return Strength {
            bits: 0.0,
            notes: vec!["empty"],
        };
    }
    let cut = chars.len().min(MAX_PARSE);
    let (parsed, notes) = parse(&chars[..cut], alphabet_bits(&chars));
    let rest = charset_bits(&chars[cut..]);
    let charset = charset_bits(&chars);
    let (bits, notes) = match parsed + rest < charset {
        true => (parsed + rest, notes),
        false => (charset, Vec::new()),
    };
    Strength { bits, notes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_patterns_score_low_and_passphrases_high() {
        let s = estimate("Password1");
        assert!(s.bits < 30.0, "{s:?}");
        assert!(s.notes.contains(&"a common password"), "{s:?}");
        for (v, max) in [
            ("aaaaaaaaaaaa", 15.0),
            ("abcdefgh", 15.0),
            ("qwertyuiop", 15.0),
            ("123456789", 15.0),
            ("monkey1987", 30.0),
            ("Staple2024!", 30.0),
            ("abcabcabcabc", 20.0),
        ] {
            let s = estimate(v);
            assert!(s.bits < max, "{v}: {s:?}");
        }
        let words = crate::generate::random_words(6).unwrap().join("-");
        let s = estimate(&words);
        assert!(s.bits > 70.0, "{s:?}");
        assert!(estimate("correct-horse-battery-staple-oak-jump").bits > 70.0);
    }

    #[test]
    fn random_strings_keep_their_charset_entropy() {
        let v = "kQ7#vR2!mX9$pL4&";
        let s = estimate(v);
        assert!((s.bits - charset_bits(&v.chars().collect::<Vec<_>>())).abs() < 1e-6);
        assert!(s.bits > 90.0 && s.notes.is_empty(), "{s:?}");
        assert_eq!(estimate("").bits, 0.0);
        assert_eq!(estimate("").rating(), "very weak");
        // Long inputs are parsed up to a bound and stay fast.
        let long = "a".repeat(5000);
        assert!(estimate(&long).bits.is_finite());
    }

    #[test]
    fn ratings() {
        let s = |bits| {
            Strength {
                bits,
                notes: vec![],
            }
            .rating()
        };
        assert_eq!(
            [s(10.0), s(30.0), s(50.0), s(70.0), s(90.0)],
            ["very weak", "weak", "fair", "strong", "very strong"]
        );
    }
}
