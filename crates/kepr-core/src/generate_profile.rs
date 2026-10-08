// generate_profile.rs — T5.04 generator profiles. The CLI reads them
// from `~/.config/kepr/generate.toml` (parsing stays out of this crate):
//
//   [default]                      # when nothing else matches
//   length = 24
//   [profile.bank]                 # kepr set KEY --generate --profile bank
//   length = 16
//   classes = ["lower", "upper", "digit", "symbol"]
//   symbols = "!#$%"
//   [profile.memorable]
//   words = 5                      # a passphrase of 5 EFF words
//   separator = "."
//   [host."example.com"]           # also for its subdomains
//   symbols = ""                   # no symbols
//   [type.wifi]                    # a record field of this record type
//   words = 4
//
// Every value is drawn from /dev/urandom without modulo bias
// (generate.rs); each requested class appears at least once.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::generate::{random_chars, random_words, ZeroString};

pub const CLASSES: &[&str] = &["lower", "upper", "digit", "symbol"];
pub const DEFAULT_SYMBOLS: &str = "!@#$%^&*-_=+";
pub const DEFAULT_LENGTH: usize = 24;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Characters (8-256); ignored for a passphrase.
    pub length: Option<usize>,
    /// Character classes that must appear (default: all four, or the
    /// first three when `symbols` is empty; a passphrase: `lower`).
    pub classes: Option<Vec<String>>,
    /// The symbol alphabet (ASCII punctuation).
    pub symbols: Option<String>,
    /// A passphrase of this many words (3-20) instead of characters;
    /// `upper` capitalises the words, `digit` / `symbol` append one.
    pub words: Option<usize>,
    /// Between passphrase words (default `-`).
    pub separator: Option<String>,
}

fn class_alphabet(class: &str, symbols: &str) -> Vec<u8> {
    match class {
        "lower" => (b'a'..=b'z').collect(),
        "upper" => (b'A'..=b'Z').collect(),
        "digit" => (b'0'..=b'9').collect(),
        _ => symbols.bytes().collect(),
    }
}

impl Profile {
    fn symbols(&self) -> &str {
        self.symbols.as_deref().unwrap_or(DEFAULT_SYMBOLS)
    }

    /// The classes that must appear.
    pub fn classes(&self) -> Vec<String> {
        match &self.classes {
            Some(c) => c.clone(),
            // A passphrase is plain words unless classes say otherwise.
            None if self.words.is_some() => vec!["lower".into()],
            None => CLASSES
                .iter()
                .filter(|c| **c != "symbol" || !self.symbols().is_empty())
                .map(|c| c.to_string())
                .collect(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let classes = self.classes();
        if classes.is_empty() && self.words.is_none() {
            return Err("classes must name at least one of lower, upper, digit, symbol".into());
        }
        for (i, c) in classes.iter().enumerate() {
            if !CLASSES.contains(&c.as_str()) {
                return Err(format!("unknown class {c:?}; use: {}", CLASSES.join(", ")));
            }
            if classes[..i].contains(c) {
                return Err(format!("class {c} is listed twice"));
            }
        }
        let sym = self.symbols();
        let unique = sym
            .bytes()
            .enumerate()
            .all(|(i, b)| !sym.as_bytes()[..i].contains(&b));
        if sym.len() > 32 || !sym.bytes().all(|b| b.is_ascii_punctuation()) || !unique {
            return Err("symbols: up to 32 distinct ASCII punctuation characters".into());
        }
        if sym.is_empty() && classes.iter().any(|c| c == "symbol") {
            return Err("the symbol class needs symbols".into());
        }
        if let Some(w) = self.words {
            if !(3..=20).contains(&w) {
                return Err("words: 3-20".into());
            }
            let sep = self.separator.as_deref().unwrap_or("-");
            if sep.chars().count() > 4 || sep.chars().any(char::is_control) {
                return Err("separator: up to 4 characters".into());
            }
        } else if !(8..=256).contains(&self.length.unwrap_or(DEFAULT_LENGTH)) {
            return Err("length: 8-256".into());
        } else if self.length.unwrap_or(DEFAULT_LENGTH) < classes.len() {
            return Err("length is shorter than the number of classes".into());
        }
        Ok(())
    }

    pub fn generate(&self) -> Result<ZeroString, String> {
        self.validate()?;
        let classes = self.classes();
        let one = |class: &str| -> Result<char, String> {
            let a = class_alphabet(class, self.symbols());
            Ok(random_chars(&a, 1)?[0] as char)
        };
        if let Some(n) = self.words {
            let upper = classes.iter().any(|c| c == "upper");
            let mut words: Vec<String> = random_words(n)?
                .into_iter()
                .map(|w| match upper {
                    true => w[..1].to_uppercase() + &w[1..],
                    false => w.to_string(),
                })
                .collect();
            let mut tail = String::new();
            for c in classes
                .iter()
                .filter(|c| matches!(c.as_str(), "digit" | "symbol"))
            {
                tail.push(one(c)?);
            }
            if let Some(last) = words.last_mut() {
                last.push_str(&tail);
            }
            let out = words.join(self.separator.as_deref().unwrap_or("-"));
            words.iter_mut().for_each(zeroize::Zeroize::zeroize);
            return Ok(ZeroString::from_string(out));
        }
        let alphabet: Vec<u8> = classes
            .iter()
            .flat_map(|c| class_alphabet(c, self.symbols()))
            .collect();
        let len = self.length.unwrap_or(DEFAULT_LENGTH);
        loop {
            let bytes = zeroize::Zeroizing::new(random_chars(&alphabet, len)?);
            let has = |c: &String| {
                let a = class_alphabet(c, self.symbols());
                bytes.iter().any(|b| a.contains(b))
            };
            if classes.iter().all(has) {
                let s = String::from_utf8(bytes.to_vec()).map_err(|_| "generation: not UTF-8")?;
                return Ok(ZeroString::from_string(s));
            }
        }
    }
}

/// The whole `generate.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileFile {
    #[serde(default)]
    pub default: Option<Profile>,
    #[serde(default)]
    pub profile: BTreeMap<String, Profile>,
    #[serde(default)]
    pub host: BTreeMap<String, Profile>,
    #[serde(default, rename = "type")]
    pub record_type: BTreeMap<String, Profile>,
}

impl ProfileFile {
    pub fn validate(&self) -> Result<(), String> {
        let tables = [
            ("profile", &self.profile),
            ("host", &self.host),
            ("type", &self.record_type),
        ];
        for (table, map) in tables {
            for (k, p) in map {
                p.validate().map_err(|e| format!("[{table}.{k:?}] {e}"))?;
            }
        }
        match &self.default {
            Some(p) => p.validate().map_err(|e| format!("[default] {e}")),
            None => Ok(()),
        }
    }

    /// `host`'s profile, else its parent domain's (`a.b.example.com` →
    /// `b.example.com` → `example.com`).
    fn for_host(&self, host: &str) -> Option<&Profile> {
        let mut h = host.trim_end_matches('.').to_ascii_lowercase();
        loop {
            if let Some(p) = self.host.get(&h) {
                return Some(p);
            }
            match h.split_once('.') {
                Some((_, rest)) if rest.contains('.') => h = rest.to_string(),
                _ => return None,
            }
        }
    }

    /// With `name`: that profile, else the host or record type of that
    /// name (an error if none). Without: by `host`, then `rtype`, then
    /// `[default]`, then the built-in defaults.
    pub fn pick(
        &self,
        name: Option<&str>,
        host: Option<&str>,
        rtype: Option<&str>,
    ) -> Result<Profile, String> {
        if let Some(n) = name {
            let found = self.profile.get(n).or_else(|| self.for_host(n));
            return found
                .or_else(|| self.record_type.get(n))
                .cloned()
                .ok_or_else(|| {
                    let known: Vec<&str> = self.profile.keys().map(String::as_str).collect();
                    format!(
                        "no generator profile {n:?} (profiles: {})",
                        if known.is_empty() {
                            "none".to_string()
                        } else {
                            known.join(", ")
                        }
                    )
                });
        }
        let found = host.and_then(|h| self.for_host(h));
        let found = found.or_else(|| rtype.and_then(|t| self.record_type.get(t)));
        Ok(found.or(self.default.as_ref()).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(length: usize, classes: &[&str], symbols: Option<&str>) -> Profile {
        Profile {
            length: Some(length),
            classes: Some(classes.iter().map(|c| c.to_string()).collect()),
            symbols: symbols.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn generated_values_satisfy_each_class_constraint() {
        for prof in [
            Profile::default(),
            p(8, &["lower", "upper", "digit", "symbol"], Some("#")),
            p(12, &["digit"], None),
            p(16, &["upper", "symbol"], Some("!?")),
            Profile {
                symbols: Some(String::new()),
                ..Default::default()
            },
        ] {
            let classes = prof.classes();
            let symbols = prof.symbols().to_string();
            for _ in 0..50 {
                let v = prof.generate().unwrap();
                assert_eq!(v.len(), prof.length.unwrap_or(DEFAULT_LENGTH));
                let allowed: Vec<u8> = classes
                    .iter()
                    .flat_map(|c| class_alphabet(c, &symbols))
                    .collect();
                assert!(v.bytes().all(|b| allowed.contains(&b)), "{prof:?}");
                for c in &classes {
                    let a = class_alphabet(c, &symbols);
                    assert!(v.bytes().any(|b| a.contains(&b)), "{c} missing: {prof:?}");
                }
            }
        }
        let words = Profile {
            words: Some(4),
            separator: Some(".".into()),
            classes: Some(vec!["upper".into(), "digit".into()]),
            ..Default::default()
        };
        let v = words.generate().unwrap();
        let parts: Vec<&str> = v.split('.').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts
            .iter()
            .all(|w| w.starts_with(|c: char| c.is_ascii_uppercase())));
        assert!(v.ends_with(|c: char| c.is_ascii_digit()));
    }

    #[test]
    fn bad_profiles_are_refused() {
        for (prof, what) in [
            (p(4, &["lower"], None), "length: 8-256"),
            (p(16, &["emoji"], None), "unknown class"),
            (p(16, &["lower", "lower"], None), "twice"),
            (p(16, &["symbol"], Some("")), "needs symbols"),
            (p(16, &["lower"], Some("ab")), "ASCII punctuation"),
            (p(16, &[], None), "at least one"),
            (
                Profile {
                    words: Some(2),
                    ..Default::default()
                },
                "words: 3-20",
            ),
        ] {
            let e = prof.validate().unwrap_err();
            assert!(e.contains(what), "{prof:?}: {e}");
        }
    }

    #[test]
    fn pick_by_name_host_type_and_default() {
        let bank = p(16, &["digit"], None);
        let site = p(20, &["lower"], None);
        let wifi = p(10, &["upper"], None);
        let dflt = p(30, &["lower", "digit"], None);
        let f = ProfileFile {
            default: Some(dflt.clone()),
            profile: BTreeMap::from([("bank".into(), bank.clone())]),
            host: BTreeMap::from([("example.com".into(), site.clone())]),
            record_type: BTreeMap::from([("wifi".into(), wifi.clone())]),
        };
        f.validate().unwrap();
        assert_eq!(f.pick(Some("bank"), None, None).unwrap(), bank);
        assert_eq!(f.pick(Some("Login.Example.com"), None, None).unwrap(), site);
        assert_eq!(f.pick(Some("wifi"), None, None).unwrap(), wifi);
        let e = f.pick(Some("nope"), None, None).unwrap_err();
        assert!(e.contains("profiles: bank"), "{e}");
        assert_eq!(
            f.pick(None, Some("a.b.example.com"), Some("wifi")).unwrap(),
            site
        );
        assert_eq!(f.pick(None, Some("other.org"), Some("wifi")).unwrap(), wifi);
        assert_eq!(f.pick(None, Some("com"), None).unwrap(), dflt);
        assert_eq!(
            ProfileFile::default().pick(None, None, None).unwrap(),
            Profile::default()
        );
        let bad = ProfileFile {
            host: BTreeMap::from([("x.org".into(), p(2, &["lower"], None))]),
            ..Default::default()
        };
        assert!(bad.validate().unwrap_err().contains("[host.\"x.org\"]"));
    }
}
