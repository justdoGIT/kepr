// daemon_store/pattern.rs — `kepr search` patterns (T11.1): a
// case-insensitive substring, or `/regex/` with a tiny matcher: `.`,
// `*` (zero or more of the previous item), `^` / `$` anchors, classes
// `[a-z0-9_]` / `[^…]`, and `\` escapes. No regex crate: the matcher is a
// position-set simulation, linear in text length × pattern length, so a
// hostile pattern can't make the daemon backtrack.

const MAX_PATTERN: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub enum Atom {
    Any,
    Char(char),
    /// `(negated, ranges)`
    Class(bool, Vec<(char, char)>),
}

impl Atom {
    fn matches(&self, c: char) -> bool {
        match self {
            Atom::Any => true,
            Atom::Char(x) => *x == c,
            Atom::Class(neg, ranges) => ranges.iter().any(|(a, b)| (*a..=*b).contains(&c)) != *neg,
        }
    }
}

#[derive(Debug)]
pub enum Pattern {
    Substring(String),
    Regex {
        start: bool,
        end: bool,
        /// `(atom, starred)`
        atoms: Vec<(Atom, bool)>,
    },
}

pub fn parse(p: &str) -> Result<Pattern, String> {
    if p.is_empty() || p.len() > MAX_PATTERN {
        return Err(format!("search pattern must be 1-{MAX_PATTERN} characters"));
    }
    match p.strip_prefix('/').and_then(|r| r.strip_suffix('/')) {
        Some(re) if p.len() >= 2 => parse_regex(&re.to_lowercase()),
        _ => Ok(Pattern::Substring(p.to_lowercase())),
    }
}

fn parse_regex(re: &str) -> Result<Pattern, String> {
    let (start, re) = match re.strip_prefix('^') {
        Some(r) => (true, r),
        None => (false, re),
    };
    let (end, re) = match re.strip_suffix('$') {
        Some(r) if !r.ends_with('\\') => (true, r),
        _ => (false, re),
    };
    let mut atoms: Vec<(Atom, bool)> = Vec::new();
    let mut chars = re.chars();
    while let Some(c) = chars.next() {
        let atom = match c {
            '.' => Atom::Any,
            '\\' => Atom::Char(chars.next().ok_or("pattern ends with \\")?),
            '[' => class(&mut chars)?,
            '*' => match atoms.last_mut() {
                Some((_, starred @ false)) => {
                    *starred = true;
                    continue;
                }
                _ => return Err("`*` must follow a character, `.` or a class".into()),
            },
            c => Atom::Char(c),
        };
        atoms.push((atom, false));
    }
    Ok(Pattern::Regex { start, end, atoms })
}

fn class(chars: &mut std::str::Chars) -> Result<Atom, String> {
    let mut neg = false;
    let mut ranges = Vec::new();
    loop {
        let c = chars.next().ok_or("unclosed `[` in pattern")?;
        if c == '^' && ranges.is_empty() && !neg {
            neg = true;
            continue;
        }
        // A `]` first in the class is a literal, as in POSIX.
        if c == ']' && !ranges.is_empty() {
            break;
        }
        let lo = if c == '\\' {
            chars.next().ok_or("pattern ends with \\")?
        } else {
            c
        };
        let mut ahead = chars.clone();
        let hi = match (ahead.next(), ahead.next()) {
            (Some('-'), Some(h)) if h != ']' => {
                chars.next();
                chars.next();
                h
            }
            _ => lo,
        };
        if hi < lo {
            return Err(format!("bad range {lo}-{hi} in pattern"));
        }
        ranges.push((lo, hi));
    }
    Ok(Atom::Class(neg, ranges))
}

impl Pattern {
    pub fn is_match(&self, text: &str) -> bool {
        let text = text.to_lowercase();
        match self {
            Pattern::Substring(s) => text.contains(s.as_str()),
            Pattern::Regex { start, end, atoms } => simulate(atoms, *start, *end, &text),
        }
    }
}

/// Positions reachable without consuming text: skip starred atoms.
fn close(atoms: &[(Atom, bool)], set: &mut [bool]) {
    for i in 0..atoms.len() {
        if set[i] && atoms[i].1 {
            set[i + 1] = true;
        }
    }
}

fn simulate(atoms: &[(Atom, bool)], start: bool, end: bool, text: &str) -> bool {
    let n = atoms.len();
    let mut cur = vec![false; n + 1];
    cur[0] = true;
    close(atoms, &mut cur);
    if cur[n] && !end {
        return true;
    }
    for c in text.chars() {
        let mut next = vec![false; n + 1];
        for i in 0..n {
            if cur[i] && atoms[i].0.matches(c) {
                next[if atoms[i].1 { i } else { i + 1 }] = true;
            }
        }
        // Unanchored: a match may begin at any position.
        next[0] |= !start;
        close(atoms, &mut next);
        if next[n] && !end {
            return true;
        }
        cur = next;
    }
    cur[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, t: &str) -> bool {
        parse(p).unwrap().is_match(t)
    }

    #[test]
    fn substring_is_case_insensitive() {
        assert!(m("stripe", "PROD_STRIPE_KEY"));
        assert!(!m("stripe", "PROD_STRIP"));
        assert!(m("/", "a/b")); // a lone slash is a substring
    }

    #[test]
    fn regex_features() {
        assert!(m("/^prod_/", "PROD_DB"));
        assert!(!m("/^prod_/", "X_PROD_DB"));
        assert!(m("/_key$/", "API_KEY"));
        assert!(!m("/_key$/", "API_KEYS"));
        assert!(m("/a.c/", "xabcx"));
        assert!(m("/^ab*c$/", "ac"));
        assert!(m("/^ab*c$/", "abbbc"));
        assert!(!m("/^ab*c$/", "abxc"));
        assert!(m("/^[a-c]*$/", "abcabc"));
        assert!(!m("/^[a-c]*$/", "abcd"));
        assert!(m("/^[^0-9]*$/", "abc"));
        assert!(!m("/^[^0-9]*$/", "ab1"));
        assert!(m("/^.*$/", ""));
        assert!(m(r"/a\.b/", "a.b"));
        assert!(!m(r"/a\.b/", "axb"));
        assert!(m("/[]a]/", "]"));
    }

    #[test]
    fn bad_patterns_are_errors() {
        for p in [
            "",
            "/*a/",
            "/a**/",
            "/[a-/",
            "/[z-a]/",
            r"/a\/",
            &"x".repeat(300),
        ] {
            assert!(parse(p).is_err(), "{p:?}");
        }
    }

    #[test]
    fn many_stars_stay_linear() {
        let p = parse("/^a*a*a*a*a*a*a*a*a*a*a*a*b$/").unwrap();
        let t = "a".repeat(5000);
        assert!(!p.is_match(&t));
    }
}
