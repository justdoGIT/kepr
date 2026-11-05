//! Glob matching for `policy.toml` conditions. Split out of `policy`.

/// `*` matches any run of characters (including `/`), `?` one character.
pub fn glob(pattern: &str, text: &str) -> bool {
    if pattern.is_ascii() && text.is_ascii() {
        return glob_bytes(pattern.as_bytes(), text.as_bytes());
    }
    glob_chars(pattern, text)
}

#[inline]
fn glob_bytes(p: &[u8], t: &[u8]) -> bool {
    let (mut pi, mut ti) = (0, 0);
    let mut back: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            back = Some((pi, ti));
            pi += 1;
        } else if let Some((bp, bt)) = back {
            pi = bp + 1;
            ti = bt + 1;
            back = Some((bp, bt + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == b'*')
}

#[inline]
fn glob_bytes_fold(p: &[u8], t: &[u8]) -> bool {
    let (mut pi, mut ti) = (0, 0);
    let mut back: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len()
            && (p[pi] == b'?' || p[pi].to_ascii_uppercase() == t[ti].to_ascii_uppercase())
        {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            back = Some((pi, ti));
            pi += 1;
        } else if let Some((bp, bt)) = back {
            pi = bp + 1;
            ti = bt + 1;
            back = Some((bp, bt + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == b'*')
}

fn glob_chars(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    let mut back: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            back = Some((pi, ti));
            pi += 1;
        } else if let Some((bp, bt)) = back {
            pi = bp + 1;
            ti = bt + 1;
            back = Some((bp, bt + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

pub(crate) fn any_glob(globs: &[String], value: Option<&str>, fold: bool) -> bool {
    if globs.is_empty() {
        return true;
    }
    let Some(v) = value else { return false };
    if fold {
        if v.is_ascii() && globs.iter().all(|g| g.is_ascii()) {
            let v_bytes = v.as_bytes();
            return globs.iter().any(|g| glob_bytes_fold(g.as_bytes(), v_bytes));
        }
        let v_upper = v.to_ascii_uppercase();
        return globs
            .iter()
            .any(|g| glob(&g.to_ascii_uppercase(), &v_upper));
    }
    globs.iter().any(|g| glob(g.as_str(), v))
}
