//! Glob matching for `policy.toml` conditions. Split out of `policy`.

/// `*` matches any run of characters (including `/`), `?` one character.
pub fn glob(pattern: &str, text: &str) -> bool {
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
    let v = if fold {
        v.to_ascii_uppercase()
    } else {
        v.into()
    };
    globs.iter().any(|g| {
        let g = if fold {
            g.to_ascii_uppercase()
        } else {
            g.clone()
        };
        glob(&g, &v)
    })
}
