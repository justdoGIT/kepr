// cli_platform/args.rs — the small argv parser the platform verbs share.
// Flags are declared up front; anything else that starts with `--` is an
// error, so a typo never becomes a positional name.

pub struct Args {
    pub positional: Vec<String>,
    values: Vec<(String, String)>,
    switches: Vec<String>,
}

/// Global output flags main.rs handles; every verb ignores them.
const GLOBAL: &[&str] = &["--json", "--color", "--no-color"];

pub fn parse(args: &[String], with_value: &[&str], switches: &[&str]) -> Result<Args, String> {
    let mut out = Args {
        positional: Vec::new(),
        values: Vec::new(),
        switches: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let a = a.as_str();
        if GLOBAL.contains(&a) {
            continue;
        }
        if let Some((flag, v)) = a.split_once('=').filter(|(f, _)| with_value.contains(f)) {
            out.values.push((flag.to_string(), v.to_string()));
        } else if with_value.contains(&a) {
            let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
            out.values.push((a.to_string(), v.clone()));
        } else if switches.contains(&a) {
            out.switches.push(a.to_string());
        } else if a.starts_with("--") {
            return Err(format!("unknown flag: {a}"));
        } else {
            out.positional.push(a.to_string());
        }
    }
    Ok(out)
}

impl Args {
    /// The last value given for `flag`.
    pub fn value(&self, flag: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(f, _)| f == flag)
            .map(|(_, v)| v.as_str())
    }

    /// Every value given for `flag`, in order.
    pub fn values(&self, flag: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(f, _)| f == flag)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn has(&self, switch: &str) -> bool {
        self.switches.iter().any(|s| s == switch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn splits_positionals_values_and_switches() {
        let a = parse(
            &v(&[
                "X", "--name", "a", "--tpm2", "--json", "--name=c", "--file", "c=d",
            ]),
            &["--name", "--file"],
            &["--tpm2"],
        )
        .unwrap();
        assert_eq!(a.positional, ["X"]);
        assert_eq!(a.value("--name"), Some("c"));
        assert_eq!(a.values("--name"), ["a", "c"]);
        assert_eq!(a.value("--file"), Some("c=d"));
        assert!(a.has("--tpm2"));
        assert!(!a.has("--json"));
    }

    #[test]
    fn unknown_flags_and_missing_values_fail() {
        assert!(parse(&v(&["--nope"]), &[], &[]).is_err());
        assert!(parse(&v(&["--name"]), &["--name"], &[]).is_err());
    }
}
