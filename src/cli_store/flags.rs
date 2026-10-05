// cli_store/flags.rs — flags this batch adds to core verbs, parsed by
// cli_args.rs through one arm: `ls --tag T --folder F` (T5.01),
// `delete --all --yes` (T11.9).

/// The flags below, as `cli_args` sees them.
pub const FLAGS: &[&str] = &["--tag", "--folder", "--all", "--yes", "-y"];

#[derive(Debug, Default)]
pub struct StoreFlags {
    /// `ls --tag T`: only keys with this tag.
    pub tag: Option<String>,
    /// `ls --folder F`: only keys in F or below (`/` = no folder).
    pub folder: Option<String>,
    /// `delete --all`: every credential of the caller.
    pub all: bool,
    /// `delete --all --yes`: the confirmation it requires.
    pub yes: bool,
}

impl StoreFlags {
    /// Take the flag at `raw[i]` (and its value); returns the next index.
    pub fn take(&mut self, raw: &[String], i: usize) -> Result<usize, String> {
        let flag = raw[i].as_str();
        let value = |i: usize| {
            raw.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag {
            "--tag" => self.tag = Some(value(i)?.to_lowercase()),
            "--folder" => self.folder = Some(value(i)?),
            "--all" => self.all = true,
            "--yes" | "-y" => self.yes = true,
            other => return Err(format!("unknown flag: {other}")),
        }
        Ok(if matches!(flag, "--tag" | "--folder") {
            i + 2
        } else {
            i + 1
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn takes_flag_values() {
        let raw = v(&["kepr", "ls", "--tag", "Work", "--folder", "a/b"]);
        let mut f = StoreFlags::default();
        assert_eq!(f.take(&raw, 2), Ok(4));
        assert_eq!(f.take(&raw, 4), Ok(6));
        assert_eq!(f.tag.as_deref(), Some("work"));
        assert_eq!(f.folder.as_deref(), Some("a/b"));
        assert!(f.take(&v(&["kepr", "ls", "--tag"]), 2).is_err());
        let raw = v(&["kepr", "rm", "--all", "-y"]);
        assert_eq!(f.take(&raw, 2), Ok(3));
        assert_eq!(f.take(&raw, 3), Ok(4));
        assert!(f.all && f.yes);
    }
}
