// cli_policy/report_filters.rs — `kepr report access KEY --kind a,b`, and
// named filters saved in `~/.config/kepr/report-filters.toml` (T13.09).
//
//   [filters.shares]
//   kinds = ["share", "read"]
//
// Filtering is on the row kinds the daemon reports; nothing here sees a
// value.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use kepr_core::protocol_policy::AccessRow;
use serde::Deserialize;

/// Every kind `daemon_policy::report` can emit.
pub const KINDS: &[&str] = &[
    "binding", "alias", "folder", "sync", "policy", "share", "agent", "read", "ssh",
];

#[derive(Deserialize, Default)]
struct File {
    #[serde(default)]
    filters: BTreeMap<String, Entry>,
}

#[derive(Deserialize)]
struct Entry {
    kinds: Vec<String>,
}

pub fn path() -> PathBuf {
    crate::cli_recordsx::types::config_dir().join("report-filters.toml")
}

/// `a,b` as a list of valid kinds.
pub fn parse_kinds(text: &str) -> Result<Vec<String>, String> {
    let kinds: Vec<String> = text
        .split(',')
        .map(|k| k.trim().to_lowercase())
        .filter(|k| !k.is_empty())
        .collect();
    if kinds.is_empty() {
        return Err("--kind needs at least one kind".into());
    }
    for k in &kinds {
        if !KINDS.contains(&k.as_str()) {
            return Err(format!(
                "unknown kind {k:?}; valid kinds: {}",
                KINDS.join(", ")
            ));
        }
    }
    Ok(kinds)
}

fn valid_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err("a filter name is 1 to 32 characters of a-z, 0-9, - and _".into())
    }
}

fn load_at(file: &Path) -> Result<BTreeMap<String, Vec<String>>, String> {
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(format!("{}: {e}", file.display())),
    };
    let f: File = toml::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
    let mut out = BTreeMap::new();
    for (name, entry) in f.filters {
        valid_name(&name)?;
        parse_kinds(&entry.kinds.join(","))?;
        out.insert(name, entry.kinds);
    }
    Ok(out)
}

pub fn get_at(file: &Path, name: &str) -> Result<Vec<String>, String> {
    let all = load_at(file)?;
    all.get(name).cloned().ok_or_else(|| {
        let known: Vec<&str> = all.keys().map(String::as_str).collect();
        format!(
            "no saved filter {name:?} (saved: {})",
            if known.is_empty() {
                "none".into()
            } else {
                known.join(", ")
            }
        )
    })
}

pub fn list_at(file: &Path) -> Result<Vec<(String, Vec<String>)>, String> {
    Ok(load_at(file)?.into_iter().collect())
}

/// Store `kinds` as filter `name`, replacing one of that name.
pub fn save_at(file: &Path, name: &str, kinds: &[String]) -> Result<(), String> {
    valid_name(name)?;
    let mut all = load_at(file)?;
    all.insert(name.to_string(), kinds.to_vec());
    let mut text = String::new();
    for (n, ks) in &all {
        let list: Vec<String> = ks.iter().map(|k| format!("\"{k}\"")).collect();
        text.push_str(&format!("[filters.{n}]\nkinds = [{}]\n\n", list.join(", ")));
    }
    let dir = file.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".report-filters.kepr-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()))
        .and_then(|()| std::fs::rename(&tmp, file))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{}: {e}", file.display())
        })
}

/// What `report access` was asked: the key, and which rows to keep.
#[derive(Default, Debug)]
pub struct Options {
    pub name: Option<String>,
    pub kinds: Option<Vec<String>>,
    pub filter: Option<String>,
    pub save: Option<String>,
    pub list: bool,
}

impl Options {
    pub fn parse(args: &[&str]) -> Result<Self, String> {
        let mut o = Options::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut value = |flag: &str| {
                it.next()
                    .map(|v| (*v).to_string())
                    .ok_or_else(|| format!("{flag} needs a value"))
            };
            match *a {
                "--kind" => o.kinds = Some(parse_kinds(&value("--kind")?)?),
                "--filter" => o.filter = Some(value("--filter")?),
                "--save-filter" => o.save = Some(value("--save-filter")?),
                "--filters" => o.list = true,
                f if f.starts_with("--") => return Err(format!("unknown flag {f}")),
                n if o.name.is_none() => o.name = Some(n.to_string()),
                _ => return Err("one credential name only".into()),
            }
        }
        if o.kinds.is_some() && o.filter.is_some() {
            return Err("use --kind or --filter, not both".into());
        }
        if o.save.is_some() && o.kinds.is_none() {
            return Err("--save-filter needs --kind".into());
        }
        Ok(o)
    }

    /// The kinds to keep, saving them first when asked.
    pub fn resolve(&self) -> Result<Vec<String>, String> {
        self.resolve_at(&path())
    }

    pub fn resolve_at(&self, file: &Path) -> Result<Vec<String>, String> {
        if let (Some(name), Some(kinds)) = (&self.save, &self.kinds) {
            save_at(file, name, kinds)?;
        }
        match (&self.kinds, &self.filter) {
            (Some(k), _) => Ok(k.clone()),
            (None, Some(f)) => get_at(file, f),
            (None, None) => Ok(Vec::new()),
        }
    }
}

pub fn print_saved() -> kepr_core::protocol::Response {
    match list_at(&path()) {
        Ok(all) => {
            if all.is_empty() {
                crate::cli_ui::info("no saved report filters");
            }
            for (n, k) in all {
                println!("{n}  {}", k.join(","));
            }
            kepr_core::protocol::Response::Pong
        }
        Err(e) => kepr_core::protocol::Response::fail(e),
    }
}

/// The rows whose kind is in `kinds` (all rows when `kinds` is empty).
pub fn keep(rows: Vec<AccessRow>, kinds: &[String]) -> Vec<AccessRow> {
    if kinds.is_empty() {
        return rows;
    }
    rows.into_iter()
        .filter(|r| kinds.contains(&r.kind))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(kind: &str) -> AccessRow {
        AccessRow {
            kind: kind.into(),
            detail: format!("{kind} detail"),
        }
    }

    #[test]
    fn kinds_are_parsed_and_checked() {
        assert_eq!(parse_kinds("share, READ").unwrap(), ["share", "read"]);
        let e = parse_kinds("share,reed").unwrap_err();
        assert!(
            e.contains("\"reed\"") && e.contains("valid kinds: binding"),
            "{e}"
        );
        assert!(parse_kinds(" , ").is_err());
    }

    #[test]
    fn filtering_keeps_only_the_listed_kinds_in_order() {
        let rows = vec![row("share"), row("read"), row("folder"), row("read")];
        let got = keep(rows.clone(), &["read".into(), "folder".into()]);
        let kinds: Vec<&str> = got.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(kinds, ["read", "folder", "read"]);
        assert_eq!(keep(rows, &[]).len(), 4, "no filter, all rows");
    }

    #[test]
    fn a_saved_filter_round_trips_and_a_second_one_keeps_the_first() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("sub").join("report-filters.toml");
        save_at(&f, "uses", &["share".into(), "read".into()]).unwrap();
        save_at(&f, "where", &["binding".into(), "folder".into()]).unwrap();
        assert_eq!(get_at(&f, "uses").unwrap(), ["share", "read"]);
        assert_eq!(get_at(&f, "where").unwrap(), ["binding", "folder"]);
        save_at(&f, "uses", &["agent".into()]).unwrap();
        assert_eq!(get_at(&f, "uses").unwrap(), ["agent"]);
        let names: Vec<String> = list_at(&f).unwrap().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["uses", "where"]);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn unknown_filters_and_bad_names_and_bad_files_are_errors() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("report-filters.toml");
        let e = get_at(&f, "nope").unwrap_err();
        assert!(e.contains("no saved filter") && e.contains("none"), "{e}");
        assert!(save_at(&f, "Bad Name", &["read".into()]).is_err());
        assert!(save_at(&f, "", &["read".into()]).is_err());
        std::fs::write(&f, "[filters.x]\nkinds = [\"nonsense\"]\n").unwrap();
        assert!(get_at(&f, "x").unwrap_err().contains("unknown kind"));
        std::fs::write(&f, "not toml [").unwrap();
        assert!(list_at(&f).is_err());
    }

    #[test]
    fn options_parse_and_resolve() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f.toml");
        let o = Options::parse(&["KEY", "--kind", "share,read", "--save-filter", "uses"]).unwrap();
        assert_eq!(o.name.as_deref(), Some("KEY"));
        assert_eq!(o.resolve_at(&f).unwrap(), ["share", "read"]);
        let o = Options::parse(&["--filter", "uses", "KEY"]).unwrap();
        assert_eq!(o.resolve_at(&f).unwrap(), ["share", "read"]);
        assert!(Options::parse(&["KEY"])
            .unwrap()
            .resolve_at(&f)
            .unwrap()
            .is_empty());
        for bad in [
            vec!["K", "--kind"],
            vec!["K", "--kind", "read", "--filter", "x"],
            vec!["K", "--save-filter", "x"],
            vec!["K", "L"],
            vec!["K", "--bogus"],
        ] {
            assert!(Options::parse(&bad).is_err(), "{bad:?}");
        }
        assert!(Options::parse(&["K", "--filter", "missing"])
            .unwrap()
            .resolve_at(&f)
            .is_err());
    }
}
