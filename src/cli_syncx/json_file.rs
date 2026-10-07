// cli_syncx/json_file.rs — T8.06: a JSON file as a sync target.
//
//     kepr sync-push DB_PASS --url json:secrets.json#prod.db.password
//     kepr sync-pull DB_PASS --url json:secrets.json#prod.db.password
//
// `PATH#KEY`: KEY is a dotted path into the file's top-level object
// (`a.b` is `{"a":{"b":…}}`; a key that itself contains a dot can't be
// addressed). Push sets that one string and leaves every other key's
// value as it was (keys are written back sorted); missing objects on the
// way are created. The file is replaced atomically and is always mode
// 0600, whatever it was before. Pull reads one string (numbers and
// booleans as their JSON text).
//
// The file holds plain values: it is for handing a few secrets to a tool
// that reads a JSON file. Everything read from it is wiped from memory
// after use; sealed / SSH / share keys never get here (the daemon refuses
// to return them to `sync-push`).

use std::path::PathBuf;

use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::sync::Syncer;

pub struct JsonFileSyncer {
    path: PathBuf,
    key: Vec<String>,
}

impl JsonFileSyncer {
    /// `PATH#KEY` (after the `json:` scheme).
    pub fn from_path(spec: &str) -> Result<Self, String> {
        let (path, key) = spec
            .rsplit_once('#')
            .ok_or("json target needs PATH#KEY, e.g. json:secrets.json#db.password")?;
        if path.is_empty() {
            return Err("json target: the file path is empty".into());
        }
        let key: Vec<String> = key.split('.').map(str::to_string).collect();
        if key.iter().any(String::is_empty) {
            return Err(format!(
                "json target: {:?} is not a key path (a, a.b, …)",
                key.join(".")
            ));
        }
        Ok(Self {
            path: PathBuf::from(path),
            key,
        })
    }

    fn dotted(&self, n: usize) -> String {
        self.key[..n].join(".")
    }

    /// The file's top-level object; `None` when the file doesn't exist.
    fn load(&self) -> Result<Option<Wiped>, String> {
        let text = match std::fs::read(&self.path) {
            Ok(b) => Zeroizing::new(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", self.path.display())),
        };
        match serde_json::from_slice(&text) {
            Ok(v @ Value::Object(_)) => Ok(Some(Wiped(v))),
            Ok(mut other) => {
                wipe(&mut other);
                Err(format!("{}: not a JSON object", self.path.display()))
            }
            // serde_json's message names a line and column, never content.
            Err(e) => Err(format!("{}: not valid JSON ({e})", self.path.display())),
        }
    }

    /// The string at KEY, `None` when KEY (or the file) is missing.
    fn lookup(&self) -> Result<Option<Zeroizing<String>>, String> {
        let Some(doc) = self.load()? else {
            return Ok(None);
        };
        let mut at = &doc.0;
        for (i, k) in self.key.iter().enumerate() {
            match at {
                Value::Object(m) => match m.get(k) {
                    Some(v) => at = v,
                    None => return Ok(None),
                },
                _ => return Err(format!("json: {} is not an object", self.dotted(i))),
            }
        }
        match at {
            Value::String(s) => Ok(Some(Zeroizing::new(s.clone()))),
            Value::Number(_) | Value::Bool(_) => Ok(Some(Zeroizing::new(at.to_string()))),
            _ => Err(format!(
                "json: {} is not a string, number or boolean",
                self.dotted(self.key.len())
            )),
        }
    }

    fn set(&self, root: &mut Value, value: &str) -> Result<(), String> {
        let mut at = root;
        for (i, k) in self.key.iter().enumerate() {
            let Value::Object(m) = at else {
                return Err(format!("json: {} is not an object", self.dotted(i)));
            };
            if i + 1 == self.key.len() {
                if let Some(mut old) = m.insert(k.clone(), Value::String(value.to_string())) {
                    wipe(&mut old);
                }
                return Ok(());
            }
            at = m
                .entry(k.clone())
                .or_insert_with(|| Value::Object(Map::new()));
        }
        Ok(())
    }
}

/// T11.17: every string / number / boolean in the file at `path` whose
/// dotted key starts with `prefix`, as `(key, json:PATH#key)`.
pub fn list(path: &str, prefix: &str) -> Result<Vec<(String, String)>, String> {
    let file = JsonFileSyncer {
        path: PathBuf::from(path),
        key: Vec::new(),
    };
    let doc = file
        .load()?
        .ok_or_else(|| format!("{path}: no such file"))?;
    let mut keys = Vec::new();
    leaves(&doc.0, String::new(), &mut keys);
    Ok(keys
        .into_iter()
        .filter(|k| k.starts_with(prefix))
        .map(|k| {
            let url = format!("json:{path}#{k}");
            (k, url)
        })
        .collect())
}

fn leaves(v: &Value, at: String, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                // A key with a dot can't be addressed as PATH#a.b.
                if !k.is_empty() && !k.contains('.') {
                    let next = if at.is_empty() {
                        k.clone()
                    } else {
                        format!("{at}.{k}")
                    };
                    leaves(v, next, out);
                }
            }
        }
        Value::String(_) | Value::Number(_) | Value::Bool(_) if !at.is_empty() => out.push(at),
        _ => {}
    }
}

/// A parsed document whose strings are zeroed when it is dropped.
struct Wiped(Value);

impl Drop for Wiped {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Zero every string in `v` (the values may be secrets).
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(m) => m.values_mut().for_each(wipe),
        _ => {}
    }
}

impl Syncer for JsonFileSyncer {
    fn backend(&self) -> &'static str {
        "json"
    }

    fn push(&self, value: &str) -> Result<(), String> {
        let mut doc = self
            .load()?
            .unwrap_or_else(|| Wiped(Value::Object(Map::new())));
        self.set(&mut doc.0, value)?;
        let mut bytes = Zeroizing::new(
            serde_json::to_vec_pretty(&doc.0).map_err(|e| format!("json: encode: {e}"))?,
        );
        bytes.push(b'\n');
        // A bare file name has an empty parent: the current directory.
        let path = match self.path.parent() {
            Some(p) if p.as_os_str().is_empty() => PathBuf::from(".").join(&self.path),
            _ => self.path.clone(),
        };
        super::atomic_file::write(&path, &bytes, 0o600)
    }

    fn fetch(&self) -> Result<Option<Zeroizing<String>>, String> {
        self.lookup()
    }

    fn pull(&self) -> Result<String, String> {
        match self.lookup()? {
            Some(v) => Ok(v.as_str().to_string()),
            None => Err(format!(
                "json: {} not found in {}",
                self.dotted(self.key.len()),
                self.path.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn target(dir: &std::path::Path, key: &str) -> JsonFileSyncer {
        let spec = format!("{}#{key}", dir.join("s.json").display());
        JsonFileSyncer::from_path(&spec).unwrap()
    }

    fn mode(p: &std::path::Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn push_creates_the_file_with_mode_0600() {
        let d = tempfile::tempdir().unwrap();
        target(d.path(), "db.password").push("hunter2").unwrap();
        let p = d.path().join("s.json");
        assert_eq!(mode(&p), 0o600);
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(v["db"]["password"], "hunter2");
        // No temp files left behind.
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn pull_reads_nested_keys() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.json");
        std::fs::write(&p, r#"{"a":{"b":"x1","n":42,"t":true},"top":"y"}"#).unwrap();
        assert_eq!(target(d.path(), "a.b").pull().unwrap(), "x1");
        assert_eq!(target(d.path(), "top").pull().unwrap(), "y");
        assert_eq!(target(d.path(), "a.n").pull().unwrap(), "42");
        assert_eq!(target(d.path(), "a.t").pull().unwrap(), "true");
        assert!(target(d.path(), "a.missing").fetch().unwrap().is_none());
        assert!(target(d.path(), "a.b.c").pull().is_err());
        assert!(target(d.path(), "a").pull().is_err());
        // T11.17: listing for `sync import --from json:PATH`.
        let p = p.display().to_string();
        let keys: Vec<String> = list(&p, "").unwrap().into_iter().map(|k| k.0).collect();
        assert_eq!(keys, ["a.b", "a.n", "a.t", "top"]);
        let one = list(&p, "a.b").unwrap();
        assert_eq!(one, [("a.b".to_string(), format!("json:{p}#a.b"))]);
        let gone = JsonFileSyncer::from_path(&format!("{}#k", d.path().join("no").display()));
        assert!(gone.unwrap().fetch().unwrap().is_none());
    }

    #[test]
    fn push_leaves_other_keys_untouched_and_tightens_the_mode() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.json");
        let before = r#"{"a":{"b":"old","keep":[1,{"x":"y"}]},"other":"z","num":1.5}"#;
        std::fs::write(&p, before).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        target(d.path(), "a.b").push("new").unwrap();
        target(d.path(), "c.d.e").push("deep").unwrap();
        assert_eq!(mode(&p), 0o600);
        let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let mut want: Value = serde_json::from_str(before).unwrap();
        want["a"]["b"] = "new".into();
        want["c"] = serde_json::json!({"d": {"e": "deep"}});
        assert_eq!(v, want);
    }

    #[test]
    fn refuses_bad_targets_without_writing() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.json");
        std::fs::write(&p, r#"{"a":"scalar"}"#).unwrap();
        assert!(target(d.path(), "a.b").push("v").is_err());
        std::fs::write(&p, "[1,2]").unwrap();
        assert!(target(d.path(), "a").push("v").is_err());
        std::fs::write(&p, "{not json").unwrap();
        let e = target(d.path(), "a").push("v").unwrap_err();
        assert!(!e.contains("not json"), "never echoes content: {e}");
        assert_eq!(std::fs::read(&p).unwrap(), b"{not json");
        for bad in ["s.json", "s.json#", "s.json#a..b", "#a"] {
            assert!(JsonFileSyncer::from_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_bare_file_name_is_relative_to_the_current_directory() {
        let s = JsonFileSyncer::from_path("secrets.json#k").unwrap();
        assert_eq!(s.path, PathBuf::from("secrets.json"));
        assert_eq!(s.key, ["k"]);
        let s = JsonFileSyncer::from_path("dir/a#b.json#x.y").unwrap();
        assert_eq!(s.path, PathBuf::from("dir/a#b.json"));
        assert_eq!(s.key, ["x", "y"]);
    }
}
