// cli_desktop/ss/audit.rs — a log of what programs did with the Secret
// Service: `$XDG_STATE_HOME/kepr/secret-service.log`, JSON lines, 0600,
// rotated at 1 MiB (one old file kept). It names the program and the item
// (id and label), never an attribute value or a secret. The daemon's own
// audit chain records each secret read by credential name as well; this
// file adds who asked, which only this front end can see.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use super::caller::{printable, Caller};

const MAX_BYTES: u64 = 1024 * 1024;

pub struct Audit {
    path: Option<PathBuf>,
    mem: Mutex<Vec<String>>,
}

pub fn default_path() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/state")
        });
    base.join("kepr/secret-service.log")
}

impl Audit {
    pub fn file(path: PathBuf) -> Audit {
        Audit {
            path: Some(path),
            mem: Mutex::new(Vec::new()),
        }
    }

    /// Keeps lines in memory (tests).
    pub fn memory() -> Audit {
        Audit {
            path: None,
            mem: Mutex::new(Vec::new()),
        }
    }

    pub fn lines(&self) -> Vec<String> {
        self.mem.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// One entry: `op` on `target` (item id, collection or `-`) by `who`;
    /// `label` is the item's label when there is one; `result` is `ok`,
    /// `denied` or the error.
    pub fn record(&self, who: &Caller, op: &str, target: &str, label: Option<&str>, result: &str) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let line = serde_json::json!({
            "ts": ts, "exe": who.exe, "pid": who.pid, "sandboxed": who.sandboxed,
            "op": op, "target": target, "label": label, "result": result,
        })
        .to_string();
        match &self.path {
            None => self
                .mem
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(line),
            Some(p) => {
                if let Err(e) = append(p, &line) {
                    eprintln!("kepr secret-service: cannot write {}: {e}", p.display());
                }
            }
        }
    }
}

fn append(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    if std::fs::metadata(path).is_ok_and(|m| m.len() > MAX_BYTES) {
        let mut old = path.as_os_str().to_owned();
        old.push(".1");
        let _ = std::fs::rename(path, old);
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    writeln!(f, "{line}")
}

/// One log line as text: `2026-10-28 12:00:01 ok      GetSecret  /usr/bin/x (pid 1)  Label`.
pub fn format_line(line: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    // Programs and items name themselves: nothing from the file reaches the
    // terminal as a control character.
    let s = |k: &str| printable(v.get(k).and_then(|x| x.as_str()).unwrap_or("-"));
    let ts = v.get("ts").and_then(|x| x.as_u64())?;
    let pid = v
        .get("pid")
        .and_then(|x| x.as_u64())
        .map_or(String::new(), |p| format!(" (pid {p})"));
    let sandbox = if v.get("sandboxed").and_then(|x| x.as_bool()) == Some(true) {
        " [sandboxed]"
    } else {
        ""
    };
    Some(format!(
        "{} {:<8} {:<12} {}{pid}{sandbox}  {}  {}",
        clock(ts),
        s("result"),
        s("op"),
        s("exe"),
        s("target"),
        s("label")
    ))
}

/// `YYYY-MM-DD HH:MM:SS` (UTC) of a Unix time.
pub fn clock(ts: u64) -> String {
    let (days, rem) = (ts / 86_400, ts % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who() -> Caller {
        Caller {
            name: ":1.3".into(),
            pid: Some(42),
            uid: Some(1000),
            exe: Some("/usr/bin/gh".into()),
            sandboxed: false,
        }
    }

    #[test]
    fn entries_name_the_program_and_the_item_but_never_a_secret() {
        let a = Audit::memory();
        a.record(&who(), "GetSecret", "ITEMID", Some("GitHub token"), "ok");
        let v: serde_json::Value = serde_json::from_str(&a.lines()[0]).unwrap();
        assert_eq!(v["exe"], "/usr/bin/gh");
        assert_eq!(
            (
                v["op"].as_str(),
                v["target"].as_str(),
                v["label"].as_str(),
                v["result"].as_str()
            ),
            (
                Some("GetSecret"),
                Some("ITEMID"),
                Some("GitHub token"),
                Some("ok")
            )
        );
        assert_eq!(v["pid"], 42);
    }

    #[test]
    fn lines_read_as_text_and_dates_are_right() {
        let a = Audit::memory();
        a.record(&who(), "GetSecret", "ITEMID", Some("GitHub token"), "ok");
        let t = format_line(&a.lines()[0]).unwrap();
        assert!(
            t.contains("GetSecret")
                && t.contains("/usr/bin/gh (pid 42)")
                && t.contains("GitHub token"),
            "{t}"
        );
        assert_eq!(format_line("not json"), None);
        let hostile = Caller {
            exe: Some("/tmp/\x1b[2Jx".into()),
            ..who()
        };
        a.record(&hostile, "GetSecret", "ID", Some("a\x07b\nc"), "ok");
        let t = format_line(&a.lines()[1]).unwrap();
        assert!(!t.chars().any(char::is_control), "{t:?}");
        assert!(t.contains("/tmp/?[2Jx") && t.contains("a?b?c"), "{t:?}");
        assert_eq!(clock(0), "1970-01-01 00:00:00");
        assert_eq!(
            clock(951_782_400 + 86_399),
            "2000-02-29 23:59:59",
            "a leap day"
        );
        assert_eq!(clock(1_793_188_799), "2026-10-28 11:59:59");
    }

    #[test]
    fn the_file_is_private_appended_and_rotated() {
        let dir = std::env::temp_dir().join(format!("kepr-ss-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("state/secret-service.log");
        let a = Audit::file(path.clone());
        a.record(&who(), "SearchItems", "-", None, "ok");
        a.record(&who(), "GetSecret", "X", None, "denied");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        std::fs::write(&path, vec![b'x'; MAX_BYTES as usize + 1]).unwrap();
        a.record(&who(), "GetSecret", "Y", None, "ok");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().lines().count(),
            1,
            "a fresh file"
        );
        assert!(dir.join("state/secret-service.log.1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
