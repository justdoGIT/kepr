// cli_policy/tail.rs — reading the audit feed from the daemon page by page
// (`AuditTail`) and remembering where a reader stopped, for the SIEM
// forwarder (T7.14) and the alert rules (T7.15). The cursor is the last
// handled entry's chain hash, kept in a small 0600 state file under
// ~/.local/state/kepr (a directory the agent sandbox hides).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_policy::{AuditRecord, PolicyRequest, PolicyResponse};

pub struct Page {
    pub events: Vec<AuditRecord>,
    pub more: bool,
    pub reset: bool,
}

/// Where audit records come from (the daemon; a fixture in tests).
pub trait Source {
    fn page(&self, after: Option<&str>) -> Result<Page, String>;
}

pub struct Daemon;

impl Source for Daemon {
    fn page(&self, after: Option<&str>) -> Result<Page, String> {
        let req = Request::Policy(PolicyRequest::AuditTail {
            after: after.map(String::from),
        });
        match crate::client::send_request(&req)? {
            Response::Policy(PolicyResponse::AuditTailOk {
                events,
                more,
                reset,
            }) => Ok(Page {
                events,
                more,
                reset,
            }),
            Response::Err { error } => Err(error),
            _ => Err("unexpected daemon response (is the daemon up to date?)".into()),
        }
    }
}

fn home_base(var: &str, fallback: &str) -> PathBuf {
    match std::env::var_os(var).filter(|v| !v.is_empty()) {
        Some(v) => PathBuf::from(v),
        None => PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(fallback),
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `~/.local/state/kepr` (or `$XDG_STATE_HOME/kepr`).
pub fn state_dir() -> PathBuf {
    home_base("XDG_STATE_HOME", ".local/state").join("kepr")
}

/// `~/.config/kepr` (or `$XDG_CONFIG_HOME/kepr`).
pub fn config_dir() -> PathBuf {
    home_base("XDG_CONFIG_HOME", ".config").join("kepr")
}

/// A state file name for `spec` (a target, a rules file): its hash, so
/// a URL never appears in a file name.
pub fn state_file(prefix: &str, spec: &str) -> PathBuf {
    use sha2::Digest;
    let h = hex::encode(sha2::Sha256::digest(spec.as_bytes()));
    state_dir().join(format!("{prefix}-{}.json", &h[..16]))
}

/// Read a JSON state file; absent or unreadable means a fresh start.
pub fn load<T: DeserializeOwned + Default>(path: &Path) -> T {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Replace a JSON state file (0600, temp file + rename).
pub fn save<T: Serialize>(path: &Path, state: &T) -> Result<(), String> {
    let dir = path.parent().ok_or("state file has no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("state dir: {e}"))?;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let bytes = serde_json::to_vec(state).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("state file: {e}"))?;
    f.write_all(&bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("state file: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("state file: {e}"))
}

/// Handles one page (`true`: the page restarts from the first entry).
pub type Handle<'a> = dyn FnMut(&[AuditRecord], bool) -> Result<(), String> + 'a;
/// Persists the resume point.
pub type Commit<'a> = dyn FnMut(&Option<String>) -> Result<(), String> + 'a;

/// Hand every record after `*after` to `handle`, page by page, moving
/// `*after` (and calling `commit`, which persists it) only after a page
/// was handled: a crash re-sends at most one page, never skips one.
pub fn drain(
    src: &dyn Source,
    after: &mut Option<String>,
    handle: &mut Handle,
    commit: &mut Commit,
) -> Result<usize, String> {
    let mut n = 0;
    loop {
        let p = src.page(after.as_deref())?;
        if p.events.is_empty() {
            if p.reset {
                *after = None;
                commit(after)?;
            }
            return Ok(n);
        }
        handle(&p.events, p.reset)?;
        n += p.events.len();
        *after = p.events.last().map(|r| r.hash.clone());
        commit(after)?;
        if !p.more {
            return Ok(n);
        }
    }
}

#[cfg(test)]
pub mod fixture {
    //! An in-memory audit feed with the daemon's paging rules.
    use super::*;
    use std::cell::RefCell;

    pub struct Log {
        pub records: RefCell<Vec<AuditRecord>>,
        pub page_size: usize,
    }

    impl Log {
        pub fn new(records: Vec<AuditRecord>) -> Self {
            Log {
                records: RefCell::new(records),
                page_size: 2,
            }
        }
    }

    impl Source for Log {
        fn page(&self, after: Option<&str>) -> Result<Page, String> {
            let all = self.records.borrow();
            let (start, reset) = match after {
                None => (0, false),
                Some(h) => match all.iter().position(|r| r.hash == h) {
                    Some(i) => (i + 1, false),
                    None => (0, true),
                },
            };
            let rest = &all[start..];
            let events: Vec<AuditRecord> = rest.iter().take(self.page_size).cloned().collect();
            Ok(Page {
                more: rest.len() > events.len(),
                events,
                reset,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_policy::siem::record;

    #[test]
    fn drain_moves_the_cursor_page_by_page() {
        let log = fixture::Log::new((0..5).map(|i| record(i, "get", None, "ok")).collect());
        let mut after = None;
        let (mut seen, mut commits) = (Vec::new(), Vec::new());
        let n = drain(
            &log,
            &mut after,
            &mut |recs, _| {
                seen.extend(recs.iter().map(|r| r.seq));
                Ok(())
            },
            &mut |a| {
                commits.push(a.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(n, 5);
        assert_eq!(seen, [0, 1, 2, 3, 4]);
        assert_eq!(commits.len(), 3);
        assert_eq!(after.as_deref(), Some("h4"));
    }

    #[test]
    fn a_failed_page_keeps_the_cursor() {
        let log = fixture::Log::new((0..3).map(|i| record(i, "get", None, "ok")).collect());
        let mut after = Some("h0".to_string());
        let r = drain(
            &log,
            &mut after,
            &mut |_, _| Err("collector down".into()),
            &mut |_| Ok(()),
        );
        assert_eq!(r.unwrap_err(), "collector down");
        assert_eq!(after.as_deref(), Some("h0"));
    }

    #[test]
    fn state_files_round_trip_privately() {
        let dir = std::env::temp_dir().join(format!("kepr-tail-{}", std::process::id()));
        let p = dir.join("x.json");
        assert_eq!(load::<Option<String>>(&p), None);
        save(&p, &Some("h9".to_string())).unwrap();
        assert_eq!(load::<Option<String>>(&p).as_deref(), Some("h9"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!state_file("fwd", "otlp:https://x/?token=abc")
            .to_string_lossy()
            .contains("token"));
    }
}
