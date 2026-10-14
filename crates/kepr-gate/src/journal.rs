//! Metadata-only request journal (T1.11, T11.22). One JSON line per
//! request on stderr, and the same entries to the daemon, in batches,
//! for `kepr agent logs`. Never headers, query strings or bodies; the
//! path is the one the agent sent, as a template, with every value this
//! session resolved masked out, so a substituted key never appears.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::{Response, StatusCode};
use kepr_core::gate_journal::{JournalEntry, MAX_BATCH};
use kepr_core::generate::ZeroString;

use crate::proxy::{Body, State};
use crate::vault::Cache;

/// Entries kept for the daemon at most; beyond it new ones are dropped
/// (they still reach stderr).
const MAX_QUEUED: usize = 4096;
const FLUSH_EVERY: Duration = Duration::from_millis(500);

pub struct Entry<'a> {
    pub provider: &'a str,
    /// Upstream host (`host:port` for connections).
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub bytes_out: usize,
    pub ms: u128,
    pub blocked: Option<&'a str>,
}

/// The stored form of `e`: query dropped, every value in `secrets`
/// masked, then reduced to a template and bounded.
pub fn entry(session: &str, e: &Entry, secrets: &[ZeroString]) -> JournalEntry {
    let mut path = e
        .path
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_string();
    for s in secrets.iter().map(|s| s.as_str()).filter(|s| !s.is_empty()) {
        if path.contains(s) {
            path = path.replace(s, "{redacted}");
        }
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    JournalEntry {
        ts,
        session: session.to_string(),
        provider: e.provider.to_string(),
        host: e.host.to_string(),
        method: e.method.to_string(),
        path,
        status: e.status,
        bytes_out: e.bytes_out as u64,
        ms: u64::try_from(e.ms).unwrap_or(u64::MAX),
        blocked: e.blocked.map(str::to_string),
        tokens: None,
    }
    .sanitized()
}

pub fn format(e: &JournalEntry) -> String {
    serde_json::to_string(e).unwrap_or_default()
}

/// The stored line of one request or connection of this session.
fn line(state: &State, e: &Entry) -> JournalEntry {
    let secrets: Vec<ZeroString> = state.cache.values().into_iter().map(|(_, v)| v).collect();
    entry(&state.session_id, e, &secrets)
}

/// Print `line` and queue it for the daemon.
pub fn push(q: &Queue, line: JournalEntry) {
    eprintln!("{}", format(&line));
    q.push(line);
}

/// Journal one request or connection of this session.
pub fn emit(state: &State, e: &Entry) {
    push(&state.journal, line(state, e));
}

/// Entries on their way to the daemon.
#[derive(Default)]
pub struct Queue {
    pending: Mutex<Vec<JournalEntry>>,
    /// Held while a batch is on its way, so the final flush at session
    /// end waits for the flusher thread's.
    sending: Mutex<()>,
}

impl Queue {
    pub fn push(&self, e: JournalEntry) {
        if let Ok(mut p) = self.pending.lock() {
            if p.len() < MAX_QUEUED {
                p.push(e);
            }
        }
    }

    /// Everything pending.
    pub(crate) fn take(&self) -> Vec<JournalEntry> {
        match self.pending.lock() {
            Ok(mut p) => std::mem::take(&mut *p),
            Err(_) => Vec::new(),
        }
    }

    /// Send what is pending to the daemon.
    pub fn flush(&self, cache: &Cache) {
        let Ok(_sending) = self.sending.lock() else {
            return;
        };
        for batch in self.take().chunks(MAX_BATCH) {
            if cache.journal(batch.to_vec()).is_err() {
                break; // the daemon refused (an older daemon): drop the rest
            }
        }
    }
}

/// Flush on a thread of its own: the daemon channel is blocking.
pub fn spawn_flusher(q: Arc<Queue>, cache: Arc<Cache>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(FLUSH_EVERY);
        q.flush(&cache);
    });
}

/// The journal line of one proxied HTTP request.
pub(crate) struct Log<'a> {
    pub state: &'a State,
    pub provider: &'a str,
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub start: Instant,
}

impl Log<'_> {
    /// The line now, to journal later (T9.07: when a metered response's
    /// tokens are known).
    pub fn line(
        &self,
        status: StatusCode,
        bytes_out: usize,
        blocked: Option<&str>,
    ) -> JournalEntry {
        line(
            self.state,
            &Entry {
                provider: self.provider,
                host: self.host,
                method: self.method,
                path: self.path,
                status: status.as_u16(),
                bytes_out,
                ms: self.start.elapsed().as_millis(),
                blocked,
            },
        )
    }

    pub fn emit(&self, status: StatusCode, bytes_out: usize, blocked: Option<&str>) {
        push(&self.state.journal, self.line(status, bytes_out, blocked));
    }

    pub fn reply(
        &self,
        r: Response<Body>,
        bytes_out: usize,
        blocked: Option<&str>,
    ) -> Response<Body> {
        self.emit(r.status(), bytes_out, blocked);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Resolve, DEFAULT_TTL};
    use kepr_core::binding::Inject;

    fn e(path: &str) -> Entry<'_> {
        Entry {
            provider: "google",
            host: "generativelanguage.googleapis.com",
            method: "POST",
            path,
            status: 200,
            bytes_out: 5,
            ms: 1,
            blocked: None,
        }
    }

    #[test]
    fn query_is_stripped_and_keys_present() {
        let line = format(&entry("s", &e("/v1/x?key=secret"), &[]));
        assert!(!line.contains("secret"));
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        for k in [
            "ts",
            "session",
            "provider",
            "host",
            "method",
            "path",
            "status",
            "bytes_out",
            "ms",
        ] {
            assert!(v.get(k).is_some(), "{k}");
        }
        assert_eq!(v["path"], "/v1/x");
        assert!(v.get("blocked").is_none());
    }

    #[test]
    fn a_resolved_value_never_reaches_the_journal() {
        // Short and lowercase, so neither the template nor the key shapes
        // would catch it: only the session's own values do.
        let secret = ZeroString::from_string("hunter2hunter2".into());
        let got = entry("s", &e("/u/hunter2hunter2/x/pre-hunter2hunter2"), &[secret]);
        let line = format(&got);
        assert!(!line.contains("hunter2"), "{line}");
        assert_eq!(got.path, "/u/{redacted}/x/pre-{redacted}");
    }

    /// A daemon channel that keeps the journal batches it is sent.
    struct Sink(Arc<Mutex<Vec<Vec<JournalEntry>>>>, bool);
    impl Resolve for Sink {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            Err("none".into())
        }
        fn journal(&self, entries: Vec<JournalEntry>) -> Result<(), String> {
            self.0.lock().unwrap().push(entries);
            self.1.then_some(()).ok_or_else(|| "refused".to_string())
        }
    }

    #[test]
    fn queued_entries_reach_the_daemon_in_bounded_batches() {
        let got = Arc::new(Mutex::new(Vec::new()));
        let cache = Cache::new(Box::new(Sink(got.clone(), true)), DEFAULT_TTL);
        let q = Queue::default();
        for i in 0..(MAX_BATCH * 2 + 3) {
            q.push(entry("0123456789abcdef", &e(&format!("/v1/{i}x")), &[]));
        }
        q.flush(&cache);
        q.flush(&cache); // nothing left: no empty batch
        let batches = got.lock().unwrap();
        let sizes: Vec<usize> = batches.iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![MAX_BATCH, MAX_BATCH, 3]);
        assert_eq!(batches[2][2].path, format!("/v1/{}x", MAX_BATCH * 2 + 2));
    }

    #[test]
    fn the_queue_is_bounded_and_a_refusal_stops_the_flush() {
        let got = Arc::new(Mutex::new(Vec::new()));
        let cache = Cache::new(Box::new(Sink(got.clone(), false)), DEFAULT_TTL);
        let q = Queue::default();
        for _ in 0..(MAX_QUEUED + 10) {
            q.push(entry("s", &e("/v1/x"), &[]));
        }
        assert_eq!(q.pending.lock().unwrap().len(), MAX_QUEUED);
        q.flush(&cache);
        assert_eq!(got.lock().unwrap().len(), 1, "stops at the first refusal");
        assert!(q.pending.lock().unwrap().is_empty());
    }
}
