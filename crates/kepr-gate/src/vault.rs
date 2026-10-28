//! Sealed-value resolution over the daemon's private channel (T1.09).
//!
//! The daemon spawns the gate with one end of a socket pair on fd 3.
//! That is the only place values come from: the gate never connects to
//! the public daemon socket.
//!
//! Every request carries an id and replies are matched by id, so a reply
//! that arrives after a timeout (a slow consent prompt) is discarded
//! rather than taken as the answer to the next request. Cached values
//! are dropped whenever the daemon's store generation changes (any set,
//! delete or expiry), and misses are resolved one at a time so a burst
//! of parallel requests causes a single consent prompt.

use std::collections::HashMap;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use kepr_core::binding::Inject;
use kepr_core::framing::{read_frame, write_frame};
use kepr_core::gate_journal::JournalEntry;
use kepr_core::gate_protocol::{GateRequest, GateResponse};
use kepr_core::gate_record::GateRecord;
use kepr_core::generate::ZeroString;
use kepr_core::protocol::MAX_MSG_BYTES;

use crate::secret_cell::SecretCell;

pub const DEFAULT_TTL: Duration = Duration::from_secs(300);
/// Long enough for a human to answer a polkit consent dialog.
const REPLY_TIMEOUT: Duration = Duration::from_secs(120);

pub trait Resolve: Send + Sync {
    fn resolve(&self, name: &str, host: &str, port: u16) -> Result<(ZeroString, Inject), String>;
    /// The daemon's store generation (see module docs).
    fn generation(&self) -> Result<u64, String>;
    /// T7.09: hand recorded chunks to the daemon.
    fn record(&self, _record: GateRecord) -> Result<(), String> {
        Err("recording is not available".into())
    }
    /// T11.22: hand request journal entries to the daemon.
    fn journal(&self, _entries: Vec<JournalEntry>) -> Result<(), String> {
        Err("journal is not available".into())
    }
    /// T9.06: add to today's usage of `name`; today's (requests, tokens).
    fn day_usage(&self, _name: &str, _requests: u64, _tokens: u64) -> Result<(u64, u64), String> {
        Err("daily usage is not available".into())
    }
    /// T9.08: is one of these fingerprints a planted canary?
    fn canary(&self, _fingerprints: Vec<String>) -> Result<bool, String> {
        Ok(false)
    }
}

pub struct FdResolver {
    stream: Mutex<UnixStream>,
    next_id: AtomicU64,
}

impl FdResolver {
    /// Take ownership of fd 3. Call once, at startup, after checking
    /// the fd is open.
    pub fn from_fd3() -> Result<Self, String> {
        // SAFETY: fd 3 was dup2'd into this process by the daemon for
        // exactly this purpose and nothing else in the gate uses it;
        // main() checks it is open before calling this, and this is
        // called once, so ownership is not shared.
        let stream = unsafe { UnixStream::from_raw_fd(3) };
        stream
            .set_read_timeout(Some(REPLY_TIMEOUT))
            .map_err(|e| format!("daemon channel: {e}"))?;
        Ok(Self {
            stream: Mutex::new(stream),
            next_id: AtomicU64::new(1),
        })
    }

    fn call(&self, make: impl FnOnce(u64) -> GateRequest) -> Result<GateResponse, String> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let payload = serde_json::to_vec(&make(id)).map_err(|e| format!("encode: {e}"))?;
        let mut s = self.stream.lock().map_err(|_| "daemon channel poisoned")?;
        write_frame(&mut *s, &payload).map_err(|e| format!("daemon channel: {e}"))?;
        loop {
            let raw = zeroize::Zeroizing::new(
                read_frame(&mut *s, MAX_MSG_BYTES).map_err(|e| format!("daemon channel: {e}"))?,
            );
            let resp: GateResponse = serde_json::from_slice(&raw)
                .map_err(|_| "daemon channel: malformed response".to_string())?;
            if resp.id() == id {
                return Ok(resp);
            }
            // A late reply to an earlier request that timed out: drop it.
        }
    }
}

impl Resolve for FdResolver {
    fn resolve(&self, name: &str, host: &str, port: u16) -> Result<(ZeroString, Inject), String> {
        let req = |id| GateRequest::Resolve {
            id,
            name: name.to_string(),
            host: host.to_string(),
            port,
        };
        match self.call(req)? {
            GateResponse::ResolveOk { value, inject, .. } => Ok((value, inject)),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn generation(&self) -> Result<u64, String> {
        match self.call(|id| GateRequest::Generation { id })? {
            GateResponse::Generation { generation, .. } => Ok(generation),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn record(&self, record: GateRecord) -> Result<(), String> {
        match self.call(|id| GateRequest::Record { id, record })? {
            GateResponse::Recorded { .. } => Ok(()),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn journal(&self, entries: Vec<JournalEntry>) -> Result<(), String> {
        match self.call(|id| GateRequest::Journal { id, entries })? {
            GateResponse::Recorded { .. } => Ok(()),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn day_usage(&self, name: &str, requests: u64, tokens: u64) -> Result<(u64, u64), String> {
        let req = |id| GateRequest::DayUsage {
            id,
            name: name.to_string(),
            requests,
            tokens,
        };
        match self.call(req)? {
            GateResponse::UsageToday {
                requests, tokens, ..
            } => Ok((requests, tokens)),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn canary(&self, fingerprints: Vec<String>) -> Result<bool, String> {
        match self.call(|id| GateRequest::Canary { id, fingerprints })? {
            GateResponse::CanaryChecked { tripped, .. } => Ok(tripped),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }
}

type Key = (String, String, u16);

pub struct Cache {
    resolver: Box<dyn Resolve>,
    ttl: Duration,
    /// T12.02: values sit in secret memory between requests (secret_cell.rs).
    entries: Mutex<HashMap<Key, (SecretCell, Inject, Instant)>>,
    /// (last generation seen, when it was checked).
    generation: Mutex<(u64, Option<Instant>)>,
    /// Serialises cache misses (single-flight).
    resolving: Mutex<()>,
    /// T7.08: tokens minted from cached values (GitHub App installation
    /// tokens) by a hash of what minted them, with their expiry; dropped
    /// with the values, so a store change ends them too.
    minted: Mutex<HashMap<[u8; 32], (SecretCell, u64)>>,
}

impl Cache {
    pub fn new(resolver: Box<dyn Resolve>, ttl: Duration) -> Self {
        Self {
            resolver,
            ttl,
            entries: Mutex::new(HashMap::new()),
            generation: Mutex::new((0, None)),
            resolving: Mutex::new(()),
            minted: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, key: &Key) -> Option<(ZeroString, Inject)> {
        let map = self.entries.lock().ok()?;
        let (v, i, at) = map.get(key)?;
        (at.elapsed() < self.ttl).then(|| (v.reveal(), i.clone()))
    }

    /// Drop every cached value if the daemon's store changed. Asked at
    /// most every GENERATION_EVERY: a busy session doesn't pay one daemon
    /// round trip per request, and a revoked key stops within that time.
    fn check_generation(&self) -> Result<(), String> {
        const GENERATION_EVERY: Duration = Duration::from_millis(250);
        let mut seen = self.generation.lock().map_err(|_| "cache poisoned")?;
        if seen.1.is_some_and(|at| at.elapsed() < GENERATION_EVERY) {
            return Ok(());
        }
        let now = self.resolver.generation()?;
        if seen.0 != now {
            self.clear();
        }
        *seen = (now, Some(Instant::now()));
        Ok(())
    }

    pub fn get(&self, name: &str, host: &str, port: u16) -> Result<(ZeroString, Inject), String> {
        self.check_generation()?;
        let key = (name.to_string(), host.to_string(), port);
        if let Some(hit) = self.cached(&key) {
            return Ok(hit);
        }
        let _one_at_a_time = self.resolving.lock().map_err(|_| "cache poisoned")?;
        if let Some(hit) = self.cached(&key) {
            return Ok(hit); // resolved by the request we waited behind
        }
        let (v, i) = self.resolver.resolve(name, host, port)?;
        if let Ok(mut map) = self.entries.lock() {
            map.insert(key, (SecretCell::new(&v), i.clone(), Instant::now()));
        }
        Ok((v, i))
    }

    /// `(NAME, value)` for every value this session has resolved; used
    /// by the prompt DLP check.
    pub fn values(&self) -> Vec<(String, ZeroString)> {
        match self.entries.lock() {
            Ok(map) => map
                .iter()
                .map(|((n, _, _), (v, _, _))| (n.clone(), v.reveal()))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// T12.01: what no response to the agent may contain: every cached
    /// value (a JSON record's secret fields only) and minted token, with
    /// their JSON-escaped forms (mask::forms). A poisoned lock still
    /// yields its values: masking fails closed.
    pub fn needles(&self) -> Vec<ZeroString> {
        let mut out = Vec::new();
        let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        for (v, _, _) in map.values() {
            out.extend(crate::mask::forms(&v.reveal()));
        }
        drop(map);
        let map = self.minted.lock().unwrap_or_else(|e| e.into_inner());
        for (t, _) in map.values() {
            out.extend(crate::mask::forms(&t.reveal()));
        }
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        out.dedup_by(|a, b| a.as_str() == b.as_str());
        out
    }

    /// T7.09: pass recorded chunks to the daemon (not cached).
    pub fn record(&self, record: GateRecord) -> Result<(), String> {
        self.resolver.record(record)
    }

    /// T11.22: pass request journal entries to the daemon.
    pub fn journal(&self, entries: Vec<JournalEntry>) -> Result<(), String> {
        self.resolver.journal(entries)
    }

    /// T9.08: ask the daemon about canary fingerprints (not cached).
    pub fn canary(&self, fingerprints: Vec<String>) -> Result<bool, String> {
        self.resolver.canary(fingerprints)
    }

    /// T9.06: report usage of `name` to the daemon (not cached).
    pub fn day_usage(&self, name: &str, requests: u64, tokens: u64) -> Result<(u64, u64), String> {
        self.resolver.day_usage(name, requests, tokens)
    }

    /// Drop every value and token; a cell zeroizes and unmaps its region
    /// on drop. A poisoned lock is cleared all the same.
    pub fn clear(&self) {
        (self.entries.lock().unwrap_or_else(|e| e.into_inner())).clear();
        (self.minted.lock().unwrap_or_else(|e| e.into_inner())).clear();
    }

    /// T7.08: a token minted under `key`, with its expiry.
    pub fn minted(&self, key: &[u8; 32]) -> Option<(ZeroString, u64)> {
        let map = self.minted.lock().ok()?;
        map.get(key).map(|(t, exp)| (t.reveal(), *exp))
    }

    /// T7.08: keep a token minted under `key` until `exp` (unix seconds).
    pub fn mint(&self, key: [u8; 32], token: &ZeroString, exp: u64, now: u64) {
        if let Ok(mut map) = self.minted.lock() {
            map.retain(|_, (_, e)| *e > now);
            map.insert(key, (SecretCell::new(token), exp));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Default)]
    struct Counting {
        resolves: AtomicU64,
        generation: AtomicU64,
    }
    impl Resolve for Arc<Counting> {
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            self.resolves.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            Ok((
                ZeroString::from_string("secret-value".into()),
                Inject::Bearer,
            ))
        }
        fn generation(&self) -> Result<u64, String> {
            Ok(self.generation.load(Ordering::SeqCst))
        }
    }

    #[test]
    fn caches_then_refetches_after_ttl() {
        let n = Arc::new(Counting::default());
        let c = Cache::new(Box::new(n.clone()), Duration::from_secs(60));
        c.get("A", "h.example.com", 443).unwrap();
        c.get("A", "h.example.com", 443).unwrap();
        assert_eq!(n.resolves.load(Ordering::SeqCst), 1);
        let c0 = Cache::new(Box::new(n.clone()), Duration::ZERO);
        c0.get("A", "h.example.com", 443).unwrap();
        c0.get("A", "h.example.com", 443).unwrap();
        assert_eq!(n.resolves.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn generation_change_drops_cache() {
        let n = Arc::new(Counting::default());
        let c = Cache::new(Box::new(n.clone()), DEFAULT_TTL);
        c.get("A", "h.example.com", 443).unwrap();
        n.generation.store(5, Ordering::SeqCst); // e.g. `kepr agent revoke`
                                                 // Within the check interval the cached value may still serve...
        c.get("A", "h.example.com", 443).unwrap();
        assert_eq!(n.resolves.load(Ordering::SeqCst), 1);
        // ...and once it has passed, the change drops the cache.
        std::thread::sleep(Duration::from_millis(300));
        c.get("A", "h.example.com", 443).unwrap();
        assert_eq!(n.resolves.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_misses_resolve_once() {
        let n = Arc::new(Counting::default());
        let c = Arc::new(Cache::new(Box::new(n.clone()), DEFAULT_TTL));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let c = c.clone();
                std::thread::spawn(move || c.get("A", "h.example.com", 443).unwrap())
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(n.resolves.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn values_and_clear() {
        let c = Cache::new(Box::new(Arc::new(Counting::default())), DEFAULT_TTL);
        c.get("A", "h.example.com", 443).unwrap();
        assert_eq!(c.values().len(), 1);
        c.clear();
        assert!(c.values().is_empty());
    }

    #[test]
    fn cached_values_and_tokens_live_in_secret_cells() {
        let c = Cache::new(Box::new(Arc::new(Counting::default())), DEFAULT_TTL);
        c.get("A", "h.example.com", 443).unwrap();
        c.mint([1; 32], &ZeroString::from("ghs_minted-token-1"), 100, 0);
        let secret = kepr_core::secmem::memfd_secret_available();
        let e = c.entries.lock().unwrap();
        assert!(e
            .values()
            .all(|(cell, _, _)| cell.is_secret_backed() == secret));
        drop(e);
        let m = c.minted.lock().unwrap();
        assert!(m
            .values()
            .all(|(cell, _)| cell.is_secret_backed() == secret));
        drop(m);
        assert_eq!(c.values()[0].1.as_str(), "secret-value");
        assert_eq!(c.minted(&[1; 32]).unwrap().0.as_str(), "ghs_minted-token-1");
        let (v, _) = c.get("A", "h.example.com", 443).unwrap();
        assert_eq!(v.as_str(), "secret-value", "a hit reveals the cell");
    }

    #[test]
    fn a_generation_change_empties_values_and_tokens() {
        let n = Arc::new(Counting::default());
        let c = Cache::new(Box::new(n.clone()), DEFAULT_TTL);
        c.get("A", "h.example.com", 443).unwrap();
        c.mint([1; 32], &ZeroString::from("ghs_minted-token-1"), 100, 0);
        c.check_generation().unwrap();
        assert_eq!(c.values().len(), 1);
        n.generation.store(7, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(300));
        c.check_generation().unwrap();
        assert!(c.values().is_empty());
        assert!(c.minted(&[1; 32]).is_none());
    }

    struct Record(&'static str);
    impl Resolve for Record {
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            Ok((ZeroString::from(self.0), Inject::Postgres))
        }
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
    }

    #[test]
    fn needles_of_a_database_record_are_its_password_not_user_or_database() {
        let rec =
            r#"{"user":"app-user-long","password":"s3cret-PW-only","database":"main-database"}"#;
        let c = Cache::new(Box::new(Record(rec)), DEFAULT_TTL);
        c.get("DB", "db.example.com", 5432).unwrap();
        let got: Vec<String> = c.needles().iter().map(|z| z.to_owned_string()).collect();
        // The password and its Base64 spellings; never the user or database.
        assert!(got.contains(&"s3cret-PW-only".to_string()));
        assert!(!got
            .iter()
            .any(|g| g.contains("app-user") || g.contains("main-")));
        assert_eq!(got.len(), 3, "{got:?}");
    }

    #[test]
    fn needles_cover_minted_tokens_and_skip_short_values() {
        let c = Cache::new(Box::new(Record("short")), DEFAULT_TTL);
        c.get("A", "h.example.com", 443).unwrap();
        assert!(c.needles().is_empty(), "under MIN_SECRET_LEN");
        c.mint([1; 32], &ZeroString::from("ghs_minted-token-1"), 100, 0);
        let got: Vec<String> = c.needles().iter().map(|z| z.to_owned_string()).collect();
        assert!(got.contains(&"ghs_minted-token-1".to_string()));
        assert_eq!(got.len(), 2, "the token and its Base64 form: {got:?}");
    }

    #[test]
    fn stale_replies_are_skipped_by_id() {
        let (gate_end, mut daemon_end) = UnixStream::pair().unwrap();
        let r = FdResolver {
            stream: Mutex::new(gate_end),
            next_id: AtomicU64::new(10),
        };
        let t = std::thread::spawn(move || {
            let _ = read_frame(&mut daemon_end, MAX_MSG_BYTES).unwrap();
            // A late reply for an older request (id 9), then the real one.
            for (id, v) in [(9, "WRONG"), (10, "right")] {
                let resp = GateResponse::ResolveOk {
                    id,
                    value: ZeroString::from_string(v.into()),
                    inject: Inject::Bearer,
                };
                write_frame(&mut daemon_end, &serde_json::to_vec(&resp).unwrap()).unwrap();
            }
        });
        let (v, _) = r.resolve("A", "h.example.com", 443).unwrap();
        assert_eq!(v.as_str(), "right");
        t.join().unwrap();
    }
}
