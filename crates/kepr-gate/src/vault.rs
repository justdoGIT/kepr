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
use kepr_core::gate_journal::{DecisionRecord, JournalEntry, ResultRecord};
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
    fn decision(&self, _record: DecisionRecord) -> Result<(), String> {
        Err("decision journal is not available".into())
    }
    fn result(&self, _record: ResultRecord) -> Result<(), String> {
        Err("decision journal is not available".into())
    }
    /// T9.06: add to today's usage of `name`; today's (requests, tokens).
    fn day_usage(&self, _name: &str, _requests: u64, _tokens: u64) -> Result<(u64, u64), String> {
        Err("daily usage is not available".into())
    }
    /// T9.08: is one of these fingerprints a planted canary?
    fn canary(&self, _fingerprints: Vec<String>) -> Result<bool, String> {
        Ok(false)
    }
    /// T13.03: store `value` as the new value of the credential this
    /// `rotate:` session rotates (the daemon refuses any other session).
    fn rotate_commit(&self, _name: &str, _value: &ZeroString) -> Result<(), String> {
        Err("rotation is not available".into())
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
        // SAFETY: fd 3 is the daemon channel, checked open at start and taken over once.
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
    fn acknowledged(&self, make: impl FnOnce(u64) -> GateRequest) -> Result<(), String> {
        match self.call(make)? {
            GateResponse::DecisionRecorded { .. } | GateResponse::ResultRecorded { .. } => Ok(()),
            GateResponse::Err { error, .. } => Err(error),
            _ => Err("daemon channel: unexpected reply".into()),
        }
    }
}
#[path = "vault_resolver.rs"]
mod vault_resolver;

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
    durable_decisions: bool,
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
            durable_decisions: false,
        }
    }
    pub fn with_durable_decisions(mut self) -> Self {
        self.durable_decisions = true;
        self
    }

    fn cached(&self, key: &Key) -> Option<(ZeroString, Inject)> {
        let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
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
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, (SecretCell::new(&v), i.clone(), Instant::now()));
        Ok((v, i))
    }

    /// Every resolved value and minted token in this session for outbound
    /// screening. Poisoned HashMaps remain structurally valid; recover their
    /// guards rather than silently losing the screening set.
    pub fn values(&self) -> Vec<(String, ZeroString)> {
        let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<_> = map
            .iter()
            .map(|((n, _, _), (v, _, _))| (n.clone(), v.reveal()))
            .collect();
        drop(map);
        let tokens = self.minted.lock().unwrap_or_else(|e| e.into_inner());
        out.extend(
            tokens
                .values()
                .map(|(v, _)| ("derived session token".into(), v.reveal())),
        );
        out
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
    fn persist(&self, f: impl FnOnce(&dyn Resolve) -> Result<(), String>) -> Result<(), String> {
        if self.durable_decisions {
            f(&*self.resolver)
        } else {
            Ok(())
        }
    }

    pub fn decision(&self, record: DecisionRecord) -> Result<(), String> {
        self.persist(|resolver| resolver.decision(record))
    }

    pub fn result(&self, record: ResultRecord) -> Result<(), String> {
        self.persist(|resolver| resolver.result(record))
    }

    /// T9.08: ask the daemon about canary fingerprints (not cached).
    pub fn canary(&self, fingerprints: Vec<String>) -> Result<bool, String> {
        self.resolver.canary(fingerprints)
    }

    /// T9.06: report usage of `name` to the daemon (not cached).
    pub fn day_usage(&self, name: &str, requests: u64, tokens: u64) -> Result<(u64, u64), String> {
        self.resolver.day_usage(name, requests, tokens)
    }

    /// Replace a sealed credential through the daemon and discard every
    /// cached copy, including the pre-cutover value.
    pub fn rotate_commit(&self, name: &str, value: &ZeroString) -> Result<(), String> {
        self.resolver.rotate_commit(name, value)?;
        self.clear();
        Ok(())
    }

    /// Drop every value and token; a cell zeroizes and unmaps its region
    /// on drop. A poisoned lock is cleared all the same.
    pub fn clear(&self) {
        (self.entries.lock().unwrap_or_else(|e| e.into_inner())).clear();
        (self.minted.lock().unwrap_or_else(|e| e.into_inner())).clear();
    }

    /// T7.08: a token minted under `key`, with its expiry.
    pub fn minted(&self, key: &[u8; 32]) -> Option<(ZeroString, u64)> {
        let map = self.minted.lock().unwrap_or_else(|e| e.into_inner());
        map.get(key).map(|(t, exp)| (t.reveal(), *exp))
    }

    /// T7.08: keep a token minted under `key` until `exp` (unix seconds).
    pub fn mint(&self, key: [u8; 32], token: &ZeroString, exp: u64, now: u64) {
        let mut map = self.minted.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (_, e)| *e > now);
        map.insert(key, (SecretCell::new(token), exp));
    }
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
