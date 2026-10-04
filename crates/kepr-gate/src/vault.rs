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
use kepr_core::gate_protocol::{GateRequest, GateResponse};
use kepr_core::generate::ZeroString;
use kepr_core::protocol::MAX_MSG_BYTES;

pub const DEFAULT_TTL: Duration = Duration::from_secs(300);
/// Long enough for a human to answer a polkit consent dialog.
const REPLY_TIMEOUT: Duration = Duration::from_secs(120);

pub trait Resolve: Send + Sync {
    fn resolve(&self, name: &str, host: &str, port: u16) -> Result<(ZeroString, Inject), String>;
    /// The daemon's store generation (see module docs).
    fn generation(&self) -> Result<u64, String>;
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
            GateResponse::Generation { .. } => Err("daemon channel: unexpected reply".into()),
        }
    }

    fn generation(&self) -> Result<u64, String> {
        match self.call(|id| GateRequest::Generation { id })? {
            GateResponse::Generation { generation, .. } => Ok(generation),
            GateResponse::Err { error, .. } => Err(error),
            GateResponse::ResolveOk { .. } => Err("daemon channel: unexpected reply".into()),
        }
    }
}

type Key = (String, String, u16);

pub struct Cache {
    resolver: Box<dyn Resolve>,
    ttl: Duration,
    entries: Mutex<HashMap<Key, (ZeroString, Inject, Instant)>>,
    generation: Mutex<u64>,
    /// Serialises cache misses (single-flight).
    resolving: Mutex<()>,
}

fn dup(z: &ZeroString) -> ZeroString {
    ZeroString::from_string(z.as_str().to_string())
}

impl Cache {
    pub fn new(resolver: Box<dyn Resolve>, ttl: Duration) -> Self {
        Self {
            resolver,
            ttl,
            entries: Mutex::new(HashMap::new()),
            generation: Mutex::new(0),
            resolving: Mutex::new(()),
        }
    }

    fn cached(&self, key: &Key) -> Option<(ZeroString, Inject)> {
        let map = self.entries.lock().ok()?;
        let (v, i, at) = map.get(key)?;
        (at.elapsed() < self.ttl).then(|| (dup(v), i.clone()))
    }

    /// Drop every cached value if the daemon's store changed.
    fn check_generation(&self) -> Result<(), String> {
        let now = self.resolver.generation()?;
        let mut seen = self.generation.lock().map_err(|_| "cache poisoned")?;
        if *seen != now {
            self.clear();
            *seen = now;
        }
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
            map.insert(key, (dup(&v), i.clone(), Instant::now()));
        }
        Ok((v, i))
    }

    /// `(NAME, value)` for every value this session has resolved; used
    /// by the prompt DLP check.
    pub fn values(&self) -> Vec<(String, ZeroString)> {
        match self.entries.lock() {
            Ok(map) => map
                .iter()
                .map(|((n, _, _), (v, _, _))| (n.clone(), dup(v)))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn clear(&self) {
        if let Ok(mut map) = self.entries.lock() {
            map.clear(); // ZeroString zeroizes on drop
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
