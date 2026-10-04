//! Sealed-value resolution over the daemon's private channel (T1.09).
//!
//! The daemon spawns the gate with one end of a socket pair on fd 3.
//! That is the only place values come from: the gate never connects to
//! the public daemon socket.

use std::collections::HashMap;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use kepr_core::binding::Inject;
use kepr_core::framing::{read_frame, write_frame};
use kepr_core::gate_protocol::{GateRequest, GateResponse};
use kepr_core::generate::ZeroString;
use kepr_core::protocol::MAX_MSG_BYTES;

pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

pub trait Resolve: Send + Sync {
    fn resolve(&self, name: &str, host: &str, port: u16) -> Result<(ZeroString, Inject), String>;
}

pub struct FdResolver {
    stream: Mutex<UnixStream>,
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
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("daemon channel: {e}"))?;
        Ok(Self {
            stream: Mutex::new(stream),
        })
    }
}

impl Resolve for FdResolver {
    fn resolve(&self, name: &str, host: &str, port: u16) -> Result<(ZeroString, Inject), String> {
        let req = GateRequest::Resolve {
            name: name.to_string(),
            host: host.to_string(),
            port,
        };
        let payload = serde_json::to_vec(&req).map_err(|e| format!("encode: {e}"))?;
        let mut s = self.stream.lock().map_err(|_| "daemon channel poisoned")?;
        write_frame(&mut *s, &payload).map_err(|e| format!("daemon channel: {e}"))?;
        let raw = zeroize::Zeroizing::new(
            read_frame(&mut *s, MAX_MSG_BYTES).map_err(|e| format!("daemon channel: {e}"))?,
        );
        match serde_json::from_slice::<GateResponse>(&raw) {
            Ok(GateResponse::ResolveOk { value, inject }) => Ok((value, inject)),
            Ok(GateResponse::Err { error }) => Err(error),
            Err(_) => Err("daemon channel: malformed response".to_string()),
        }
    }
}

type Key = (String, String, u16);

pub struct Cache {
    resolver: Box<dyn Resolve>,
    ttl: Duration,
    entries: Mutex<HashMap<Key, (ZeroString, Inject, Instant)>>,
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
        }
    }

    pub fn get(&self, name: &str, host: &str, port: u16) -> Result<(ZeroString, Inject), String> {
        let key = (name.to_string(), host.to_string(), port);
        if let Ok(map) = self.entries.lock() {
            if let Some((v, i, at)) = map.get(&key) {
                if at.elapsed() < self.ttl {
                    return Ok((dup(v), i.clone()));
                }
            }
        }
        // Resolve without holding the lock: it is blocking IO.
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct Counting(Arc<AtomicUsize>);
    impl Resolve for Counting {
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok((
                ZeroString::from_string("secret-value".into()),
                Inject::Bearer,
            ))
        }
    }

    #[test]
    fn caches_then_refetches_after_ttl() {
        let n = Arc::new(AtomicUsize::new(0));
        let c = Cache::new(Box::new(Counting(n.clone())), Duration::from_secs(60));
        c.get("A", "h.example.com", 443).unwrap();
        c.get("A", "h.example.com", 443).unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 1);
        let c0 = Cache::new(Box::new(Counting(n.clone())), Duration::ZERO);
        c0.get("A", "h.example.com", 443).unwrap();
        c0.get("A", "h.example.com", 443).unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn values_and_clear() {
        let c = Cache::new(Box::new(Counting(Arc::default())), DEFAULT_TTL);
        c.get("A", "h.example.com", 443).unwrap();
        assert_eq!(c.values().len(), 1);
        c.clear();
        assert!(c.values().is_empty());
    }
}
