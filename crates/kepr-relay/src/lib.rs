//! kepr-relay (T6.04): a tiny optional HTTP server for one-time share
//! links. It stores opaque blobs that are already encrypted; the key of a
//! link lives only in the link's `#fragment`, which never reaches it.
//!
//! ```text
//! PUT  /b/<id>   body = blob (≤ 1 MiB), X-Kepr-Ttl: seconds → 201 | 409 | 413 | 507
//! GET  /b/<id>   fetch-and-delete → 200 blob | 410 already fetched | 404
//! HEAD /b/<id>   200 waiting | 410 fetched | 404 unknown or expired
//! ```
//!
//! Blobs live in memory only and go at first fetch or expiry. Each client
//! address gets a request budget per minute. Run it behind a TLS proxy
//! when it is reachable from other machines.

pub mod http;
pub mod limit;
pub mod store;

use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use limit::RateLimit;
use store::{Limits, Put, Status, Store};

const DEFAULT_TTL: u64 = 24 * 3600;
const MAX_CONNECTIONS: usize = 64;
/// The whole request must arrive within this, however slowly it is sent.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Relay {
    store: Mutex<Store>,
    rate: Mutex<RateLimit>,
    pub limits: Limits,
    active: AtomicUsize,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A reply: status, body, and whether to send the body (not for HEAD).
pub struct Reply(pub u16, pub Vec<u8>, pub bool);

fn text(status: u16, msg: &str) -> Reply {
    Reply(status, msg.as_bytes().to_vec(), true)
}

impl Relay {
    pub fn new(limits: Limits, per_minute: u32) -> Self {
        Self {
            store: Mutex::new(Store::default()),
            rate: Mutex::new(RateLimit::new(per_minute)),
            limits,
            active: AtomicUsize::new(0),
        }
    }

    /// Route one parsed request from `ip`.
    pub fn handle(&self, req: http::Request, ip: IpAddr, now: u64) -> Reply {
        if !self
            .rate
            .lock()
            .map(|mut r| r.allow(ip, now))
            .unwrap_or(false)
        {
            return text(429, "slow down");
        }
        let Some(id) = req
            .path
            .strip_prefix("/b/")
            .filter(|id| store::valid_id(id))
        else {
            return text(404, "not found");
        };
        let Ok(mut s) = self.store.lock() else {
            return text(503, "unavailable");
        };
        match req.method.as_str() {
            "PUT" => {
                let ttl = req.ttl.unwrap_or(DEFAULT_TTL);
                match s.put(id, req.body, ttl, now, &self.limits) {
                    Put::Stored => text(201, "stored"),
                    Put::Exists => text(409, "this id is taken"),
                    Put::TooBig => text(413, "blob too large"),
                    Put::BadTtl => text(400, "ttl out of range"),
                    Put::Full => text(507, "relay is full"),
                }
            }
            "GET" => match s.take(id, now) {
                Some(blob) => Reply(200, blob, true),
                None if s.status(id, now) == Status::Opened => text(410, "already opened"),
                None => text(404, "not found"),
            },
            "HEAD" => match s.status(id, now) {
                Status::Present => Reply(200, Vec::new(), false),
                Status::Opened => Reply(410, Vec::new(), false),
                Status::Unknown => Reply(404, Vec::new(), false),
            },
            _ => text(405, "method not allowed"),
        }
    }

    fn connection(&self, stream: TcpStream) {
        let ip = match stream.peer_addr() {
            Ok(a) => a.ip(),
            Err(_) => return,
        };
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let reply = match http::read_request(
            http::Deadline::new(&stream, REQUEST_DEADLINE),
            self.limits.max_blob,
        ) {
            Ok(req) => self.handle(req, ip, now()),
            Err((status, msg)) => text(status, msg),
        };
        http::respond(&stream, reply.0, &reply.1, !reply.2);
    }
}

/// Serve forever: one thread per connection, at most 64 at a time.
pub fn serve(listener: TcpListener, relay: Arc<Relay>) {
    for stream in listener.incoming().flatten() {
        if relay.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            relay.active.fetch_sub(1, Ordering::SeqCst);
            http::respond(&stream, 503, b"busy", false);
            continue;
        }
        let r = Arc::clone(&relay);
        let spawned = std::thread::Builder::new()
            .name("kepr-relay-conn".into())
            .spawn(move || {
                r.connection(stream);
                r.active.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            relay.active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Start a relay on `addr` in a background thread; returns its address.
/// For tests and embedding.
pub fn spawn(addr: &str, relay: Relay) -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    let relay = Arc::new(relay);
    std::thread::Builder::new()
        .name("kepr-relay".into())
        .spawn(move || serve(listener, relay))?;
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn call(addr: std::net::SocketAddr, raw: &[u8]) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(raw).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn put_then_fetch_once_over_tcp() {
        let addr = spawn("127.0.0.1:0", Relay::new(Limits::default(), 100)).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let put = format!(
            "PUT /b/{id} HTTP/1.1\r\nHost: r\r\nContent-Length: 4\r\nX-Kepr-Ttl: 60\r\n\r\nblob"
        );
        assert!(call(addr, put.as_bytes()).starts_with("HTTP/1.1 201"));
        let head = format!("HEAD /b/{id} HTTP/1.1\r\n\r\n");
        assert!(call(addr, head.as_bytes()).starts_with("HTTP/1.1 200"));
        let get = format!("GET /b/{id} HTTP/1.1\r\n\r\n");
        let first = call(addr, get.as_bytes());
        assert!(first.starts_with("HTTP/1.1 200") && first.ends_with("\r\n\r\nblob"));
        assert!(call(addr, get.as_bytes()).starts_with("HTTP/1.1 410"));
        assert!(call(addr, head.as_bytes()).starts_with("HTTP/1.1 410"));
        assert!(call(addr, b"GET /etc/passwd HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn each_address_is_rate_limited() {
        let r = Relay::new(Limits::default(), 2);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let req = || http::Request {
            method: "HEAD".into(),
            path: "/b/0123456789abcdef".into(),
            ttl: None,
            body: vec![],
        };
        assert_eq!(r.handle(req(), ip, 0).0, 404);
        assert_eq!(r.handle(req(), ip, 1).0, 404);
        assert_eq!(r.handle(req(), ip, 2).0, 429);
    }
}
