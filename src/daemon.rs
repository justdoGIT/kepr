#![allow(unused_unsafe)]
#![allow(dead_code)]

// daemon.rs — kepr-daemon entry, accept loop, and request dispatcher.
//
// Root systemd service. Owns all encryption/decryption operations and audit
// logging. Per-connection: read peer uid via SO_PEERCRED, parse framed JSON,
// dispatch, emit framed JSON response. Connections are handled by a bounded
// worker pool so a flood can't spawn unbounded threads.

mod audit;
mod crypto;
mod daemon_cache;
mod daemon_handlers;
mod daemon_peer;
mod daemon_pool;
mod daemon_ratelimit;
mod daemon_socket;
mod framing;
mod generate;
mod protocol;
mod store;

use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::OnceLock;

use audit::{username_for_uid, AuditEvent, AuditResult};
use daemon_handlers::{handle_check, handle_delete, handle_get, handle_list, handle_set};
use daemon_peer::get_peer_uid;
use daemon_pool::Pool;
use daemon_ratelimit::RateLimiter;
use daemon_socket::{
    effective_uid, set_socket_permissions, setup_socket_dir, tighten_umask_for_socket,
};
use framing::{read_frame, write_frame};
use protocol::{Request, Response, MAX_MSG_BYTES, SOCKET_PATH, TIMEOUT_SECS};

// Worker pool sizing. Connections are short-lived (1 req / 1 resp) but each
// may fork+exec the credential backend, so we want some slack over CPU count.
const POOL_WORKERS: usize = 16;
const POOL_QUEUE: usize = 64;

// Per-peer-uid rate limit. A peer that stays under ~10 ops/sec sees no
// impact; a peer that bursts past 30 outstanding requests is throttled
// per-token-deficit until the bucket refills. See daemon_ratelimit.
const RATE_LIMIT_CAPACITY: f64 = 30.0;
const RATE_LIMIT_REFILL_PER_SEC: f64 = 10.0;
const RATE_LIMIT_REJECT_JITTER_MS: u64 = 20;

static RATE_LIMITER: OnceLock<RateLimiter> = OnceLock::new();

fn rate_limiter() -> &'static RateLimiter {
    RATE_LIMITER.get_or_init(|| RateLimiter::new(RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_PER_SEC))
}

// ── mlockall ─────────────────────────────────────────────────────────────────
// Lock current and future allocations into RAM so decrypted secret bytes
// never land on swap. Daemon runs as root, so RLIMIT_MEMLOCK is typically
// unlimited; soft-fail with a warning if it isn't available.

const MCL_CURRENT: i32 = 1;
const MCL_FUTURE: i32 = 2;
extern "C" {
    fn mlockall(flags: i32) -> i32;
}

fn lock_memory() {
    let ret = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
    if ret != 0 {
        eprintln!("[kepr-daemon] warning: mlockall failed — secrets may be swappable");
    }
}

fn main() {
    if effective_uid() != 0 {
        eprintln!("[kepr-daemon] must run as root");
        std::process::exit(1);
    }

    lock_memory();
    setup_socket_dir();
    let _ = fs::remove_file(SOCKET_PATH);

    // Must precede `bind`: socket inode mode is `0666 & ~umask` at creation
    // time, so without this the post-bind `chmod` is racy on any host that
    // overrides the systemd default umask.
    tighten_umask_for_socket();

    let listener = UnixListener::bind(SOCKET_PATH).expect("cannot bind socket");
    set_socket_permissions();

    let pool = Pool::new(POOL_WORKERS, POOL_QUEUE, handle_client);

    eprintln!("[kepr-daemon] listening on {SOCKET_PATH} (workers={POOL_WORKERS})");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => pool.dispatch(stream),
            Err(e) => eprintln!("[kepr-daemon] accept error: {e}"),
        }
    }
}

fn handle_client(mut stream: UnixStream) {
    let timeout = std::time::Duration::from_secs(TIMEOUT_SECS);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let peer_uid = match get_peer_uid(&stream) {
        Some(uid) => uid,
        None => {
            send_error(&mut stream, "cannot verify caller identity");
            return;
        }
    };

    if !rate_limiter().check(peer_uid) {
        // Brief jitter before responding so a hostile peer cannot spin a
        // tight loop probing the limit boundary; the bucket already throttles
        // throughput, the sleep deters timing-based fingerprinting.
        std::thread::sleep(std::time::Duration::from_millis(
            RATE_LIMIT_REJECT_JITTER_MS,
        ));
        send_error(&mut stream, "rate limited");
        return;
    }

    let buf = match read_frame(&mut stream, MAX_MSG_BYTES) {
        Ok(b) => b,
        Err(_) => return,
    };

    let request: Request = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            send_error(&mut stream, &format!("invalid request: {e}"));
            return;
        }
    };

    let username = username_for_uid(peer_uid);
    let response = dispatch(peer_uid, &username, request);
    send_response(&mut stream, &response);
}

fn dispatch(uid: u32, username: &str, request: Request) -> Response {
    match request {
        Request::Ping => {
            audit::log(&AuditEvent {
                op: "ping",
                name: None,
                uid,
                username,
                result: AuditResult::Ok,
            });
            Response::Pong
        }
        Request::Set {
            name,
            value,
            generate,
        } => handle_set(uid, username, &name, value.as_deref(), generate.as_deref()),
        Request::Get { name } => handle_get(uid, username, &name),
        Request::List => handle_list(uid, username),
        Request::Delete { name } => handle_delete(uid, username, &name),
        Request::Check => handle_check(uid, username),
    }
}

fn send_response(stream: &mut UnixStream, resp: &Response) {
    if let Ok(json) = serde_json::to_vec(resp) {
        let _ = write_frame(stream, &json);
    }
}

fn send_error(stream: &mut UnixStream, msg: &str) {
    send_response(stream, &Response::fail(msg));
}
