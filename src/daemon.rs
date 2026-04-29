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
mod crypto_inproc;
mod daemon_cache;
mod daemon_handlers;
mod daemon_peer;
mod daemon_pool;
mod daemon_ratelimit;
mod daemon_socket;
mod master_key;
mod store;
mod version_state;

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
use kepr_core::framing::{read_frame, write_frame};
use kepr_core::protocol::{Request, Response, MAX_MSG_BYTES, SOCKET_PATH, TIMEOUT_SECS};

// Worker pool sizing. Connections are short-lived (1 req / 1 resp) but each
// may fork+exec the credential backend, so we want some slack over CPU count.
const POOL_WORKERS: usize = 16;
const POOL_QUEUE: usize = 64;

// Per-peer-uid rate limit. A peer that stays under ~10 ops/sec sees no
// impact; a peer that bursts past 30 outstanding requests is throttled
// per-token-deficit until the bucket refills. See daemon_ratelimit.
const RATE_LIMIT_CAPACITY: f64 = 30.0;
const RATE_LIMIT_REFILL_PER_SEC: f64 = 10.0;

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

/// Path to the daemon's sealed master key file. The systemd unit's
/// `StateDirectory=kepr` ensures `/var/lib/kepr/` exists at 0700
/// before the daemon starts, so the file lands at 0600 inside it.
const MASTER_KEY_PATH: &str = "/var/lib/kepr/master.key";

/// Path to the per-credential version-counter state. Tracks the
/// highest counter the daemon has ever stamped into a kepr_v2
/// ciphertext, so a wholesale `/etc/credstore.encrypted/` rollback
/// is detected at decrypt time.
const VERSION_STATE_PATH: &str = "/var/lib/kepr/cred-versions.json";

/// Magic prefixes written by the InProc AEAD backend. Files in
/// `/etc/credstore.encrypted/` that match the `kepr-*` prefix but do
/// not start with one of these magics are leftover from the legacy
/// systemd-creds backend and are unreadable under the new format —
/// see `sweep_legacy_credstore`.
///
/// `kepr_v1\n` is the original InProc format (Phase 0 α2a–α3 — no
/// per-cred counter). `kepr_v2\n` adds the rollback-protection
/// counter inside the AEAD plaintext. Both must be preserved on the
/// startup sweep; only files with neither magic are legacy.
const INPROC_MAGICS: &[&[u8]] = &[b"kepr_v1\n", b"kepr_v2\n"];

/// Walk `/etc/credstore.encrypted/` for `kepr-*` files and delete any
/// whose first 8 bytes are not the InProc AEAD magic. The user
/// authorised this destructive cutover at the migration policy step;
/// the alternative ("read-fallback to systemd-creds") was rejected to
/// avoid carrying two backends forever. Each deletion is logged to
/// the audit channel so post-mortem inspection has a record.
///
/// Failures (read-dir, individual unlink) are logged and the sweep
/// continues — a partial cleanup is better than aborting startup
/// because of one stuck file.
fn sweep_legacy_credstore() {
    use store::CRED_PREFIX;
    let dir = std::path::Path::new(store::CREDSTORE);
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return, // dir absent on a fresh install — nothing to do
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with(&format!("{CRED_PREFIX}-")) {
            continue;
        }
        let path = entry.path();
        // All currently-supported magics are 8 bytes (`kepr_vN\n`),
        // so a single fixed-size head buffer covers them all.
        const HEAD_LEN: usize = 8;
        let mut head = [0u8; HEAD_LEN];
        let is_legacy = match fs::File::open(&path).and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut head)
        }) {
            Ok(()) => !INPROC_MAGICS
                .iter()
                .any(|m| m.len() == HEAD_LEN && head == **m),
            // Treat unreadable / too-short files as legacy too — they
            // cannot decrypt under either backend, so removal is the
            // honest answer.
            Err(_) => true,
        };
        if is_legacy {
            match fs::remove_file(&path) {
                Ok(()) => eprintln!("[kepr-daemon] swept legacy credential: {}", name_str),
                Err(e) => eprintln!("[kepr-daemon] failed to sweep {}: {e}", name_str),
            }
        }
    }
}

fn main() {
    if effective_uid() != 0 {
        eprintln!("[kepr-daemon] must run as root");
        std::process::exit(1);
    }

    lock_memory();

    // Bootstrap the in-process AEAD backend before serving any request.
    // This is a one-shot at startup: load (or generate + seal + persist)
    // the 32-byte master key, hand it to InProcBackend, and install
    // that as `crypto::default_backend()`. The systemd-creds fork+exec
    // happens at most once here for the master key; per-credential
    // ops are pure in-process AES-256-GCM afterwards.
    let key = master_key::load_or_generate(
        std::path::Path::new(MASTER_KEY_PATH),
        &master_key::SystemdCredsSealer,
    )
    .unwrap_or_else(|e| {
        eprintln!("[kepr-daemon] cannot bootstrap master key: {e}");
        std::process::exit(1);
    });
    // Load the per-cred counter state for rollback protection. A
    // missing file is the legitimate fresh-install case; a malformed
    // file is a hard failure — we refuse to start rather than silently
    // regress to no rollback protection.
    let versions = std::sync::Arc::new(
        version_state::VersionState::load(std::path::PathBuf::from(VERSION_STATE_PATH))
            .unwrap_or_else(|e| {
                eprintln!("[kepr-daemon] cannot load version state: {e}");
                std::process::exit(1);
            }),
    );
    crypto::initialize_inproc_backend(*key, versions).unwrap_or_else(|e| {
        eprintln!("[kepr-daemon] cannot install backend: {e}");
        std::process::exit(1);
    });
    // Drop the bootstrap copy ASAP. Without this, the `Zeroizing` wrapper
    // would only run its destructor at the end of main() — which is the
    // end of the process lifetime, since the accept loop below never
    // returns under normal operation. An explicit drop zeroizes the
    // 32-byte key immediately after the backend has its own copy, which
    // shrinks the window where a coredump or memory snapshot could
    // surface plaintext key material.
    drop(key);

    // One-time sweep of any legacy systemd-creds-format credentials left
    // over from before the AEAD migration. The user explicitly opted to
    // delete these on cutover (no in-place re-encryption), so log the
    // names and remove the files. Idempotent: on second start the sweep
    // finds nothing because every file the daemon writes now starts with
    // the kepr_v1 magic.
    sweep_legacy_credstore();

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
        // Reply immediately and return the worker to the pool. An earlier
        // version slept here for a small jitter to deter timing-based
        // fingerprinting of the bucket capacity, but the sleep happens
        // inside a bounded worker (POOL_WORKERS = 16): a peer hammering
        // the limit could keep ~16 workers parked in this branch and
        // saturate the pool from the reject path alone, defeating the
        // limiter's whole point. The bucket already throttles throughput;
        // the public capacity is documented, so jitter buys nothing real.
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
