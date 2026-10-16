#![allow(unused_unsafe)]

// daemon.rs — kepr-daemon entry, accept loop, and request dispatcher.
//
// Root systemd service. Owns all encryption/decryption operations and audit
// logging. Per-connection: read peer uid via SO_PEERCRED, parse framed JSON,
// dispatch, emit framed JSON response. Connections are handled by a bounded
// worker pool so a flood can't spawn unbounded threads.

mod atomic_file;
mod audit;
mod audit_chain;
mod cred_meta;
mod crypto;
mod crypto_inproc;
mod daemon_audit;
mod daemon_cache;
mod daemon_credlock;
mod daemon_dispatch;
mod daemon_expiry;
mod daemon_extra;
mod daemon_gate;
mod daemon_gate_deadline;
mod daemon_gate_registry;
mod daemon_gate_service;
mod daemon_handlers;
mod daemon_handlers_get;
mod daemon_handlers_list;
mod daemon_health;
mod daemon_history;
mod daemon_lock;
mod daemon_memlock;
mod daemon_peer;
mod daemon_polkit;
mod daemon_pool;
mod daemon_ratelimit;
mod daemon_records;
mod daemon_recovery;
mod daemon_share;
mod daemon_share_seen;
mod daemon_singleton;
mod daemon_sleepwatch;
mod daemon_socket;
mod daemon_ssh;
mod daemon_usage;
mod expiry;
mod fido2;
mod key_unlock;
mod master_key;
mod store;
mod version_state;

// ── P2–P11 ticket batches (2026-10-05): one directory module per batch,
// declared under its own marker so parallel branches merge cleanly.
// batch: vault
mod daemon_vault;
// batch: seal
mod daemon_seal;
// batch: store
mod daemon_store;
// batch: records
mod daemon_recordsx;
// batch: share
mod daemon_sharing;
// batch: sync
mod daemon_syncx;
// batch: policy
mod daemon_policy;
// batch: gate
mod daemon_gatex;
// batch: aws
mod daemon_aws;
// batch: eco
mod daemon_eco;
// batch: platform
mod daemon_platform;
// batch: session
mod daemon_session;
// end of batches

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::OnceLock;

use audit::username_for_uid;
use daemon_peer::get_peer_creds;
use daemon_pool::Pool;
use daemon_ratelimit::RateLimiter;
use daemon_socket::{
    effective_uid, private_umask_after_bind, set_socket_permissions, setup_socket_dir,
    tighten_umask_for_socket,
};
use kepr_core::framing::{read_frame, write_frame};
use kepr_core::protocol::{Request, Response, MAX_MSG_BYTES, TIMEOUT_SECS};

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

fn user_mode() -> bool {
    std::env::var_os("KEPR_USER_MODE").is_some() || effective_uid() != 0
}

fn state_dir() -> std::path::PathBuf {
    if user_mode() {
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                    .join(".local/state")
            });
        kepr_core::profile::nest(base.join("kepr")) // T11.16
    } else {
        std::path::PathBuf::from("/var/lib/kepr")
    }
}

pub(crate) fn master_key_path() -> std::path::PathBuf {
    state_dir().join("master.key")
}

pub(crate) fn protected_master_key_path() -> std::path::PathBuf {
    state_dir().join("master.key.argon2id")
}

fn version_state_path() -> std::path::PathBuf {
    state_dir().join("cred-versions.json")
}

fn audit_chain_path() -> std::path::PathBuf {
    state_dir().join("audit.log")
}

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
    let dir = store::store_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return, // dir absent on a fresh install — nothing to do
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with(&format!("{CRED_PREFIX}-")) {
            continue;
        }
        // Sidecar metadata (`*.meta`) and in-flight temp files (`*.tmp*`)
        // are not credential ciphertext and never carry the InProc magic
        // header. Sweeping them on every restart silently strips TTL,
        // consent, and FIDO2 policy gates — `precheck_meta` allows a read
        // when the sidecar is missing (fail-open), so this used to turn
        // every daemon restart into a policy bypass. Skip them so the
        // legacy-format sweep only ever touches actual credential files.
        if name_str.ends_with(".meta") || name_str.contains(".tmp") {
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
    daemon_memlock::lock_memory();
    daemon_memlock::disable_core_dumps();

    let user = std::env::args().any(|arg| arg == "--user") || effective_uid() != 0;
    if user {
        std::env::set_var("KEPR_USER_MODE", "1");
    } else {
        std::env::set_var("KEPR_SYSTEM_MODE", "1");
    }
    daemon_session::check_profile_or_exit(); // T11.16

    fs::create_dir_all(state_dir()).unwrap_or_else(|e| {
        eprintln!("[kepr-daemon] cannot create state directory: {e}");
        std::process::exit(1);
    });
    fs::set_permissions(state_dir(), std::fs::Permissions::from_mode(0o700)).unwrap_or_else(|e| {
        eprintln!("[kepr-daemon] cannot secure state directory: {e}");
        std::process::exit(1);
    });
    // Refuse to start a second instance against the same state
    // directory. See `daemon_singleton::acquire_singleton_lock` —
    // concurrent daemons corrupted the audit chain by racing on the
    // same `next_seq`.
    let _daemon_lock_guard = daemon_singleton::acquire_singleton_lock(&state_dir());
    fs::create_dir_all(crate::store::store_dir()).unwrap_or_else(|e| {
        eprintln!("[kepr-daemon] cannot create credential directory: {e}");
        std::process::exit(1);
    });
    // 0700 in both modes: the daemon is the sole reader/writer of
    // ciphertext files (system mode runs as root; user mode runs as the
    // owning uid). Other kepr-group members reach their own credentials
    // only through the socket, never by listing this directory, so the
    // previous group-readable 0755 in system mode only ever leaked
    // credential names, per-uid policy flags, and value lengths (file
    // size) to every local user.
    fs::set_permissions(
        crate::store::store_dir(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap_or_else(|e| {
        eprintln!("[kepr-daemon] cannot secure credential directory: {e}");
        std::process::exit(1);
    });
    let versions = std::sync::Arc::new(
        version_state::VersionState::load(version_state_path()).unwrap_or_else(|e| {
            eprintln!("[kepr-daemon] cannot load version state: {e}");
            std::process::exit(1);
        }),
    );
    let versions_for_sweeper = std::sync::Arc::clone(&versions);
    // The master key (T12.32: or locked, for `kepr recovery-key unlock`).
    daemon_seal::startup::start(user, versions);

    sweep_legacy_credstore();
    daemon_expiry::spawn_sweeper(versions_for_sweeper);
    daemon_policy::init(); // T6.11: policy.toml, reloaded on SIGHUP
    if user {
        daemon_sleepwatch::spawn(effective_uid());
        daemon_session::idle::spawn(effective_uid());
    }

    let chain = audit_chain::AuditChain::open(audit_chain_path()).unwrap_or_else(|e| {
        eprintln!("[kepr-daemon] cannot open audit chain: {e}");
        std::process::exit(1);
    });
    audit::install_chain(std::sync::Arc::new(chain)).unwrap_or_else(|e| {
        eprintln!("[kepr-daemon] cannot install audit chain: {e}");
        std::process::exit(1);
    });

    let socket = kepr_core::protocol::socket_path();
    setup_socket_dir();
    let _ = fs::remove_file(&socket);
    tighten_umask_for_socket();
    let listener = UnixListener::bind(&socket).expect("cannot bind socket");
    set_socket_permissions();
    private_umask_after_bind();

    let pool = Pool::new(POOL_WORKERS, POOL_QUEUE, handle_client);
    eprintln!(
        "[kepr-daemon] listening on {} (workers={POOL_WORKERS})",
        socket.display()
    );
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

    let (peer_pid, peer_uid) = match get_peer_creds(&stream) {
        Some(c) => (c.pid, c.uid),
        None => {
            send_error(&mut stream, "cannot verify caller identity");
            return;
        }
    };
    if user_mode() && peer_uid != effective_uid() {
        send_error(&mut stream, "caller is not the daemon owner");
        return;
    }
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

    // The raw frame can hold a secret (Set value, Unlock password):
    // wipe it once parsed.
    let mut whole = daemon_socket::Deadline::new(&stream, timeout);
    let buf = match read_frame(&mut whole, MAX_MSG_BYTES) {
        Ok(b) => zeroize::Zeroizing::new(b),
        Err(_) => return,
    };

    let request: Request = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            // serde's message can quote the offending value (possibly a
            // secret); report only where parsing failed.
            send_error(
                &mut stream,
                &format!("invalid request (line {}, column {})", e.line(), e.column()),
            );
            return;
        }
    };

    daemon_session::idle::touch(&request);
    let username = username_for_uid(peer_uid);
    let response = daemon_dispatch::dispatch(peer_uid, peer_pid, &username, request);
    send_response(&mut stream, &response);
    daemon_session::fetchfd::send_pending(&stream, &response); // T3.06
}

fn send_response(stream: &mut UnixStream, resp: &Response) {
    if let Ok(json) = serde_json::to_vec(resp).map(zeroize::Zeroizing::new) {
        let _ = write_frame(stream, &json);
    }
}

fn send_error(stream: &mut UnixStream, msg: &str) {
    send_response(stream, &Response::fail(msg));
}
