#![allow(unused_unsafe)]

// daemon.rs — kepr-daemon entry, accept loop, and request dispatcher.
//
// Root systemd service. Owns all encryption/decryption operations and audit
// logging. Per-connection: read peer uid via SO_PEERCRED, parse framed JSON,
// dispatch, emit framed JSON response. Connections are handled by a bounded
// worker pool so a flood can't spawn unbounded threads.

mod audit;
mod audit_chain;
mod crypto;
mod crypto_inproc;
mod daemon_audit;
mod daemon_cache;
mod daemon_dispatch;
mod daemon_expiry;
mod daemon_handlers;
mod daemon_handlers_get;
mod daemon_lock;
mod daemon_peer;
mod daemon_polkit;
mod daemon_pool;
mod daemon_ratelimit;
mod daemon_singleton;
mod daemon_socket;
mod expiry;
mod fido2;
mod key_unlock;
mod master_key;
mod store;
mod version_state;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::OnceLock;

use daemon_dispatch::handle_client;
use daemon_pool::Pool;
use daemon_ratelimit::RateLimiter;
use daemon_socket::{
    effective_uid, set_socket_permissions, setup_socket_dir, tighten_umask_for_socket,
};

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
// Lock pages already allocated for the daemon. MCL_FUTURE is deliberately
// excluded: under the common 8 MiB RLIMIT_MEMLOCK it can succeed initially,
// then make pthread_create fail with EAGAIN when the worker pool allocates its
// stacks. Individual secret buffers are zeroized; failure here remains a
// warning because unprivileged user-mode daemons cannot raise this limit.

const MCL_CURRENT: i32 = 1;
extern "C" {
    fn mlockall(flags: i32) -> i32;
}

fn lock_memory() {
    let ret = unsafe { mlockall(MCL_CURRENT) };
    if ret != 0 {
        eprintln!("[kepr-daemon] warning: mlockall failed — secrets may be swappable");
    }
}

/// Disable core dumps and ptrace attachment for this process.
///
/// SAFETY: `PR_SET_DUMPABLE` takes a single integer argument (0 = not
/// dumpable); the remaining `prctl(2)` varargs are ignored for this
/// option. No pointer or lifetime hazard — this only flips a per-process
/// kernel flag. Without this, decrypted secrets, the master key, and
/// Argon2id working memory can land in a systemd-coredump or be read via
/// ptrace by a process that gains the right capability.
fn disable_core_dumps() {
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if ret != 0 {
        eprintln!(
            "[kepr-daemon] warning: prctl(PR_SET_DUMPABLE) failed — core dumps may leak secrets"
        );
    }
}

fn user_mode() -> bool {
    std::env::var_os("KEPR_USER_MODE").is_some() || effective_uid() != 0
}

fn state_dir() -> std::path::PathBuf {
    if user_mode() {
        std::env::var_os("XDG_STATE_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                    .join(".local/state")
            })
            .join("kepr")
    } else {
        std::path::PathBuf::from("/var/lib/kepr")
    }
}

fn master_key_path() -> std::path::PathBuf {
    state_dir().join("master.key")
}

fn protected_master_key_path() -> std::path::PathBuf {
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
    lock_memory();
    disable_core_dumps();

    let user = std::env::args().any(|arg| arg == "--user") || effective_uid() != 0;
    if user {
        std::env::set_var("KEPR_USER_MODE", "1");
    } else {
        std::env::set_var("KEPR_SYSTEM_MODE", "1");
    }

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
    let sealer: Box<dyn master_key::Sealer> = if user {
        Box::new(master_key::LocalFileSealer)
    } else {
        Box::new(master_key::SystemdCredsSealer)
    };
    let password_protected = protected_master_key_path().exists();
    let key = if password_protected {
        None
    } else {
        Some(
            master_key::load_or_generate(&master_key_path(), sealer.as_ref()).unwrap_or_else(|e| {
                eprintln!("[kepr-daemon] cannot bootstrap master key: {e}");
                std::process::exit(1);
            }),
        )
    };
    let versions = std::sync::Arc::new(
        version_state::VersionState::load(version_state_path()).unwrap_or_else(|e| {
            eprintln!("[kepr-daemon] cannot load version state: {e}");
            std::process::exit(1);
        }),
    );
    let versions_for_sweeper = std::sync::Arc::clone(&versions);
    crypto::initialize_inproc_backend(key.as_ref().map(|key| **key).unwrap_or([0u8; 32]), versions)
        .unwrap_or_else(|e| {
            eprintln!("[kepr-daemon] cannot install backend: {e}");
            std::process::exit(1);
        });
    if password_protected {
        crypto::lock_backend().unwrap_or_else(|e| {
            eprintln!("[kepr-daemon] cannot lock protected backend: {e}");
            std::process::exit(1);
        });
        eprintln!("[kepr-daemon] credential store is locked; run `kepr unlock`");
    }
    drop(key);

    sweep_legacy_credstore();
    daemon_expiry::spawn_sweeper(versions_for_sweeper);

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

