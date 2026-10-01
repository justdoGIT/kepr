// daemon_singleton.rs — single-instance guard for kepr-daemon.
//
// Root cause this closes: `client.rs::connect_socket()` spawns a
// fresh `kepr-daemon` on any failed connect, and `daemon.rs::main()`
// unconditionally `fs::remove_file(&socket)`s then rebinds without
// checking whether another instance is already listening. Together
// those let a second daemon silently steal the socket path out from
// under a still-running first instance — observed in practice when
// `/run/user/<uid>` gets recreated (session churn) while an earlier
// daemon process survives as an orphan. Both instances then served
// requests and independently appended to the same persistent
// `audit.log` through their own in-process `Mutex<ChainState>`
// (see `audit_chain.rs`), which has no cross-process visibility.
// Two daemons racing on the same `next_seq` produced duplicate-seq
// entries sharing one `prev_hash`, which `AuditChain::verify`
// correctly rejects on the next startup ("seq N != expected N+1"),
// refusing to start rather than silently serving from a now-
// untrusted chain. Observed in production on 2026-09-30 and again
// on 2026-10-01.
//
// Fix: before touching the socket, take an exclusive non-blocking
// `flock(2)` on a dedicated lockfile in the state directory. A
// second instance against the same state directory fails the lock
// and exits immediately instead of racing the first. `flock` is
// held for the lifetime of the returned `File` and releases
// automatically on process exit — including crash or SIGKILL — so
// there is no stale-pidfile/PID-reuse hazard a traditional
// pidfile + `kill(pid, 0)` check would have.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Acquire the exclusive daemon lock in `state_dir`, or print a
/// diagnostic and exit the process. `state_dir` must already exist
/// (the daemon creates and secures it before calling this).
pub fn acquire_singleton_lock(state_dir: &Path) -> File {
    match try_acquire(state_dir) {
        Ok(file) => file,
        Err(LockError::Open(e)) => {
            eprintln!(
                "[kepr-daemon] cannot open lock file {}: {e}",
                lock_path(state_dir).display()
            );
            std::process::exit(1);
        }
        Err(LockError::Held) => {
            eprintln!(
                "[kepr-daemon] another kepr-daemon instance already holds {} — \
                 refusing to start a second instance (concurrent daemons \
                 previously corrupted the audit chain)",
                lock_path(state_dir).display()
            );
            std::process::exit(1);
        }
    }
}

enum LockError {
    Open(std::io::Error),
    Held,
}

fn lock_path(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("daemon.lock")
}

fn try_acquire(state_dir: &Path) -> Result<File, LockError> {
    let path = lock_path(state_dir);
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(LockError::Open)?;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        return Err(LockError::Held);
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kepr-singleton-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn first_acquire_succeeds() {
        let dir = tempdir();
        let _guard = try_acquire(&dir).unwrap_or_else(|_| panic!("first lock should succeed"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn second_acquire_against_same_dir_fails_while_first_held() {
        let dir = tempdir();
        let _first = try_acquire(&dir).unwrap_or_else(|_| panic!("first lock should succeed"));
        let second = try_acquire(&dir);
        assert!(
            matches!(second, Err(LockError::Held)),
            "second acquire should fail while the first guard is alive"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lock_releases_when_guard_drops() {
        let dir = tempdir();
        {
            let _first = try_acquire(&dir).unwrap_or_else(|_| panic!("first lock should succeed"));
        } // guard dropped here -> fd closed -> flock released
        let second = try_acquire(&dir);
        assert!(
            second.is_ok(),
            "lock should be acquirable again after the holder's fd closes"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lock_file_created_at_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir();
        let _guard = try_acquire(&dir).unwrap_or_else(|_| panic!("lock should succeed"));
        let meta = fs::metadata(lock_path(&dir)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        fs::remove_dir_all(&dir).ok();
    }
}
