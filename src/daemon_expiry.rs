// daemon_expiry.rs — periodic TTL sweeper.
//
// Phase 2 β. Without this, expired credentials (PR #69 / Phase 2 α)
// stay on disk forever; `handle_get` refuses them, but disk usage
// grows without bound for any caller that uses `--ttl` heavily.
//
// Design:
//
//   - One background thread, daemon-lifetime. Sleeps `interval`,
//     wakes, scans /etc/credstore.encrypted/ once, sleeps again.
//     No graceful shutdown — systemd will SIGTERM the daemon when
//     the unit stops; the thread dies with the process.
//   - Each scan walks `*.meta` files, reads the JSON envelope, and
//     for any meta with `expires_at_unix < now` removes the cred,
//     the meta, AND tombstones the version-state counter so a
//     post-restore replay of the (now-deleted) ciphertext fails
//     the rollback check the same way a `kepr delete` does.
//   - All four removal steps (cred file, meta file, version
//     tombstone, daemon_cache invalidation) match the order
//     `handle_delete` uses, with one difference: the audit op is
//     "expire" not "delete" so post-mortem inspection can
//     distinguish user-driven removals from sweeper-driven ones.
//
// Threat model: the sweeper runs as root in the daemon's address
// space, so it inherits every authz invariant the daemon already
// has. There is no per-call `SO_PEERCRED` because there's no peer —
// the work is daemon-internal. The cred uid is recovered from the
// on-disk filename via `store::from_cred_name`, the same parser
// every other handler trusts.
//
// Failure semantics: a single bad meta file (malformed JSON,
// transient EIO) MUST NOT stop the rest of the sweep. Each per-cred
// step is wrapped in `match` and logs to stderr (the daemon's
// journald sink) on failure; the sweep continues. A sweeper that
// bails on the first error would leave operators with a cron-like
// "why did expiry stop running" mystery.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::audit::{self, username_for_uid, AuditEvent, AuditResult};
use crate::daemon_cache;
use crate::expiry;
use crate::store;
use crate::version_state::VersionState;

/// How often the sweeper wakes up. Default chosen to keep
/// per-credential expiry latency under a minute while remaining
/// invisible to system load: a single `read_dir` + N `read_meta`
/// every 60s is well below 1ms of CPU on any realistic credstore.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

/// Aggregate counts from a single sweep, returned for tests and
/// for the optional once-per-tick audit summary. Production callers
/// don't need the value — the per-cred audit log is the source of
/// truth — but a numeric summary makes the test surface tractable.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepStats {
    /// Number of meta files inspected this pass.
    pub seen: usize,
    /// Cred + meta pairs successfully removed.
    pub expired: usize,
    /// Errors encountered (read or remove). Sweep continues past
    /// each one; the count is informational.
    pub errors: usize,
}

/// One sweep pass over `dir`. Returns aggregate counts. Public for
/// tests; the production thread loops this with the production
/// directory and `now_unix()`.
pub fn sweep_once(dir: &Path, now: u64, versions: Option<&Arc<VersionState>>) -> SweepStats {
    let mut stats = SweepStats::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            // Missing dir is the legitimate fresh-install case.
            // Anything else is worth flagging; sweep just no-ops
            // for this tick.
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("[kepr-daemon] sweeper: read_dir({}): {e}", dir.display());
                stats.errors += 1;
            }
            return stats;
        }
    };

    for entry in entries.flatten() {
        let meta_path = entry.path();
        // Only consider `*.meta` siblings of cred files. Any other
        // entry is either a cred file (skipped here, handled via
        // its own meta), a stale tempfile, or someone else's
        // business — leave it alone.
        if meta_path.extension().and_then(|s| s.to_str()) != Some("meta") {
            continue;
        }
        stats.seen += 1;

        // Reconstruct the cred path by stripping `.meta`.
        let cred_path = strip_meta_extension(&meta_path);

        // Read the meta. None = file disappeared between read_dir
        // and read (race with handle_delete or another sweeper
        // tick); silently skip. Some(Err) = malformed; skip and
        // surface in the error count so a post-mortem can correlate.
        let meta = match expiry::read_meta(&meta_path) {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                eprintln!(
                    "[kepr-daemon] sweeper: malformed meta {}: {e}",
                    meta_path.display()
                );
                stats.errors += 1;
                continue;
            }
            None => continue,
        };

        // Phase 2 ε: meta is now multi-flag. The sweeper only
        // cares about credentials with a TTL — a consent-only
        // cred (no expires_at_unix) lives forever from the
        // sweeper's perspective. Skip if no expiry, or if the
        // expiry is still in the future.
        let expires_at = match meta.expires_at_unix {
            Some(t) => t,
            None => continue,
        };
        if expires_at > now {
            continue; // not yet expired
        }

        // Past the deadline — remove cred + meta + tombstone counter.
        // Recover (uid, name) from the cred filename so the audit
        // log carries the right uid and the version-state tombstone
        // names the right cred-name.
        let cred_basename = match cred_path.file_name().and_then(|s| s.to_str()) {
            Some(b) => b.to_string(),
            None => {
                eprintln!(
                    "[kepr-daemon] sweeper: invalid cred path {}",
                    cred_path.display()
                );
                stats.errors += 1;
                continue;
            }
        };
        let (uid, name_upper) = match store::from_cred_name(&cred_basename) {
            Some(p) => p,
            None => {
                eprintln!("[kepr-daemon] sweeper: cannot parse cred name from {cred_basename}");
                stats.errors += 1;
                continue;
            }
        };

        // Mirror what InProcBackend::delete does, but via the same
        // primitives the test harness can drive: tombstone the
        // version counter FIRST (so a post-restore replay of the
        // about-to-be-removed ciphertext fails verify), then unlink
        // the cred file. Bypassing the Backend trait keeps the
        // sweeper testable against an arbitrary directory; the
        // semantic guarantees match `handle_delete` step-for-step.
        //
        // Order matters — same reason as PR #59: if tombstone fails
        // and we'd already removed the file, an attacker with a
        // pre-delete snapshot could replay since the counter
        // wouldn't have advanced. Tombstone-first means a tombstone
        // failure leaves the file in place, the next sweep retries.
        if let Some(vs) = versions {
            if let Err(e) = vs.tombstone(&cred_basename) {
                eprintln!("[kepr-daemon] sweeper: tombstone {cred_basename}: {e}");
                stats.errors += 1;
                // Don't proceed to file delete — same fail-closed
                // ordering as handle_delete (see crypto_inproc::delete
                // and PR #59's review notes).
                continue;
            }
        }

        let cred_existed = match std::fs::remove_file(&cred_path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                eprintln!("[kepr-daemon] sweeper: remove cred {cred_basename}: {e}");
                stats.errors += 1;
                // Don't `continue` — the meta is the trigger for
                // further sweeps; remove it even if the cred
                // delete failed, so subsequent sweeps don't loop on
                // the same orphan. The audit log will record the
                // anomaly via cred_existed=false.
                false
            }
        };

        // Drop the meta file. Best-effort — a present meta with no
        // cred would just be ignored by future sweeps, but tidiness.
        expiry::delete_meta(&meta_path);

        // Invalidate the per-uid scan cache so list/check pick up
        // the removal on their next call without waiting for the
        // cache TTL.
        daemon_cache::invalidate(uid);

        // Audit. `op = "expire"` distinguishes sweeper removals
        // from user-driven `delete`s — operators triaging "where
        // did my cred go?" can differentiate at a glance.
        let username = username_for_uid(uid);
        let result = if cred_existed {
            AuditResult::Ok
        } else {
            AuditResult::Fail("cred file already missing at sweep time".to_string())
        };
        audit::log(&AuditEvent {
            op: "expire",
            name: Some(&name_upper),
            uid,
            username: &username,
            result,
        });

        stats.expired += 1;
    }
    stats
}

/// Strip the trailing `.meta` extension from a sidecar path,
/// returning the cred path. Symmetric inverse of
/// `expiry::meta_path_for`.
fn strip_meta_extension(meta_path: &Path) -> PathBuf {
    // `with_extension("")` would drop the extension cleanly when
    // there is exactly one. Since expiry::meta_path_for APPENDS
    // `.meta` to whatever was there (so `kepr-1000-foo` becomes
    // `kepr-1000-foo.meta`), `with_extension("")` is the right
    // inverse: `kepr-1000-foo.meta` → `kepr-1000-foo`.
    meta_path.with_extension("")
}

/// Spawn the sweeper thread. Daemon-lifetime; no shutdown handle.
/// `versions` is the same `Arc<VersionState>` that the daemon
/// hands to `crypto::initialize_inproc_backend`, so tombstones
/// here advance the same counter the encrypt path consults.
pub fn spawn_sweeper(versions: Arc<VersionState>) {
    spawn_sweeper_with_interval(versions, DEFAULT_INTERVAL);
}

/// Same as `spawn_sweeper` but takes an explicit interval. Used
/// by future tunable-config work; today the daemon only ever
/// passes the default. Non-public against accidental misuse.
fn spawn_sweeper_with_interval(versions: Arc<VersionState>, interval: Duration) {
    thread::Builder::new()
        .name("kepr-expiry".to_string())
        .spawn(move || loop {
            // Sleep BEFORE the first sweep so a fresh daemon
            // doesn't waste a tick on an empty store. The
            // first useful work happens at startup + interval,
            // not startup + 0.
            thread::sleep(interval);
            let now = expiry::now_unix();
            let dir = Path::new(store::CREDSTORE);
            let _ = sweep_once(dir, now, Some(&versions));
        })
        .expect("spawn kepr-expiry thread");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Plant a cred file + meta sidecar pair under `dir` and
    /// return both paths. Production code never writes these
    /// directly (the daemon goes through crypto + expiry::write_meta),
    /// but the sweeper's contract is observable from the
    /// filesystem alone, so the tests work entirely at that layer.
    fn plant(dir: &Path, uid: u32, name: &str, expires_at_unix: u64) -> (PathBuf, PathBuf) {
        let cred_name = format!("kepr-{uid}-{}", name.to_lowercase().replace('_', "-"));
        let cp = dir.join(&cred_name);
        // Write something cred-shaped; the sweeper only inspects
        // the meta side, so the contents are arbitrary.
        fs::write(&cp, b"opaque-cred-bytes").unwrap();
        let mp = expiry::meta_path_for(&cp);
        expiry::write_meta(
            &mp,
            &expiry::CredMeta {
                expires_at_unix: Some(expires_at_unix),
                requires_consent: None,
            },
        )
        .unwrap();
        (cp, mp)
    }

    fn plant_meta_only(dir: &Path, basename: &str, expires_at_unix: u64) -> PathBuf {
        // For the orphan-meta test: a meta with no sibling cred.
        // The sweeper should still remove it once expired.
        let mp = dir.join(format!("{basename}.meta"));
        expiry::write_meta(
            &mp,
            &expiry::CredMeta {
                expires_at_unix: Some(expires_at_unix),
                requires_consent: None,
            },
        )
        .unwrap();
        mp
    }

    #[test]
    fn sweep_does_nothing_when_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let stats = sweep_once(dir.path(), 1_000_000, None);
        assert_eq!(stats, SweepStats::default());
    }

    #[test]
    fn sweep_does_nothing_when_dir_is_absent() {
        // Fresh-install case. read_dir returns NotFound; sweep
        // must not panic and must not record an error.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("never-created");
        let stats = sweep_once(&missing, 1_000_000, None);
        assert_eq!(stats, SweepStats::default());
    }

    #[test]
    fn sweep_skips_unexpired_creds() {
        let dir = tempfile::tempdir().unwrap();
        // Plant with expiry FAR in the future.
        let (cp, mp) = plant(dir.path(), 1000, "FOO", 9_000_000_000);
        let stats = sweep_once(dir.path(), 1_000_000, None);
        assert_eq!(stats.seen, 1, "saw the meta file");
        assert_eq!(stats.expired, 0, "must not remove unexpired");
        assert_eq!(stats.errors, 0);
        assert!(cp.exists(), "cred file must remain");
        assert!(mp.exists(), "meta file must remain");
    }

    #[test]
    fn sweep_skips_creds_with_no_meta() {
        // A cred file with no `.meta` sibling is a no-TTL cred.
        // The sweeper must not touch it.
        let dir = tempfile::tempdir().unwrap();
        let cp = dir.path().join("kepr-1000-no-ttl");
        fs::write(&cp, b"opaque").unwrap();
        let stats = sweep_once(dir.path(), 9_000_000_000, None);
        assert_eq!(stats, SweepStats::default());
        assert!(cp.exists(), "no-ttl cred must remain");
    }

    #[test]
    fn sweep_removes_orphan_meta_with_expired_ts() {
        // Edge case: a meta with no sibling cred. Means a previous
        // delete didn't clean up its meta, or a meta-write succeeded
        // but the cred was removed underneath. Either way the
        // sweeper drops the orphan once expired.
        let dir = tempfile::tempdir().unwrap();
        let mp = plant_meta_only(dir.path(), "kepr-1000-orphan", 999);
        let stats = sweep_once(dir.path(), 1_000_000, None);
        assert_eq!(stats.seen, 1);
        assert_eq!(stats.expired, 1);
        assert!(!mp.exists(), "orphan meta must be removed");
    }

    #[test]
    fn sweep_skips_malformed_meta_and_continues() {
        // Two metas — one healthy expired, one garbage. The
        // healthy one must still be reaped.
        let dir = tempfile::tempdir().unwrap();
        let (cp_good, mp_good) = plant(dir.path(), 1000, "GOOD", 999);
        let bad_path = dir.path().join("kepr-1000-bad.meta");
        fs::write(&bad_path, b"not json at all").unwrap();
        let cp_bad = dir.path().join("kepr-1000-bad");
        fs::write(&cp_bad, b"opaque").unwrap();

        let stats = sweep_once(dir.path(), 1_000_000, None);
        assert_eq!(stats.seen, 2);
        assert_eq!(stats.expired, 1, "good cred reaped");
        assert!(stats.errors >= 1, "bad meta surfaces in errors");
        assert!(!mp_good.exists());
        // The malformed meta is left alone — handle_get fails-closed
        // on it, and a future sweep can pick it up if the meta
        // becomes well-formed.
        assert!(bad_path.exists(), "malformed meta is left for triage");
        assert!(cp_bad.exists(), "matching cred left while meta is bad");
        // The healthy cred must be GONE so the test verifies the
        // sweep's actual effect, not just the stats.
        assert!(
            !cp_good.exists(),
            "good cred file must be deleted (sweep_once must call backend.delete)"
        );
    }

    #[test]
    fn sweep_ignores_non_meta_entries() {
        // A bare cred file, a tempfile, and a regular file shouldn't
        // count as `seen`. Only `.meta` paths trigger the loop body.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("kepr-1000-cred"), b"x").unwrap();
        fs::write(dir.path().join("kepr-1000-tmp.123"), b"x").unwrap();
        fs::write(dir.path().join("README"), b"x").unwrap();
        let stats = sweep_once(dir.path(), 1_000_000, None);
        assert_eq!(stats, SweepStats::default());
    }

    #[test]
    fn strip_meta_extension_inverts_meta_path_for() {
        // Round-trip: meta_path_for(p) then strip_meta_extension
        // must yield p. Pin the inverse.
        let cp = PathBuf::from("/etc/credstore.encrypted/kepr-1000-foo");
        let mp = expiry::meta_path_for(&cp);
        assert_eq!(strip_meta_extension(&mp), cp);
    }
}
