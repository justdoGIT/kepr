// version_state.rs — per-credential monotonic counter for rollback
// protection (Finding 2 in the public CEO/PhD-security review).
//
// Without this, restoring an old `/etc/credstore.encrypted/` snapshot
// reinstates revoked or rotated secrets silently — `set NAME` only
// "really" revokes the previous value if the older ciphertext can no
// longer be successfully decrypted under the daemon's current rules.
//
// Strategy:
//
//   1. Every `set` increments a counter for that cred name and bakes
//      the counter into the AEAD plaintext (so the GCM tag binds it).
//   2. The daemon persists the highest counter ever observed per cred
//      in /var/lib/kepr/cred-versions.json (root:root 0600, inside
//      /var/lib/kepr at 0700 — same StateDirectory as the master key).
//   3. On `get`, the file's embedded counter is compared to the
//      persisted state. A counter < state means the file was rolled
//      back; decrypt is refused.
//
// Threat model: an attacker with read+write to /etc/credstore.encrypted/
// (e.g., backup-restore, compromised filesystem snapshot, kepr-group
// member with elevated FS access) cannot replay an old ciphertext
// without also rolling back /var/lib/kepr/cred-versions.json. /var/lib/kepr/
// is 0700 root-only, so the rollback requires root — at which point
// the attacker is also the daemon and can forge anything anyway.
//
// State file format: a flat JSON object mapping cred-name (the on-disk
// `kepr-<uid>-<name>` form) to its highest-seen counter. Atomic writes
// via a per-(pid, thread-id) temp file + rename, created at 0o600 by
// open(2) so the inode never exists at any wider mode. Same shape as
// the InProc backend's write_atomic.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

/// On-disk state mapping `kepr-<uid>-<name>` to the highest counter
/// the daemon has ever stamped into a ciphertext for that cred. The
/// counter is u64 — at one increment per nanosecond the daemon would
/// run out after ~584 years.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct StateFile {
    /// JSON map: cred-name → highest counter recorded.
    counters: HashMap<String, u64>,
}

/// Daemon-wide rollback-protection state. One instance lives for the
/// daemon's lifetime; it owns a Mutex so any worker thread can call
/// `next` / `verify` without external synchronisation.
#[derive(Debug)]
pub struct VersionState {
    path: PathBuf,
    counters: Mutex<HashMap<String, u64>>,
}

impl VersionState {
    /// Load the state file from `path`. Missing file is treated as
    /// "fresh install, no counters yet" rather than an error — the
    /// daemon's first run on a host is the legitimate empty case.
    /// A malformed file IS an error; the daemon refuses to start
    /// rather than silently regress to no rollback protection.
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let counters = if path.exists() {
            let bytes = fs::read(&path).map_err(|e| format!("read state: {e}"))?;
            let state: StateFile =
                serde_json::from_slice(&bytes).map_err(|e| format!("parse state: {e}"))?;
            state.counters
        } else {
            HashMap::new()
        };
        Ok(Self {
            path,
            counters: Mutex::new(counters),
        })
    }

    /// Run `f` with the next counter for `cred_name`, atomically.
    /// The closure does the actual on-disk write of the ciphertext
    /// for that counter; on closure success the new counter is
    /// committed and the state file is persisted, on closure failure
    /// the in-memory map is left untouched and disk state is
    /// unchanged.
    ///
    /// Codex flagged two P1s on the previous shape:
    ///
    ///   1. The earlier `next()` advanced the in-memory counter
    ///      *before* the caller wrote the ciphertext file. If the
    ///      file write then failed (ENOSPC, rename failure), the
    ///      cred became unreadable: the on-disk file still carried
    ///      the old counter while the state's high-water mark had
    ///      jumped, so subsequent `get` calls were rejected as
    ///      rollback. Running the file IO first, committing the
    ///      counter only on success, fixes this.
    ///
    ///   2. The earlier `next()` released the mutex before
    ///      persisting the cloned snapshot to disk. Two concurrent
    ///      `next()` calls could persist their snapshots in either
    ///      order, so an older snapshot could land on disk last and
    ///      overwrite a newer counter. After a daemon restart, the
    ///      reloaded state could be lower than what the in-memory
    ///      one had committed, weakening rollback protection.
    ///      Holding the lock through the file IO (this includes the
    ///      caller's closure) and the subsequent persist serialises
    ///      both mutations and avoids the lost-update race.
    ///
    /// Trade-off: encrypts across different credentials also
    /// serialise on this lock. The daemon's encrypt rate is bounded
    /// by user activity (a few `set` ops/sec at most for any normal
    /// workload), so the throughput cost is negligible compared to
    /// the correctness win.
    pub fn with_next<F>(&self, cred_name: &str, f: F) -> Result<u64, String>
    where
        F: FnOnce(u64) -> Result<(), String>,
    {
        let mut map = self.counters.lock().unwrap();
        let prev = map.get(cred_name).copied();
        let next = prev.unwrap_or(0) + 1;

        // Two-phase commit. Codex's rollback-protection re-review
        // surfaced the underlying atomicity requirement: the rollback
        // floor (state) and the on-disk ciphertext (file) MUST advance
        // together, or the daemon must be left with consistent old
        // values, or the cred must brick. Anything in between (file
        // ahead of state, or vice versa) lets an attacker replay a
        // ciphertext whose counter no longer matches the floor.
        //
        // Strategy: bump state first. If state-persist fails, file IO
        // never runs. If state-persist succeeds, run file IO. If file
        // IO fails, attempt to revert state. The revert failing is
        // the only path that leaves an inconsistency, and there state
        // is ahead of file — verify rejects the older file, so the
        // cred bricks. Bricked > replayable.

        // Phase 1: persist the new counter.
        map.insert(cred_name.to_string(), next);
        let snapshot = map.clone();
        if let Err(e) = self.persist(&snapshot) {
            // State persist failed. Revert in-memory and bail out;
            // file IO was never attempted.
            match prev {
                Some(p) => {
                    map.insert(cred_name.to_string(), p);
                }
                None => {
                    map.remove(cred_name);
                }
            }
            return Err(e);
        }

        // Phase 2: file IO. The state floor is now at `next`, so
        // any successful write at `next` produces a verify-clean
        // ciphertext.
        if let Err(e) = f(next) {
            // File IO failed AFTER state was persisted. Try to
            // revert state to its prior value so the existing
            // on-disk ciphertext (still at the old counter) keeps
            // verifying.
            match prev {
                Some(p) => {
                    map.insert(cred_name.to_string(), p);
                }
                None => {
                    map.remove(cred_name);
                }
            }
            let snapshot = map.clone();
            if let Err(rev_err) = self.persist(&snapshot) {
                // Revert persist also failed: state on disk is at
                // `next`, no new file exists, existing ciphertext
                // (if any) is at `prev`. verify(prev vs next)
                // rejects, so subsequent reads of the cred return
                // "credential unavailable" until a successful retry
                // of with_next. The cred is bricked, NOT replayable
                // — strictly better than the previous shape, which
                // could leak a replay window in the same scenario.
                return Err(format!(
                    "{e} (state revert also failed: {rev_err}; cred is now unreadable until retry)"
                ));
            }
            return Err(e);
        }

        Ok(next)
    }

    /// Verify a ciphertext-embedded counter is acceptable: it must be
    /// at least as high as the recorded high-water mark. A strictly
    /// lower value means the file is older than what the daemon has
    /// already stamped, i.e. a rollback. Equal is fine — the file
    /// matches what we last wrote.
    ///
    /// `kepr_v1` files have no counter; the caller passes 0 there and
    /// any unknown cred-name accepts (high-water = 0). This means a
    /// v1 file written before this change still decrypts cleanly,
    /// but the moment it is overwritten via `set` it becomes a v2
    /// file with counter=1 and rollback protection takes effect.
    pub fn verify(&self, cred_name: &str, file_counter: u64) -> Result<(), String> {
        let map = self.counters.lock().unwrap();
        let recorded = map.get(cred_name).copied().unwrap_or(0);
        if file_counter < recorded {
            Err(format!(
                "rollback detected: file counter {file_counter} < recorded {recorded}"
            ))
        } else {
            Ok(())
        }
    }

    /// Tombstone the counter for `cred_name`: advance it past the
    /// highest counter ever issued, so any pre-delete ciphertext
    /// snapshot replay fails the rollback check. Called on `delete`.
    ///
    /// `verify` accepts file_counter ≥ recorded, so simply *removing*
    /// the entry would let a captured pre-delete file (counter == old
    /// high-water) replay against the implicit recorded=0 — exactly
    /// what Codex flagged on the prior shape. Advancing instead means
    /// any old ciphertext is now strictly below the recorded value
    /// and gets rejected.
    ///
    /// Holds the lock through persist for the same reason `with_next`
    /// does — out-of-order persistence between a tombstone and a
    /// concurrent `with_next` would corrupt the state file.
    pub fn tombstone(&self, cred_name: &str) -> Result<(), String> {
        let mut map = self.counters.lock().unwrap();
        let current = map.get(cred_name).copied().unwrap_or(0);
        let bumped = current + 1;
        map.insert(cred_name.to_string(), bumped);
        let snapshot = map.clone();
        if let Err(e) = self.persist(&snapshot) {
            // Symmetric with with_next: revert the in-memory bump on
            // persist failure so on-disk and in-memory don't diverge.
            map.insert(cred_name.to_string(), current);
            return Err(e);
        }
        Ok(())
    }

    fn persist(&self, counters: &HashMap<String, u64>) -> Result<(), String> {
        let state = StateFile {
            counters: counters.clone(),
        };
        let bytes = serde_json::to_vec(&state).map_err(|e| format!("serialise state: {e}"))?;
        let parent = self.path.parent().ok_or("invalid state path (no parent)")?;
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| format!("create state dir: {e}"))?;
        }
        let tmp = self.path.with_extension(format!(
            "tmp.{}.{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        // create_new(true) so mode(0o600) is honoured at open time.
        // EEXIST means a stale tempfile from a crashed run; remove
        // and retry once. Same shape as crypto_inproc::write_atomic.
        let mut f = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&tmp);
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|e| format!("open state temp (after stale-cleanup): {e}"))?
            }
            Err(e) => return Err(format!("open state temp: {e}")),
        };
        if let Err(e) = f.write_all(&bytes) {
            drop(f);
            let _ = fs::remove_file(&tmp);
            return Err(format!("write state: {e}"));
        }
        drop(f);
        fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("install state: {e}")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_state() -> (VersionState, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred-versions.json");
        let state = VersionState::load(path).unwrap();
        (state, dir)
    }

    /// Test helper: succeed-immediately closure. Used wherever a test
    /// just wants to advance the counter without simulating any real
    /// file IO.
    fn ok_io<T>(_: T) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn next_starts_at_one_for_unknown_cred() {
        let (s, _d) = fresh_state();
        assert_eq!(s.with_next("FOO", ok_io).unwrap(), 1);
    }

    #[test]
    fn next_increments_per_call() {
        let (s, _d) = fresh_state();
        assert_eq!(s.with_next("FOO", ok_io).unwrap(), 1);
        assert_eq!(s.with_next("FOO", ok_io).unwrap(), 2);
        assert_eq!(s.with_next("FOO", ok_io).unwrap(), 3);
    }

    #[test]
    fn next_is_independent_per_cred() {
        let (s, _d) = fresh_state();
        assert_eq!(s.with_next("FOO", ok_io).unwrap(), 1);
        assert_eq!(s.with_next("BAR", ok_io).unwrap(), 1);
        assert_eq!(s.with_next("FOO", ok_io).unwrap(), 2);
    }

    #[test]
    fn with_next_does_not_advance_on_io_failure() {
        // Codex P1 #1: a failing write_atomic must NOT leave the
        // state map advanced. Verify by injecting a closure that
        // always errors and checking the next successful call still
        // gets counter=1.
        let (s, _d) = fresh_state();
        let err = s
            .with_next("FOO", |_| Err("simulated ENOSPC".to_string()))
            .expect_err("io failure propagates");
        assert!(err.contains("ENOSPC"));
        // State is untouched: a subsequent call still returns 1.
        assert_eq!(s.with_next("FOO", ok_io).unwrap(), 1);
    }

    #[test]
    fn verify_accepts_equal_counter() {
        let (s, _d) = fresh_state();
        let n = s.with_next("FOO", ok_io).unwrap();
        s.verify("FOO", n).expect("equal counter must verify");
    }

    #[test]
    fn verify_accepts_higher_counter() {
        // Higher than recorded should pass — this happens on the
        // first decrypt after a `set` that hasn't been observed
        // (impossible in a single-daemon model, but a defensive
        // ordering for correctness). Pin it.
        let (s, _d) = fresh_state();
        let _ = s.with_next("FOO", ok_io).unwrap(); // recorded = 1
        s.verify("FOO", 2).expect("higher counter must verify");
    }

    #[test]
    fn verify_rejects_lower_counter() {
        let (s, _d) = fresh_state();
        let _ = s.with_next("FOO", ok_io).unwrap();
        let _ = s.with_next("FOO", ok_io).unwrap(); // recorded = 2
        let err = s.verify("FOO", 1).expect_err("lower counter must reject");
        assert!(err.contains("rollback detected"), "got: {err}");
    }

    #[test]
    fn verify_unknown_cred_accepts_zero() {
        // A cred we have never seen has implicit recorded=0; any
        // counter ≥ 0 must pass. This is the v1-file readback path.
        let (s, _d) = fresh_state();
        s.verify("UNKNOWN", 0).expect("v1-file path must accept 0");
        s.verify("UNKNOWN", 42)
            .expect("any non-negative counter accepted");
    }

    #[test]
    fn tombstone_advances_past_highest_issued() {
        // After `set` (counter=1) and `set` (counter=2), tombstone
        // must bump the recorded value to 3 so the file at counter=2
        // (the latest pre-delete ciphertext) gets rejected on
        // replay. Equality is not enough — verify uses ≥.
        let (s, _d) = fresh_state();
        let _ = s.with_next("FOO", ok_io).unwrap(); // recorded = 1
        let _ = s.with_next("FOO", ok_io).unwrap(); // recorded = 2
        s.tombstone("FOO").unwrap();
        // The latest issued counter (2) must now be rejected.
        let err = s
            .verify("FOO", 2)
            .expect_err("counter=2 must reject post-tombstone");
        assert!(err.contains("rollback detected"), "got: {err}");
        // counter=3 still verifies (a fresh `set` after the delete
        // would issue 3 and decrypt cleanly).
        s.verify("FOO", 3).expect("counter=3 must verify");
        // And the next with_next() advances from 3, not from 1.
        assert_eq!(s.with_next("FOO", ok_io).unwrap(), 4);
    }

    #[test]
    fn tombstone_on_unknown_cred_records_one() {
        // Tombstoning a cred we've never seen sets the floor at 1.
        // This handles the (admittedly weird) case where a delete
        // races against a fresh-install scenario.
        let (s, _d) = fresh_state();
        s.tombstone("UNKNOWN").unwrap();
        let err = s.verify("UNKNOWN", 0).expect_err("counter=0 < 1");
        assert!(err.contains("rollback detected"), "got: {err}");
        s.verify("UNKNOWN", 1).expect("counter=1 verifies");
    }

    #[test]
    fn state_persists_across_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred-versions.json");

        let s1 = VersionState::load(path.clone()).unwrap();
        let _ = s1.with_next("FOO", ok_io).unwrap();
        let _ = s1.with_next("FOO", ok_io).unwrap();
        let _ = s1.with_next("BAR", ok_io).unwrap();
        drop(s1);

        let s2 = VersionState::load(path).unwrap();
        // Recorded values should round-trip.
        let err = s2.verify("FOO", 1).expect_err("rollback after reload");
        assert!(err.contains("rollback detected"), "got: {err}");
        s2.verify("FOO", 2).expect("reload preserved FOO=2");
        s2.verify("BAR", 1).expect("reload preserved BAR=1");
    }

    #[test]
    fn state_file_is_0600_after_persist() {
        use std::os::unix::fs::PermissionsExt;
        let (s, _d) = fresh_state();
        let _ = s.with_next("FOO", ok_io).unwrap(); // forces persist
        let mode = fs::metadata(&s.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state file must be 0o600, got {mode:o}");
    }

    #[test]
    fn missing_state_file_loads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let s = VersionState::load(path).expect("missing path is OK");
        // Empty state means any counter passes against an unknown cred.
        s.verify("ANY", 0).unwrap();
    }

    #[test]
    fn with_next_reverts_in_memory_on_persist_failure() {
        // P2 fix from Codex: when persist fails AFTER the file IO
        // succeeds, the in-memory map must NOT stay ahead of the
        // durable state file. Otherwise a daemon restart that reloads
        // from disk would regress the rollback floor below ciphertexts
        // we just produced. Pin the revert.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let s = VersionState::load(state_path).unwrap();

        // First call persists successfully — recorded = 1.
        s.with_next("FOO", ok_io).unwrap();

        // Make the parent dir non-writable so the next persist's
        // tempfile creation fails with EACCES.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();

        let err = s.with_next("FOO", ok_io);

        // Restore permissions BEFORE assertions so TempDir cleanup
        // can run regardless of test outcome.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();

        assert!(err.is_err(), "persist failure must propagate");

        // The critical post-condition: in-memory state is reverted
        // to its previous value (recorded = 1), not stuck at 2.
        // Verify both directly and via the verify() boundary.
        let err2 = s
            .verify("FOO", 0)
            .expect_err("0 < recorded=1 still rejects");
        assert!(err2.contains("rollback detected"), "got: {err2}");
        s.verify("FOO", 1).expect("recorded reverted to 1");
    }

    #[test]
    fn malformed_state_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.json");
        fs::write(&path, b"not valid json").unwrap();
        let err = VersionState::load(path).expect_err("must reject garbage");
        assert!(err.contains("parse state"), "got: {err}");
    }
}
