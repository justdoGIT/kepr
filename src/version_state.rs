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

    /// Increment and return the next counter for `cred_name`. Persists
    /// the new value to disk before returning so a daemon crash mid-
    /// `set` cannot leave a ciphertext on disk whose counter is higher
    /// than what the state file remembers.
    pub fn next(&self, cred_name: &str) -> Result<u64, String> {
        let mut map = self.counters.lock().unwrap();
        let next = map.get(cred_name).copied().unwrap_or(0) + 1;
        map.insert(cred_name.to_string(), next);
        let snapshot = map.clone();
        drop(map); // release the lock before doing IO
        self.persist(&snapshot)?;
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

    /// Forget the counter for `cred_name`. Called on `delete` so a
    /// subsequent `set` of the same name starts at counter=1 rather
    /// than carrying the old high-water mark forever.
    pub fn forget(&self, cred_name: &str) -> Result<(), String> {
        let mut map = self.counters.lock().unwrap();
        if map.remove(cred_name).is_some() {
            let snapshot = map.clone();
            drop(map);
            self.persist(&snapshot)?;
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

    #[test]
    fn next_starts_at_one_for_unknown_cred() {
        let (s, _d) = fresh_state();
        assert_eq!(s.next("FOO").unwrap(), 1);
    }

    #[test]
    fn next_increments_per_call() {
        let (s, _d) = fresh_state();
        assert_eq!(s.next("FOO").unwrap(), 1);
        assert_eq!(s.next("FOO").unwrap(), 2);
        assert_eq!(s.next("FOO").unwrap(), 3);
    }

    #[test]
    fn next_is_independent_per_cred() {
        let (s, _d) = fresh_state();
        assert_eq!(s.next("FOO").unwrap(), 1);
        assert_eq!(s.next("BAR").unwrap(), 1);
        assert_eq!(s.next("FOO").unwrap(), 2);
    }

    #[test]
    fn verify_accepts_equal_counter() {
        let (s, _d) = fresh_state();
        let n = s.next("FOO").unwrap();
        s.verify("FOO", n).expect("equal counter must verify");
    }

    #[test]
    fn verify_accepts_higher_counter() {
        // Higher than recorded should pass — this happens on the
        // first decrypt after a `set` that hasn't been observed
        // (impossible in a single-daemon model, but a defensive
        // ordering for correctness). Pin it.
        let (s, _d) = fresh_state();
        let _ = s.next("FOO").unwrap(); // recorded = 1
        s.verify("FOO", 2).expect("higher counter must verify");
    }

    #[test]
    fn verify_rejects_lower_counter() {
        let (s, _d) = fresh_state();
        let _ = s.next("FOO").unwrap();
        let _ = s.next("FOO").unwrap(); // recorded = 2
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
    fn forget_resets_counter() {
        let (s, _d) = fresh_state();
        let _ = s.next("FOO").unwrap();
        let _ = s.next("FOO").unwrap();
        s.forget("FOO").unwrap();
        // After forget, a verify against any counter should pass
        // (since the cred is unknown again).
        s.verify("FOO", 1).expect("post-forget verify");
        // And next() starts again from 1.
        assert_eq!(s.next("FOO").unwrap(), 1);
    }

    #[test]
    fn state_persists_across_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred-versions.json");

        let s1 = VersionState::load(path.clone()).unwrap();
        let _ = s1.next("FOO").unwrap();
        let _ = s1.next("FOO").unwrap();
        let _ = s1.next("BAR").unwrap();
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
        let _ = s.next("FOO").unwrap(); // forces persist
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
    fn malformed_state_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.json");
        fs::write(&path, b"not valid json").unwrap();
        let err = VersionState::load(path).expect_err("must reject garbage");
        assert!(err.contains("parse state"), "got: {err}");
    }
}
