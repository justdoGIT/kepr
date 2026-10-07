// daemon_session/unlock_guard.rs — unlock backoff and opt-in wipe (T11.13).
//
// Every check of the store passphrase (`kepr unlock`, re-authentication
// before a reveal) goes through `unwrap_guarded`. Consecutive wrong
// passphrases back off exponentially: after n failures the next attempt
// waits 2^(n-1) seconds, capped at 5 minutes. Attempts made during the
// wait are refused without trying the passphrase and are not counted. The
// counter and the last failure's time are kept in the state directory, so
// restarting the daemon doesn't reset them; a correct passphrase does.
//
// `KEPR_WIPE_AFTER=N` (opt-in; unset, 0 or junk = never) destroys the
// passphrase-wrapped master key after N consecutive failures: the file is
// replaced by a tombstone (`key_unlock::WIPED`), so a restarted daemon
// stays locked instead of generating a fresh key, and every later unlock
// says the store was wiped. A recovery kit (`kepr recovery-kit restore`)
// still rebuilds the key: the credential files are untouched. The wipe is
// audited as `unlock-wipe`.
//
// Attempts are serialised (one Argon2id derivation at a time), so
// parallel connections can't sidestep the backoff.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::key_unlock;

const MAX_BACKOFF_SECS: u64 = 300;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GuardState {
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub last_failure: u64,
}

/// Seconds to wait after `failures` consecutive failures: 0, 1, 2, 4, …,
/// capped at 5 minutes.
pub fn backoff_secs(failures: u32) -> u64 {
    match failures {
        0 => 0,
        n => 1u64
            .checked_shl(n - 1)
            .unwrap_or(u64::MAX)
            .min(MAX_BACKOFF_SECS),
    }
}

impl GuardState {
    /// `Err(secs)` while the backoff still runs.
    pub fn check(&self, now: u64) -> Result<(), u64> {
        let wait = backoff_secs(self.failures);
        let elapsed = now.saturating_sub(self.last_failure);
        if elapsed < wait {
            Err(wait - elapsed)
        } else {
            Ok(())
        }
    }

    pub fn record_failure(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        self.last_failure = now;
    }

    pub fn record_success(&mut self) {
        *self = Self::default();
    }

    /// True when the opt-in wipe threshold has been reached.
    pub fn wipe_due(&self, wipe_after: Option<u32>) -> bool {
        matches!(wipe_after, Some(n) if n > 0 && self.failures >= n)
    }
}

/// `KEPR_WIPE_AFTER`: a positive number, or off.
pub fn wipe_after_from_env() -> Option<u32> {
    parse_wipe_after(std::env::var("KEPR_WIPE_AFTER").ok().as_deref())
}

fn parse_wipe_after(v: Option<&str>) -> Option<u32> {
    v.and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
}

/// Where the guard keeps its state and which envelope it may wipe.
pub struct Paths {
    pub state: PathBuf,
    pub envelope: PathBuf,
}

impl Paths {
    fn daemon() -> Self {
        Self {
            state: crate::state_dir().join("unlock-guard.json"),
            envelope: crate::protected_master_key_path(),
        }
    }
}

/// Outcome of a wrong passphrase, for the caller's message and audit.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Still backing off: try again in this many seconds.
    Wait(u64),
    /// Wrong passphrase (counted); `wiped` = the key was destroyed now.
    Wrong { wiped: bool },
    /// The key was wiped earlier.
    Wiped,
    /// Anything else (unreadable file, I/O): not counted.
    Other(String),
}

impl Refusal {
    pub fn message(&self) -> String {
        match self {
            Refusal::Wait(s) => format!("too many failed attempts; try again in {s}s"),
            Refusal::Wrong { wiped: false } => {
                "invalid password or protected master-key envelope".into()
            }
            Refusal::Wrong { wiped: true } | Refusal::Wiped => WIPED_MSG.into(),
            Refusal::Other(e) => e.clone(),
        }
    }
}

const WIPED_MSG: &str = "the master key was wiped after too many failed unlocks; \
                         restore it with `kepr recovery-kit restore`";

static LOCK: Mutex<()> = Mutex::new(());

fn load(path: &Path) -> GuardState {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save(path: &Path, s: &GuardState) {
    if let Ok(bytes) = serde_json::to_vec(s) {
        if let Err(e) = crate::atomic_file::write(path, &bytes, 0o600) {
            eprintln!("[kepr-daemon] cannot save unlock guard state: {e}");
        }
    }
}

/// `key_unlock::unwrap`'s shape (tests pass a cheap stand-in for Argon2id).
pub type Unwrap = fn(&[u8], &[u8]) -> Result<Zeroizing<[u8; 32]>, String>;

/// Check `password` against the envelope at `paths.envelope` under the
/// backoff, with an injected clock, wipe threshold and unwrap function.
pub fn unwrap_at(
    paths: &Paths,
    (now, wipe_after): (u64, Option<u32>),
    password: &[u8],
    unwrap: Unwrap,
) -> Result<Zeroizing<[u8; 32]>, Refusal> {
    let _serial = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let envelope = std::fs::read(&paths.envelope)
        .map_err(|_| Refusal::Other("credential store is not password protected".into()))?;
    if envelope.starts_with(key_unlock::WIPED) {
        return Err(Refusal::Wiped);
    }
    let mut state = load(&paths.state);
    state.check(now).map_err(Refusal::Wait)?;
    match unwrap(&envelope, password) {
        Ok(key) => {
            if state != GuardState::default() {
                state.record_success();
                save(&paths.state, &state);
            }
            Ok(key)
        }
        Err(_) => {
            state.record_failure(now);
            save(&paths.state, &state);
            let wiped = state.wipe_due(wipe_after)
                && crate::atomic_file::write(&paths.envelope, key_unlock::WIPED, 0o600).is_ok();
            Err(Refusal::Wrong { wiped })
        }
    }
}

/// A new envelope was installed (`kepr lock`, recovery restore): earlier
/// failures were against another passphrase, so forget them.
pub fn reset() {
    let _ = std::fs::remove_file(Paths::daemon().state);
}

/// `unwrap_at`, then `on_wipe` exactly when this attempt wiped the key.
pub fn unwrap_then(
    paths: &Paths,
    clock_wipe: (u64, Option<u32>),
    password: &[u8],
    unwrap: Unwrap,
    on_wipe: impl FnOnce(),
) -> Result<Zeroizing<[u8; 32]>, String> {
    let r = unwrap_at(paths, clock_wipe, password, unwrap);
    if let Err(Refusal::Wrong { wiped: true }) = &r {
        on_wipe();
    }
    r.map_err(|e| e.message())
}

/// The daemon's passphrase check (unlock, re-auth, recovery-kit create)
/// for caller `uid`: real clock, state dir, `KEPR_WIPE_AFTER`. A wipe
/// also drops the loaded key and is audited as `unlock-wipe`.
pub fn unwrap_guarded(
    password: &[u8],
    uid: u32,
    username: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    unwrap_then(
        &Paths::daemon(),
        (crate::expiry::now_unix(), wipe_after_from_env()),
        password,
        key_unlock::unwrap,
        || {
            let _ = crate::crypto::lock_backend();
            crate::daemon_session::audit_op("unlock-wipe", None, uid, username, Ok(()));
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The "envelope" holds the passphrase itself; Argon2id (seconds per
    /// call in a debug build) is `key_unlock`'s to test.
    fn paths(dir: &tempfile::TempDir, password: &[u8]) -> Paths {
        let p = Paths {
            state: dir.path().join("guard.json"),
            envelope: dir.path().join("master.key.argon2id"),
        };
        std::fs::write(&p.envelope, password).unwrap();
        p
    }

    fn fake(envelope: &[u8], password: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        if envelope == password {
            Ok(Zeroizing::new([5u8; 32]))
        } else {
            Err("invalid password".into())
        }
    }

    fn try_at(p: &Paths, now: u64, wipe: Option<u32>, pw: &[u8]) -> Result<[u8; 32], Refusal> {
        unwrap_at(p, (now, wipe), pw, fake).map(|k| *k)
    }

    #[test]
    fn backoff_schedule_doubles_from_one_second_to_five_minutes() {
        let got: Vec<u64> = (0..12).map(backoff_secs).collect();
        assert_eq!(got, [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300]);
        assert_eq!(backoff_secs(u32::MAX), 300);
    }

    #[test]
    fn check_waits_out_the_backoff_from_the_last_failure() {
        let mut s = GuardState::default();
        assert_eq!(s.check(0), Ok(()));
        s.record_failure(100);
        assert_eq!(s.check(100), Err(1));
        assert_eq!(s.check(101), Ok(()));
        s.record_failure(101);
        s.record_failure(101);
        assert_eq!(s.check(102), Err(3));
        // A clock that went backwards still waits the full period.
        assert_eq!(s.check(50), Err(4));
    }

    #[test]
    fn wipe_only_when_configured() {
        let mut s = GuardState::default();
        for t in 0..10 {
            s.record_failure(t);
        }
        assert!(!s.wipe_due(None));
        assert!(!s.wipe_due(Some(0)));
        assert!(!s.wipe_due(Some(11)));
        assert!(s.wipe_due(Some(10)));
    }

    #[test]
    fn counter_resets_on_success_and_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir, b"right");
        assert_eq!(
            try_at(&p, 1000, None, b"wrong").unwrap_err(),
            Refusal::Wrong { wiped: false }
        );
        // The state is on disk (a restarted daemon sees it).
        assert_eq!(load(&p.state).failures, 1);
        assert_eq!(
            try_at(&p, 1000, None, b"right").unwrap_err(),
            Refusal::Wait(1)
        );
        assert_eq!(try_at(&p, 1001, None, b"right").unwrap(), [5u8; 32]);
        assert_eq!(load(&p.state), GuardState::default());
    }

    #[test]
    fn attempts_during_the_wait_are_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir, b"right");
        let _ = try_at(&p, 0, None, b"x");
        let _ = try_at(&p, 1, None, b"x");
        assert_eq!(try_at(&p, 2, None, b"x"), Err(Refusal::Wait(1)));
        assert_eq!(load(&p.state).failures, 2);
    }

    #[test]
    fn wipe_replaces_the_envelope_with_a_tombstone_after_n_failures() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir, b"right");
        let mut now = 0;
        for _ in 0..2 {
            assert_eq!(
                try_at(&p, now, Some(3), b"x"),
                Err(Refusal::Wrong { wiped: false })
            );
            now += 1000;
        }
        assert_eq!(
            try_at(&p, now, Some(3), b"x"),
            Err(Refusal::Wrong { wiped: true })
        );
        assert_eq!(std::fs::read(&p.envelope).unwrap(), key_unlock::WIPED);
        // Even the right passphrase can't open it now.
        assert_eq!(
            try_at(&p, now + 1000, Some(3), b"right"),
            Err(Refusal::Wiped)
        );
        assert!(Refusal::Wiped.message().contains("recovery-kit restore"));
    }

    #[test]
    fn no_wipe_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir, b"right");
        for i in 0..20u64 {
            let _ = try_at(&p, i * 1000, None, b"x");
        }
        assert!(try_at(&p, 100_000, None, b"right").is_ok());
    }

    #[test]
    fn the_wipe_hook_runs_once_and_only_for_a_wipe() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir, b"right");
        let mut hooks = 0;
        for i in 0..4u64 {
            let r = unwrap_then(&p, (i * 1000, Some(2)), b"x", fake, || hooks += 1);
            assert!(r.is_err());
        }
        // Wipe on the 2nd failure; the 3rd and 4th see the tombstone.
        assert_eq!(hooks, 1);
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir, b"right");
        for i in 0..4u64 {
            let _ = unwrap_then(&p, (i * 1000, None), b"x", fake, || hooks += 1);
        }
        assert_eq!(hooks, 1, "no wipe (and no audit) unless configured");
    }

    #[test]
    fn wipe_after_parses_only_positive_numbers() {
        for (v, want) in [("3", Some(3)), (" 5 ", Some(5)), ("0", None), ("x", None)] {
            assert_eq!(parse_wipe_after(Some(v)), want, "{v}");
        }
        assert_eq!(parse_wipe_after(None), None);
    }
}
