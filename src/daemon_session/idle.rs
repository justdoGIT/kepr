// daemon_session/idle.rs — idle auto-lock (T11.12).
//
// `KEPR_IDLE_LOCK=15m` (s / m / h / d suffix, bare number = seconds,
// `0` / `off` = disabled) locks a passphrase-protected user-mode store
// once no request has reached the daemon for that long. `kepr status` and
// `ping` don't count as activity, so a status bar polling the daemon
// doesn't keep the store open. While an agent gate runs the store is in
// use: the clock restarts and nothing is locked.
//
// The lock itself is what `kepr panic` and the sleep watcher do
// (`daemon_gate_registry::panic_now`). The timer is pure over an injected
// clock (`IdleTimer`); `spawn` wires it to the wall clock.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kepr_core::protocol::Request;

/// Parse `15m`, `90s`, `1h`, `2d`, or a bare number of seconds.
/// `None` for `0`, `off`, empty or malformed input (= feature off).
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    let (digits, unit) = match s.char_indices().last()? {
        (i, c) if c.is_ascii_alphabetic() => (&s[..i], c.to_ascii_lowercase()),
        _ => (s, 's'),
    };
    let n: u64 = digits.parse().ok()?;
    let mult = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => return None,
    };
    n.checked_mul(mult).filter(|&secs| secs > 0)
}

/// What the store looks like at a tick.
#[derive(Debug, Clone, Copy)]
pub struct StoreState {
    pub gates_running: bool,
    pub locked: bool,
    pub password_protected: bool,
}

/// Last-activity clock. `now` is always passed in (seconds), so tests
/// drive it without sleeping.
pub struct IdleTimer {
    limit_secs: u64,
    last: AtomicU64,
}

impl IdleTimer {
    pub const fn new(limit_secs: u64) -> Self {
        Self {
            limit_secs,
            last: AtomicU64::new(0),
        }
    }

    pub fn touch(&self, now: u64) {
        self.last.fetch_max(now, Ordering::Relaxed);
    }

    /// True when the store should be locked now. A running gate counts as
    /// activity (the clock restarts); an unprotected or already locked
    /// store is never "due".
    pub fn tick(&self, now: u64, s: StoreState) -> bool {
        if s.gates_running {
            self.touch(now);
            return false;
        }
        if s.locked || !s.password_protected {
            return false;
        }
        now.saturating_sub(self.last.load(Ordering::Relaxed)) >= self.limit_secs
    }
}

/// Requests that don't count as activity (status polling).
pub fn counts_as_activity(req: &Request) -> bool {
    !matches!(req, Request::Status | Request::Ping)
}

static TIMER: std::sync::OnceLock<IdleTimer> = std::sync::OnceLock::new();

fn now_secs() -> u64 {
    crate::expiry::now_unix()
}

/// Per-request hook (daemon.rs): restart the idle clock.
pub fn touch(req: &Request) {
    if let Some(t) = TIMER.get() {
        if counts_as_activity(req) {
            t.touch(now_secs());
        }
    }
}

/// Start the idle watcher for `owner_uid` (user mode) if
/// `KEPR_IDLE_LOCK` is set.
pub fn spawn(owner_uid: u32) {
    let Some(limit) = std::env::var("KEPR_IDLE_LOCK")
        .ok()
        .as_deref()
        .and_then(parse_duration)
    else {
        return;
    };
    let timer = TIMER.get_or_init(|| IdleTimer::new(limit));
    timer.touch(now_secs());
    let step = Duration::from_secs((limit / 4).clamp(1, 30));
    std::thread::spawn(move || loop {
        std::thread::sleep(step);
        let state = StoreState {
            gates_running: crate::daemon_gate_registry::gates_for(owner_uid) > 0,
            locked: crate::crypto::backend_is_locked(),
            password_protected: crate::protected_master_key_path().exists(),
        };
        if timer.tick(now_secs(), state) {
            let (_, locked) = crate::daemon_platform::fingerprint::soft_lock(owner_uid);
            crate::daemon_session::audit_op(
                "idle-lock",
                None,
                owner_uid,
                &crate::audit::username_for_uid(owner_uid),
                if locked { Ok(()) } else { Err("lock failed") },
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN: StoreState = StoreState {
        gates_running: false,
        locked: false,
        password_protected: true,
    };

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("15m"), Some(900));
        assert_eq!(parse_duration("90s"), Some(90));
        assert_eq!(parse_duration("90"), Some(90));
        assert_eq!(parse_duration("1h"), Some(3600));
        assert_eq!(parse_duration("2D"), Some(172_800));
        for off in ["0", "0m", "off", "", "m", "5x", "-5m", "1.5h"] {
            assert_eq!(parse_duration(off), None, "{off:?}");
        }
    }

    #[test]
    fn locks_only_after_the_limit_without_requests() {
        let t = IdleTimer::new(900);
        t.touch(1_000);
        assert!(!t.tick(1_899, OPEN));
        assert!(t.tick(1_900, OPEN));
        // A request restarts the clock.
        t.touch(1_950);
        assert!(!t.tick(2_000, OPEN));
        assert!(t.tick(2_850, OPEN));
    }

    #[test]
    fn no_lock_while_a_gate_runs_and_the_clock_restarts_after() {
        let t = IdleTimer::new(60);
        t.touch(0);
        let gate = StoreState {
            gates_running: true,
            ..OPEN
        };
        assert!(!t.tick(500, gate));
        // The gate stopped at 500: a full period must pass again.
        assert!(!t.tick(559, OPEN));
        assert!(t.tick(560, OPEN));
    }

    #[test]
    fn never_locks_an_unprotected_or_locked_store() {
        let t = IdleTimer::new(1);
        t.touch(0);
        let plain = StoreState {
            password_protected: false,
            ..OPEN
        };
        let locked = StoreState {
            locked: true,
            ..OPEN
        };
        assert!(!t.tick(100, plain));
        assert!(!t.tick(100, locked));
    }

    #[test]
    fn status_polling_is_not_activity() {
        assert!(!counts_as_activity(&Request::Status));
        assert!(!counts_as_activity(&Request::Ping));
        assert!(counts_as_activity(&Request::List));
    }

    #[test]
    fn an_older_clock_reading_never_moves_the_clock_back() {
        let t = IdleTimer::new(10);
        t.touch(100);
        t.touch(50);
        assert!(!t.tick(105, OPEN));
    }
}
