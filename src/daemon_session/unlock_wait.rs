// daemon_session/unlock_wait.rs — requests wait for an unlock that is
// under way or about to come (T13.25), instead of failing as locked.
//
// Two cases. An unlock is running (`kepr unlock`, `LoginUnlock`: the
// Argon2id derivation takes a moment). Or the daemon was just started for
// a login that will unlock it (`kepr-daemon --user --login`, as the user
// unit starts it, with login unlock on): `kepr pam-unlock` connects a
// moment after the socket appears, and an ssh-agent or git request that
// wins that race would otherwise see a locked store and fail the login's
// first `git pull`. Such requests wait while the store is locked, at most
// `MAX_WAIT` (under the client's 10 s timeout); the start-up window closes
// after `GRACE`, or as soon as an unlock attempt ends. At most
// `MAX_WAITERS` requests wait at once, so a burst can't hold every worker
// the unlock itself needs.

use std::path::Path;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use kepr_core::protocol::Request;
use kepr_core::protocol_session::SessionRequest;

pub const MAX_WAIT: Duration = Duration::from_secs(6);
pub const GRACE: Duration = Duration::from_secs(5);
const MAX_WAITERS: usize = 8;

struct State {
    unlocking: u32,
    grace_until: Option<Instant>,
    waiters: usize,
}

pub struct Waits {
    state: Mutex<State>,
    changed: Condvar,
}

impl Waits {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                unlocking: 0,
                grace_until: None,
                waiters: 0,
            }),
            changed: Condvar::new(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// An unlock is expected within `d` from `now`.
    pub fn begin_grace(&self, now: Instant, d: Duration) {
        self.state().grace_until = Some(now + d);
    }

    /// No unlock is coming after all.
    pub fn end_grace(&self) {
        self.state().grace_until = None;
        self.changed.notify_all();
    }

    pub fn begin_unlock(&self) {
        self.state().unlocking += 1;
    }

    /// An attempt ended (either way): it was the one the window waited for.
    pub fn end_unlock(&self) {
        let mut s = self.state();
        s.unlocking = s.unlocking.saturating_sub(1);
        s.grace_until = None;
        drop(s);
        self.changed.notify_all();
    }

    /// Wait while `locked()` and an unlock is running or expected, at most
    /// `max`. Whether it waited at all.
    pub fn wait(&self, locked: &dyn Fn() -> bool, max: Duration) -> bool {
        let deadline = Instant::now() + max;
        let mut s = self.state();
        if s.waiters >= MAX_WAITERS {
            return false;
        }
        s.waiters += 1;
        let mut waited = false;
        loop {
            let now = Instant::now();
            let coming = s.unlocking > 0 || s.grace_until.is_some_and(|g| now < g);
            if !coming || now >= deadline || !locked() {
                break;
            }
            let until = match s.grace_until {
                Some(g) if s.unlocking == 0 => g.min(deadline),
                _ => deadline,
            };
            waited = true;
            s = self
                .changed
                .wait_timeout(s, until.saturating_duration_since(now))
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        s.waiters -= 1;
        waited
    }
}

static WAITS: Waits = Waits::new();

/// While alive, requests that need the key wait for this unlock.
pub struct Unlocking(());

impl Unlocking {
    pub fn begin() -> Self {
        WAITS.begin_unlock();
        Unlocking(())
    }
}

impl Drop for Unlocking {
    fn drop(&mut self) {
        WAITS.end_unlock();
    }
}

pub fn end_grace() {
    WAITS.end_grace();
}

/// Requests that read or write key-protected data, the ones a login's
/// first ssh, git, docker or `kepr exec` sends. Everything else (status,
/// ping, lock / unlock themselves, crypto info, listings of names) answers
/// at once, or `kepr status` would sit out the start-up window.
fn needs_key(r: &Request) -> bool {
    matches!(
        r,
        Request::Get { .. }
            | Request::Set { .. }
            | Request::RecordSet { .. }
            | Request::Records(_)
            | Request::StartGate { .. }
            | Request::SshList
            | Request::SshSign { .. }
            | Request::Session(
                SessionRequest::GetQuiet { .. }
                    | SessionRequest::FetchFd { .. }
                    | SessionRequest::Reauth { .. }
            )
    )
}

/// Before a request: wait if it may need the key while one is coming.
pub fn before(request: &Request) {
    if needs_key(request) {
        WAITS.wait(&crate::crypto::backend_is_locked, MAX_WAIT);
    }
}

/// Should a starting daemon expect a login unlock? Only when the user
/// unit started it for a login (`--login`), login unlock is on and the
/// store has a passphrase to unlock.
pub fn expect_login(login_flag: bool, home: &Path, protected: bool) -> bool {
    login_flag && protected && kepr_core::login_unlock::enabled(home)
}

/// Daemon start-up (user mode).
pub fn start() {
    let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let flag = std::env::args().any(|a| a == "--login");
    if expect_login(flag, &home, crate::protected_master_key_path().exists()) {
        WAITS.begin_grace(Instant::now(), GRACE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const LONG: Duration = Duration::from_secs(5);

    #[test]
    fn nothing_coming_means_no_wait() {
        let w = Waits::new();
        let t = Instant::now();
        assert!(!w.wait(&|| true, LONG));
        assert!(t.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn a_running_unlock_is_waited_for() {
        let w = Arc::new(Waits::new());
        let open = Arc::new(AtomicBool::new(false));
        w.begin_unlock();
        let (w2, open2) = (Arc::clone(&w), Arc::clone(&open));
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            open2.store(true, Ordering::SeqCst);
            w2.end_unlock();
        });
        let t = Instant::now();
        assert!(w.wait(&|| !open.load(Ordering::SeqCst), LONG));
        assert!(t.elapsed() >= Duration::from_millis(100));
        assert!(t.elapsed() < Duration::from_secs(3));
        h.join().unwrap();
    }

    #[test]
    fn an_unlocked_store_never_waits() {
        let w = Waits::new();
        w.begin_unlock();
        let t = Instant::now();
        assert!(!w.wait(&|| false, LONG));
        assert!(t.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn the_start_up_window_closes_by_itself() {
        let w = Waits::new();
        w.begin_grace(Instant::now(), Duration::from_millis(200));
        let t = Instant::now();
        assert!(w.wait(&|| true, LONG));
        assert!(t.elapsed() >= Duration::from_millis(150));
        assert!(t.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_failed_attempt_ends_the_window_at_once() {
        let w = Arc::new(Waits::new());
        w.begin_grace(Instant::now(), LONG);
        let w2 = Arc::clone(&w);
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            w2.begin_unlock();
            w2.end_unlock(); // wrong password: still locked
        });
        let t = Instant::now();
        assert!(w.wait(&|| true, LONG));
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        h.join().unwrap();
        // And a later request doesn't wait for a login that came and went.
        assert!(!w.wait(&|| true, LONG));
    }

    #[test]
    fn the_wait_is_bounded() {
        let w = Waits::new();
        w.begin_unlock(); // never ends
        let t = Instant::now();
        assert!(w.wait(&|| true, Duration::from_millis(200)));
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn only_a_few_requests_wait_at_once() {
        let w = Arc::new(Waits::new());
        w.begin_grace(Instant::now(), LONG);
        let waiting: Vec<_> = (0..MAX_WAITERS)
            .map(|_| {
                let w = Arc::clone(&w);
                std::thread::spawn(move || w.wait(&|| true, LONG))
            })
            .collect();
        let t = Instant::now();
        while w.state().waiters < MAX_WAITERS {
            assert!(t.elapsed() < LONG, "waiters never arrived");
            std::thread::sleep(Duration::from_millis(10));
        }
        let t = Instant::now();
        assert!(!w.wait(&|| true, LONG), "one too many");
        assert!(t.elapsed() < Duration::from_millis(500));
        w.end_grace();
        for h in waiting {
            assert!(h.join().unwrap());
        }
    }

    #[test]
    fn unlock_requests_and_status_never_wait() {
        use kepr_core::generate::ZeroString;
        for r in [
            Request::Ping,
            Request::Status,
            Request::List,
            Request::Eco(kepr_core::protocol_eco::EcoRequest::CryptoInfo),
            Request::Panic,
            Request::Unlock {
                password: ZeroString::from("x"),
            },
            Request::Session(SessionRequest::LoginUnlock {
                password: ZeroString::from("x"),
            }),
        ] {
            assert!(!needs_key(&r), "{r:?}");
        }
        assert!(needs_key(&Request::SshList));
        assert!(needs_key(&Request::SshSign {
            name: "K".into(),
            data_b64: String::new(),
        }));
        assert!(needs_key(&Request::Session(SessionRequest::GetQuiet {
            name: "K".into()
        })));
        assert!(needs_key(&Request::Get {
            name: "K".into(),
            fido2_assertion: None,
        }));
    }

    #[test]
    fn a_start_up_expects_a_login_only_when_all_three_hold() {
        let home = tempfile::tempdir().unwrap();
        assert!(!expect_login(true, home.path(), true), "login unlock off");
        let m = kepr_core::login_unlock::marker(home.path());
        std::fs::create_dir_all(m.parent().unwrap()).unwrap();
        std::fs::write(&m, b"").unwrap();
        assert!(expect_login(true, home.path(), true));
        assert!(
            !expect_login(false, home.path(), true),
            "not started for a login"
        );
        assert!(!expect_login(true, home.path(), false), "no passphrase");
    }
}
