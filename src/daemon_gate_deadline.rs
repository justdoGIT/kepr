// daemon_gate_deadline.rs — a gate drops a value when the window that
// let it have the value ends (security review, 2026-10-14).
//
// A gate caches what it resolved for up to vault.rs `DEFAULT_TTL` (5 min)
// and drops it all as soon as the generation it polls (every 250 ms)
// changes. The store generation moves on every set, delete and grant
// change, but a window running out changes nothing: a just-in-time grant
// (T7.10), an M-of-N approval window (T7.12) or the credential's own
// expiry would leave the cached value usable until that TTL, or until the
// 60 s sweeper. So each release notes when it stops being allowed, and
// the session's generation reply adds one for every such time that has
// passed. Per session: one user's windows never empty another's caches.
// Bounded: a session that can't note another deadline is refused the
// value (fail-closed).

use std::collections::BTreeSet;
use std::sync::Mutex;

use crate::expiry::CredMeta;

/// Most distinct deadlines one session keeps at a time.
const MAX: usize = 1024;

/// One session's deadlines still to come, and how many have passed.
#[derive(Default)]
pub struct Deadlines(Mutex<(BTreeSet<u64>, u64)>);

impl Deadlines {
    /// A value just released stops being allowed at `at` (unix seconds).
    pub fn note(&self, at: u64) -> Result<(), ()> {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if g.0.len() >= MAX && !g.0.contains(&at) {
            return Err(());
        }
        g.0.insert(at);
        Ok(())
    }

    /// How many noted deadlines have passed by `now`, counted once each
    /// time a check finds some: added to the generation the gate sees.
    pub fn passed(&self, now: u64) -> u64 {
        let mut g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let later = g.0.split_off(&now.saturating_add(1));
        if !g.0.is_empty() {
            g.1 += 1;
        }
        g.0 = later;
        g.1
    }
}

/// When a value released at `now` to a session running `harness` stops
/// being allowed: the earliest of the credential's expiry, the end of the
/// grants that let this session have it and its approval window's end.
pub fn until(
    uid: u32,
    name: &str,
    meta: &CredMeta,
    harness: Option<&str>,
    now: u64,
) -> Option<u64> {
    let window = meta
        .approvals
        .filter(|n| *n >= 2)
        .and_then(|_| crate::daemon_syncx::quorum_window(uid, name, now));
    let grant = crate::daemon_aws::grant::open_until(meta, harness, now);
    [meta.expires_at_unix, grant, window]
        .into_iter()
        .flatten()
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_passed_deadline_moves_the_count_once() {
        let d = Deadlines::default();
        assert_eq!(d.passed(100), 0);
        d.note(110).unwrap();
        d.note(120).unwrap();
        d.note(120).unwrap();
        assert_eq!(d.passed(109), 0, "not yet");
        assert_eq!(d.passed(110), 1, "a window ending at 110 is closed at 110");
        assert_eq!(d.passed(115), 1, "nothing new");
        assert_eq!(d.passed(500), 2);
        assert_eq!(d.passed(600), 2);
    }

    #[test]
    fn a_full_session_is_refused_not_forgotten() {
        let d = Deadlines::default();
        for t in 0..MAX as u64 {
            d.note(1000 + t).unwrap();
        }
        assert_eq!(d.note(5000), Err(()));
        d.note(1000).unwrap();
        assert_eq!(d.passed(1000), 1);
        d.note(5000).unwrap();
    }
}
