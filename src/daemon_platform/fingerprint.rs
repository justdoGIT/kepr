// daemon_platform/fingerprint.rs — `kepr unlock --fingerprint` (T10.03).
//
// A fingerprint can't derive the key that wraps the master key, so this is
// a quick unlock, opt-in with `KEPR_FINGERPRINT_UNLOCK=8h` (s/m/h/d) on a
// passphrase-protected user-mode daemon:
//
// - When the idle timer (T11.12) or the sleep watcher locks the store
//   (`soft_lock`), the daemon keeps the master key in memory for that long
//   instead of dropping it. The backend is locked all the same: every
//   request fails until an unlock.
// - `FingerprintUnlock` asks polkit to authorise the calling process (the
//   SO_PEERCRED pid) for `io.kepr.unlock` (`auth_self`, so pam_fprintd in
//   polkit's PAM stack accepts a finger; never `_keep`, so every unlock
//   prompts). Granted → the kept key reopens the store.
// - Nothing to release (feature off, `kepr panic`, a daemon restart, the
//   window passed, the passphrase file gone) → refused without a prompt;
//   the passphrase (`kepr unlock`) is the only way back. `kepr panic`
//   (`forget`) is the hard stop: it drops the kept key.
//
// System mode is refused: the shared store is root's, and neither the idle
// timer nor the sleep watcher runs there.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use kepr_core::protocol::Response;
use zeroize::Zeroizing;

use crate::crypto;

/// Polkit action for unlocking; must match `systemd/polkit/io.kepr.policy`.
pub const ACTION_ID: &str = "io.kepr.unlock";

/// The master key kept across a soft lock, and when it stops counting.
pub struct Kept {
    key: Zeroizing<[u8; 32]>,
    until: Instant,
}

static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

/// `KEPR_FINGERPRINT_UNLOCK`: how long a soft-locked store may be reopened
/// with a fingerprint. Unset, `0` or `off` = feature off.
pub fn window_from_env() -> Option<Duration> {
    let v = std::env::var("KEPR_FINGERPRINT_UNLOCK").ok()?;
    crate::daemon_session::idle::parse_duration(&v).map(Duration::from_secs)
}

fn slot() -> std::sync::MutexGuard<'static, Option<Kept>> {
    KEPT.lock().unwrap_or_else(|p| p.into_inner())
}

/// Drop the kept key (`kepr panic`).
pub fn forget() {
    *slot() = None;
}

/// The idle timer's and the sleep watcher's lock: `panic_now`, keeping the
/// key for the fingerprint window when the feature is on and the store
/// really locked. Same return value as `panic_now`.
pub fn soft_lock(uid: u32) -> (usize, bool) {
    let window = window_from_env().filter(|_| crate::user_mode());
    let key = window.and_then(|_| crypto::snapshot_key().ok());
    let (gates, locked) = crate::daemon_gate_registry::panic_now(uid);
    match (locked, key, window) {
        (true, Some(key), Some(w)) => {
            *slot() = Some(Kept {
                key,
                until: Instant::now() + w,
            })
        }
        // Already locked (screen lock, then suspend): keep what was kept.
        (true, None, _) => {}
        _ => forget(),
    }
    (gates, locked)
}

/// What the store looks like when an unlock arrives.
#[derive(Debug, Clone, Copy)]
pub struct State {
    pub user_mode: bool,
    pub locked: bool,
    pub password_protected: bool,
}

const UNAVAILABLE: &str =
    "fingerprint unlock is not available now; unlock with the passphrase (kepr unlock)";

/// The decision, over an injected slot, clock, polkit check and backend.
/// The kept key is taken out of the slot before the prompt and put back
/// only when polkit says no, so two requests can't both use it.
pub fn unlock_with(
    kept: &Mutex<Option<Kept>>,
    state: State,
    now: Instant,
    authorize: impl FnOnce() -> bool,
    unlock: impl FnOnce(&[u8; 32]) -> Result<(), String>,
) -> Result<(), String> {
    let take = || kept.lock().unwrap_or_else(|p| p.into_inner()).take();
    if !state.user_mode {
        return Err("fingerprint unlock works with the user-mode daemon only".into());
    }
    if !state.locked {
        take();
        return Err("credential store is not locked".into());
    }
    let entry = match take() {
        Some(k) if state.password_protected && k.until > now => k,
        _ => return Err(UNAVAILABLE.into()),
    };
    if !authorize() {
        let mut g = kept.lock().unwrap_or_else(|p| p.into_inner());
        if g.is_none() {
            *g = Some(entry);
        }
        return Err("not authorized".into());
    }
    unlock(&entry.key)
}

pub fn handle_unlock(uid: u32, peer_pid: i32, username: &str) -> Response {
    let state = State {
        user_mode: crate::user_mode(),
        locked: crypto::backend_is_locked(),
        password_protected: crate::protected_master_key_path().exists(),
    };
    let result = unlock_with(
        &KEPT,
        state,
        Instant::now(),
        || crate::daemon_polkit::authorized(peer_pid, ACTION_ID),
        crypto::unlock_backend,
    );
    crate::daemon_session::audit_op(
        "unlock-fingerprint",
        None,
        uid,
        username,
        result.as_ref().map(|_| ()).map_err(String::as_str),
    );
    match result {
        Ok(()) => Response::UnlockedOk,
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const LOCKED: State = State {
        user_mode: true,
        locked: true,
        password_protected: true,
    };

    fn kept(secs_left: u64, now: Instant) -> Mutex<Option<Kept>> {
        Mutex::new(Some(Kept {
            key: Zeroizing::new([7u8; 32]),
            until: now + Duration::from_secs(secs_left),
        }))
    }

    /// Runs `unlock_with`; returns (result, prompted, key handed to the backend).
    fn go(
        slot: &Mutex<Option<Kept>>,
        state: State,
        now: Instant,
        grant: bool,
    ) -> (Result<(), String>, bool, Option<[u8; 32]>) {
        let prompted = Cell::new(false);
        let got = Cell::new(None);
        let r = unlock_with(
            slot,
            state,
            now,
            || {
                prompted.set(true);
                grant
            },
            |k| {
                got.set(Some(*k));
                Ok(())
            },
        );
        (r, prompted.get(), got.get())
    }

    #[test]
    fn granted_unlock_uses_the_kept_key_once() {
        let now = Instant::now();
        let slot = kept(60, now);
        let (r, prompted, key) = go(&slot, LOCKED, now, true);
        assert_eq!(r, Ok(()));
        assert!(prompted);
        assert_eq!(key, Some([7u8; 32]));
        assert!(slot.lock().unwrap().is_none(), "the kept key is consumed");
        let (r, prompted, _) = go(&slot, LOCKED, now, true);
        assert!(r.unwrap_err().contains("passphrase"));
        assert!(!prompted, "nothing to release: no prompt");
    }

    #[test]
    fn denied_prompt_keeps_the_key_for_another_try() {
        let now = Instant::now();
        let slot = kept(60, now);
        let (r, prompted, key) = go(&slot, LOCKED, now, false);
        assert_eq!(r, Err("not authorized".into()));
        assert!(prompted);
        assert_eq!(key, None);
        assert!(slot.lock().unwrap().is_some());
    }

    #[test]
    fn no_prompt_without_a_valid_kept_key() {
        let now = Instant::now();
        // Window passed.
        let slot = kept(5, now);
        let later = now + Duration::from_secs(6);
        let (r, prompted, key) = go(&slot, LOCKED, later, true);
        assert!(r.is_err() && !prompted && key.is_none());
        assert!(slot.lock().unwrap().is_none(), "an expired key is dropped");
        // Never kept (feature off, panic, restart).
        let empty = Mutex::new(None);
        let (r, prompted, _) = go(&empty, LOCKED, now, true);
        assert!(r.is_err() && !prompted);
        // Passphrase file gone (wiped after failed unlocks).
        let slot = kept(60, now);
        let wiped = State {
            password_protected: false,
            ..LOCKED
        };
        let (r, prompted, key) = go(&slot, wiped, now, true);
        assert!(r.is_err() && !prompted && key.is_none());
    }

    #[test]
    fn refused_in_system_mode_and_when_not_locked() {
        let now = Instant::now();
        let slot = kept(60, now);
        let system = State {
            user_mode: false,
            ..LOCKED
        };
        let (r, prompted, _) = go(&slot, system, now, true);
        assert!(r.unwrap_err().contains("user-mode"));
        assert!(!prompted);
        let open = State {
            locked: false,
            ..LOCKED
        };
        let (r, prompted, _) = go(&slot, open, now, true);
        assert!(r.is_err() && !prompted);
        assert!(slot.lock().unwrap().is_none(), "a stale key is dropped");
    }

    #[test]
    fn window_parsing() {
        assert_eq!(
            crate::daemon_session::idle::parse_duration("8h"),
            Some(8 * 3600)
        );
        assert_eq!(crate::daemon_session::idle::parse_duration("off"), None);
    }

    /// The policy file is well-formed, registers both actions the daemon
    /// asks polkit about, and never caches an authorisation (`_keep`) or
    /// grants without one.
    #[test]
    fn polkit_policy_declares_both_actions() {
        let xml = include_str!("../../systemd/polkit/io.kepr.policy");
        assert!(tags_balance(xml), "policy XML is not well-formed");
        for id in ["io.kepr.read-credential", ACTION_ID] {
            let start = xml
                .find(&format!("<action id=\"{id}\">"))
                .unwrap_or_else(|| panic!("action {id} missing"));
            let body = &xml[start..start + xml[start..].find("</action>").unwrap()];
            for tag in ["description", "message"] {
                assert!(body.contains(&format!("<{tag}>")), "{id}: no <{tag}>");
            }
            assert!(body.contains("<allow_any>no</allow_any>"), "{id}");
            assert!(body.contains("<allow_inactive>no</allow_inactive>"), "{id}");
            assert!(
                body.contains("<allow_active>auth_self</allow_active>"),
                "{id}"
            );
        }
        assert!(!xml.contains("_keep<"), "authorisations must not be cached");
        assert!(xml.contains(&format!("\"{}\"", crate::daemon_polkit::ACTION_ID)));
    }

    /// Minimal well-formedness: every element closes in order; comments,
    /// the prolog and the DOCTYPE are skipped.
    fn tags_balance(xml: &str) -> bool {
        let mut stack: Vec<&str> = Vec::new();
        let mut rest = xml;
        while let Some(i) = rest.find('<') {
            rest = &rest[i..];
            let comment = rest.starts_with("<!--");
            let close = if comment { "-->" } else { ">" };
            let Some(end) = rest.find(close) else {
                return false;
            };
            // XML forbids `--` inside a comment; polkit's parser would
            // reject the whole file.
            if comment && rest[4..end].contains("--") {
                return false;
            }
            let tag = &rest[1..end];
            rest = &rest[end + close.len()..];
            if tag.starts_with('?') || tag.starts_with('!') {
                continue;
            }
            if let Some(name) = tag.strip_prefix('/') {
                if stack.pop() != Some(name.trim()) {
                    return false;
                }
            } else if !tag.ends_with('/') {
                stack.push(tag.split_whitespace().next().unwrap_or(""));
            }
        }
        stack.is_empty()
    }
}
