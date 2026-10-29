// daemon_session/login.rs — unlocking at login and changing the store
// passphrase (T13.25).
//
// `LoginUnlock` is what `kepr pam-unlock` sends with the password typed at
// a login or a screen unlock (pam_kepr.so). Unlike `Unlock` it is user mode
// only; it leaves an unlocked store alone without trying the password; its
// failures go to the login budget (unlock_guard.rs: never the wipe, closed
// after `login_unlock::MAX_FAILURES`); and it never undoes `kepr panic`: a
// store locked on purpose stays locked until `kepr unlock`. Start-up, the
// idle timer and the sleep / screen-lock watcher lock the store so that
// the next login opens it again; that is what this request is for.
//
// `ChangePassphrase` wraps the master key under a new passphrase after
// checking the old one: `kepr passwd`, or (`login`) the PAM password hook
// keeping the store passphrase equal to the login password. Root only in
// system mode. A store whose passphrase goes with a FIDO2 key is refused:
// neither path can supply the key's factor.

use std::sync::atomic::{AtomicBool, Ordering};

use kepr_core::protocol::Response;
use kepr_core::protocol_session::SessionResponse;

use super::{audit_op, unlock_guard, unlock_wait};
use crate::daemon_seal::fido2_kek;
use crate::{crypto, key_unlock};

/// Longest passphrase `ChangePassphrase` sets (what pam_kepr passes on).
const MAX_PASSPHRASE: usize = 1024;

const USER_MODE_ONLY: &str =
    "login unlock is for a user-mode store; the system store is unlocked by root";
const NOT_PROTECTED: &str = "credential store is not password protected";

static PANICKED: AtomicBool = AtomicBool::new(false);

/// `kepr panic` locked the store: only `kepr unlock` reopens it.
pub fn panicked() {
    PANICKED.store(true, Ordering::SeqCst);
}

/// A passphrase unlock (`kepr unlock`) succeeded.
pub fn unlocked() {
    PANICKED.store(false, Ordering::SeqCst);
}

/// What a `LoginUnlock` does with the store as it is.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    AlreadyOpen,
    Refuse(&'static str),
    Try,
}

pub fn plan(user_mode: bool, locked: bool, panicked: bool, envelope: Option<&[u8]>) -> Plan {
    if !user_mode {
        return Plan::Refuse(USER_MODE_ONLY);
    }
    if !locked {
        return Plan::AlreadyOpen;
    }
    if panicked {
        return Plan::Refuse("kepr was locked with `kepr panic`; unlock it with `kepr unlock`");
    }
    match envelope {
        None => Plan::Refuse(NOT_PROTECTED),
        Some(e) if fido2_kek::is_fido2(e) => {
            Plan::Refuse("this store needs its security key; unlock it with `kepr unlock`")
        }
        Some(_) => Plan::Try,
    }
}

pub fn handle_login_unlock(uid: u32, username: &str, password: &[u8]) -> Response {
    let r = login_unlock(password);
    unlock_wait::end_grace(); // whatever happened, no other login unlock is coming
    audit_op(
        "login-unlock",
        None,
        uid,
        username,
        r.as_ref().map(|_| ()).map_err(String::as_str),
    );
    match r {
        Ok(()) => Response::UnlockedOk,
        Err(e) => Response::fail(e),
    }
}

fn login_unlock(password: &[u8]) -> Result<(), String> {
    if password.is_empty() {
        return Err("password cannot be empty".into());
    }
    let path = crate::protected_master_key_path();
    let envelope = std::fs::read(&path).ok();
    match plan(
        crate::user_mode(),
        crypto::backend_is_locked(),
        PANICKED.load(Ordering::SeqCst),
        envelope.as_deref(),
    ) {
        Plan::AlreadyOpen => return Ok(()),
        Plan::Refuse(e) => return Err(e.into()),
        Plan::Try => {}
    }
    let _busy = unlock_wait::Unlocking::begin();
    let key = unlock_guard::unwrap_login(password)?;
    match crypto::unlock_backend(&key) {
        Ok(()) => key_unlock::upgrade_at(&path, password, &key),
        // A `kepr unlock` got there first.
        Err(_) if !crypto::backend_is_locked() => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

/// The refusals that need no passphrase check.
pub fn check_change(
    (user_mode, uid, login): (bool, u32, bool),
    (old, new): (&[u8], &[u8]),
    envelope: Option<&[u8]>,
) -> Result<(), String> {
    if !user_mode && login {
        return Err(USER_MODE_ONLY.into());
    }
    if !user_mode && uid != 0 {
        return Err("only root may change the shared store's passphrase".into());
    }
    if old.is_empty() || new.is_empty() {
        return Err("password cannot be empty".into());
    }
    if new.len() > MAX_PASSPHRASE {
        return Err(format!(
            "the new passphrase is too long (at most {MAX_PASSPHRASE} bytes)"
        ));
    }
    if kepr_core::seal_factor::split_factor(new)?.0.is_some() {
        return Err("the new passphrase cannot carry a security-key factor".into());
    }
    match envelope {
        None => Err(NOT_PROTECTED.into()),
        Some(e) if fido2_kek::is_fido2(e) => {
            Err("this store's passphrase goes with a security key; it can't be changed here".into())
        }
        Some(_) => Ok(()),
    }
}

pub fn handle_change(
    uid: u32,
    username: &str,
    (old, new): (&[u8], &[u8]),
    login: bool,
) -> Response {
    let r = change(uid, username, (old, new), login);
    let op = if login {
        "login-passphrase-change"
    } else {
        "passphrase-change"
    };
    audit_op(
        op,
        None,
        uid,
        username,
        r.as_ref().map(|_| ()).map_err(String::as_str),
    );
    match r {
        Ok(()) => Response::Session(SessionResponse::PassphraseChanged),
        Err(e) => Response::fail(e),
    }
}

fn change(uid: u32, username: &str, (old, new): (&[u8], &[u8]), login: bool) -> Result<(), String> {
    let envelope = std::fs::read(crate::protected_master_key_path()).ok();
    check_change(
        (crate::user_mode(), uid, login),
        (old, new),
        envelope.as_deref(),
    )?;
    let key = if login {
        unlock_guard::unwrap_login(old)?
    } else {
        unlock_guard::unwrap_guarded(old, uid, username)?
    };
    // An unlocked store must be running on this very key; a replaced
    // envelope would not be.
    if let Ok(running) = crypto::snapshot_key() {
        if !kepr_core::http_lite::ct_eq(running.as_ref(), key.as_ref()) {
            return Err(
                "the passphrase opens another key than the running one; restart kepr-daemon".into(),
            );
        }
    }
    let envelope = key_unlock::wrap(&key, new)?;
    crate::daemon_lock::write_protected_master_key(&envelope) // atomic; resets both budgets
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW3: &[u8] = b"kepr_pw3\n...";
    const PW2: &[u8] = b"kepr_pw2\n...";

    #[test]
    fn a_login_unlock_plan_for_every_state() {
        assert_eq!(plan(true, false, false, Some(PW3)), Plan::AlreadyOpen);
        // Unlocked: nothing is tried, even after a panic was undone.
        assert_eq!(plan(true, false, true, None), Plan::AlreadyOpen);
        assert_eq!(plan(true, true, false, Some(PW3)), Plan::Try);
        assert_eq!(
            plan(false, true, false, Some(PW3)),
            Plan::Refuse(USER_MODE_ONLY)
        );
        let Plan::Refuse(e) = plan(true, true, true, Some(PW3)) else {
            panic!("a panic lock was undone by a login")
        };
        assert!(e.contains("kepr unlock"));
        assert_eq!(plan(true, true, false, None), Plan::Refuse(NOT_PROTECTED));
        let Plan::Refuse(e) = plan(true, true, false, Some(PW2)) else {
            panic!("tried a FIDO2 store without its key")
        };
        assert!(e.contains("security key"));
    }

    #[test]
    fn the_panic_flag_is_cleared_by_a_passphrase_unlock() {
        panicked();
        assert!(PANICKED.load(Ordering::SeqCst));
        unlocked();
        assert!(!PANICKED.load(Ordering::SeqCst));
    }

    #[test]
    fn change_refusals_before_any_check() {
        let ok = |m, u, l| check_change((m, u, l), (b"old", b"new"), Some(PW3));
        assert!(ok(true, 1000, false).is_ok());
        assert!(ok(true, 1000, true).is_ok());
        assert!(ok(false, 0, false).is_ok(), "root on the system store");
        assert!(ok(false, 1000, false).unwrap_err().contains("only root"));
        assert_eq!(ok(false, 0, true).unwrap_err(), USER_MODE_ONLY);
        let args = (true, 1000, false);
        assert!(check_change(args, (b"", b"n"), Some(PW3)).is_err());
        assert!(check_change(args, (b"o", b""), Some(PW3)).is_err());
        let long = vec![b'a'; MAX_PASSPHRASE + 1];
        assert!(check_change(args, (b"o", &long), Some(PW3))
            .unwrap_err()
            .contains("too long"));
        assert_eq!(
            check_change(args, (b"o", b"n"), None).unwrap_err(),
            NOT_PROTECTED
        );
        assert!(check_change(args, (b"o", b"n"), Some(PW2))
            .unwrap_err()
            .contains("security key"));
        let factor = b"\x01fido2:AAAA:AAAA:AAAA\x01pw";
        assert!(check_change(args, (b"o", factor), Some(PW3)).is_err());
    }
}
