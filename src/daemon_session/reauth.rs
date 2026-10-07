// daemon_session/reauth.rs — re-authentication before reveal (T11.14).
//
// A credential whose `.meta` says `requires_reauth` is only returned by
// `Get` (and so `copy`, `exec`, `kepr://` notation, `record show
// --reveal`, `share send`, one-time links) and its attachments are only
// read while a reveal window is open for it: `Reauth { name, passphrase }`
// checks the store passphrase through `unlock_guard` (same backoff,
// counter and opt-in wipe as `kepr unlock`) and opens a 60 s window for
// that (uid, credential). Without one, `Get` answers exactly
// `REAUTH_NEEDED` so the CLI knows to ask; every other refusal stays
// "credential unavailable". Fail closed: an unreadable `.meta` is refused
// by the existing gate before this one is consulted. Readers that can't
// prompt (search, dupes, history diff, health) skip the value entirely.
//
// The flag is sticky: `set` keeps it (`carry_over`), so overwriting and
// then restoring a history version can't drop it; only `ReauthFlag {
// on: false }` with an open window clears it. It needs a passphrase-
// protected store, and in system mode only root (the store passphrase is
// root's; other users must not drive its backoff or wipe). Sealed, SSH
// and share-key credentials are never revealed, so the flag is refused.

use std::time::{Duration, Instant};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_session::{SessionResponse, REAUTH_NEEDED, REAUTH_WINDOW_SECS};

use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};

pub use kepr_core::protocol_session::REAUTH_NEEDED as NEEDED;

const WINDOW: Duration = Duration::from_secs(REAUTH_WINDOW_SECS);

/// Open reveal windows: (uid, credential, closes at).
pub struct Windows(Vec<(u32, String, Instant)>);

impl Windows {
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    pub fn open(&mut self, uid: u32, name: &str, now: Instant) {
        self.0
            .retain(|(u, n, until)| *until > now && !(*u == uid && n == name));
        self.0.push((uid, name.to_string(), now + WINDOW));
    }

    pub fn is_open(&self, uid: u32, name: &str, now: Instant) -> bool {
        self.0
            .iter()
            .any(|(u, n, until)| *u == uid && n == name && now < *until)
    }
}

static WINDOWS: std::sync::Mutex<Windows> = std::sync::Mutex::new(Windows::new());

fn windows() -> std::sync::MutexGuard<'static, Windows> {
    WINDOWS.lock().unwrap_or_else(|p| p.into_inner())
}

/// Is a reveal window open for `uid`'s `upper` right now?
pub fn window_open(uid: u32, upper: &str) -> bool {
    windows().is_open(uid, upper, Instant::now())
}

/// The `Get` gate (pure): `Err(REAUTH_NEEDED)` while `meta` asks for
/// re-auth and no window is open.
pub fn gate(meta: &CredMeta, window_open: bool) -> Result<(), String> {
    if meta.requires_reauth == Some(true) && !window_open {
        return Err(REAUTH_NEEDED.into());
    }
    Ok(())
}

/// For reads that can't prompt (share send, one-time links): what to
/// say when `reason` is the re-auth refusal, else `generic`.
pub fn refusal(reason: &str, upper: &str, generic: &str) -> String {
    if reason == REAUTH_NEEDED {
        format!("{upper} needs the store passphrase: run `kepr reauth {upper}` first")
    } else {
        generic.to_string()
    }
}

/// `handle_set` hook: keep the flag across a value replacement (not onto
/// a value that is never revealed anyway).
pub fn carry_over(uid: u32, upper: &str, meta: &mut CredMeta) {
    if never_revealed(meta) {
        return;
    }
    if let Some(Ok(old)) = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))) {
        if old.requires_reauth == Some(true) {
            meta.requires_reauth = Some(true);
        }
    }
}

fn never_revealed(m: &CredMeta) -> bool {
    m.sealed == Some(true) || m.ssh.is_some() || m.share_key == Some(true)
}

/// Who may use the store passphrase: the owner in user mode, root in
/// system mode, and only on a passphrase-protected store.
fn may_reauth(uid: u32) -> Result<(), String> {
    if !crate::user_mode() && uid != 0 {
        return Err("re-authentication uses the store passphrase; only root has it here".into());
    }
    if !crate::protected_master_key_path().exists() {
        return Err("re-authentication needs a store passphrase first (kepr lock)".into());
    }
    Ok(())
}

/// Validate, uppercase and follow an alias: the window and the flag
/// belong to the credential `Get` actually reads.
fn target(uid: u32, name: &str) -> Result<String, String> {
    validate_name(name)?;
    Ok(crate::daemon_store::resolve_alias(
        uid,
        &name.to_uppercase(),
    ))
}

/// Validate `name`, run the passphrase `check` and open the window.
/// Returns the credential's name (for the audit line) and the outcome.
fn open_window(
    uid: u32,
    name: &str,
    check: impl FnOnce() -> Result<(), String>,
) -> (String, Result<(), String>) {
    let upper = match target(uid, name) {
        Ok(u) => u,
        Err(e) => return (name.to_uppercase(), Err(e)),
    };
    let r = if crate::store::cred_exists(uid, &upper) {
        check().map(|()| windows().open(uid, &upper, Instant::now()))
    } else {
        Err(crate::crypto::SANITIZED_LOOKUP_ERROR.to_string())
    };
    (upper, r)
}

pub fn handle_reauth(uid: u32, username: &str, name: &str, passphrase: &ZeroString) -> Response {
    let (upper, r) = open_window(uid, name, || {
        may_reauth(uid)?;
        if passphrase.as_str().is_empty() {
            return Err("password cannot be empty".to_string());
        }
        // Same backoff, failure counter and opt-in wipe as `kepr unlock`.
        crate::daemon_session::unlock_guard::unwrap_guarded(passphrase.as_bytes(), uid, username)
            .map(drop)
    });
    super::audit_op(
        "reauth",
        Some(&upper),
        uid,
        username,
        r.as_ref().map(drop).map_err(String::as_str),
    );
    match r {
        Ok(()) => Response::Session(SessionResponse::ReauthOk {
            name: upper,
            valid_secs: REAUTH_WINDOW_SECS,
        }),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_flag(uid: u32, username: &str, name: &str, on: bool) -> Response {
    let mut upper = name.to_uppercase();
    let r = (|| {
        upper = target(uid, name)?;
        let _lock = crate::daemon_credlock::lock(uid, &upper);
        if !crate::store::cred_exists(uid, &upper) {
            return Err(crate::crypto::SANITIZED_LOOKUP_ERROR.to_string());
        }
        let mp = expiry::meta_path_for(&cred_path(uid, &upper));
        let meta = match expiry::read_meta(&mp) {
            None => CredMeta::default(),
            Some(Ok(m)) => m,
            Some(Err(_)) => return Err("credential metadata unreadable".into()),
        };
        let new = flagged(
            meta.clone(),
            on,
            || window_open(uid, &upper),
            || may_reauth(uid),
        )?;
        if new != meta {
            if new.is_empty() {
                expiry::delete_meta(&mp);
            } else {
                expiry::write_meta(&mp, &new)?;
            }
        }
        Ok(())
    })();
    let op = if on { "reauth-on" } else { "reauth-off" };
    super::audit_op(
        op,
        Some(&upper),
        uid,
        username,
        r.as_ref().map(drop).map_err(String::as_str),
    );
    match r {
        Ok(()) => Response::Session(SessionResponse::ReauthFlagOk { name: upper, on }),
        Err(e) => Response::fail(e),
    }
}

/// `meta` with the flag set or cleared (pure policy). Setting it needs
/// a usable passphrase; clearing it needs an open window.
fn flagged(
    mut meta: CredMeta,
    on: bool,
    window_open: impl FnOnce() -> bool,
    may: impl FnOnce() -> Result<(), String>,
) -> Result<CredMeta, String> {
    if on {
        if never_revealed(&meta) {
            return Err(
                "this credential is never revealed; re-authentication doesn't apply".into(),
            );
        }
        may()?;
        meta.requires_reauth = Some(true);
    } else if meta.requires_reauth == Some(true) {
        if !window_open() {
            return Err(REAUTH_NEEDED.into());
        }
        meta.requires_reauth = None;
    }
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_session::unlock_guard::{self, Paths, Refusal};
    use zeroize::Zeroizing;

    #[test]
    fn missing_reauth_is_refused_with_the_exact_marker() {
        let m = CredMeta {
            requires_reauth: Some(true),
            ..Default::default()
        };
        assert_eq!(gate(&m, false), Err("reauth needed".to_string()));
        assert_eq!(gate(&m, true), Ok(()));
        assert_eq!(gate(&CredMeta::default(), false), Ok(()));
    }

    #[test]
    fn a_window_lasts_sixty_seconds_per_credential_and_uid() {
        let t0 = Instant::now();
        let mut w = Windows::new();
        assert!(!w.is_open(1, "A", t0));
        w.open(1, "A", t0);
        assert!(w.is_open(1, "A", t0 + Duration::from_secs(59)));
        assert!(!w.is_open(1, "A", t0 + Duration::from_secs(60)));
        assert!(!w.is_open(1, "B", t0), "per credential");
        assert!(!w.is_open(2, "A", t0), "per uid");
        // Re-opening extends it; expired windows are dropped.
        w.open(1, "A", t0 + Duration::from_secs(50));
        assert!(w.is_open(1, "A", t0 + Duration::from_secs(100)));
        w.open(1, "B", t0 + Duration::from_secs(200));
        assert_eq!(w.0.len(), 1);
    }

    /// The passphrase check is `unlock_guard`'s: a wrong one is refused
    /// and counted (so it backs off), a right one returns the key.
    #[test]
    fn wrong_passphrase_is_refused_and_counted() {
        fn fake(env: &[u8], pw: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
            (env == pw)
                .then(|| Zeroizing::new([1; 32]))
                .ok_or("x".into())
        }
        let dir = tempfile::tempdir().unwrap();
        let p = Paths {
            state: dir.path().join("g.json"),
            envelope: dir.path().join("env"),
        };
        std::fs::write(&p.envelope, b"right").unwrap();
        let r = unlock_guard::unwrap_at(&p, (100, None), b"wrong", fake);
        assert_eq!(r.err(), Some(Refusal::Wrong { wiped: false }));
        let r = unlock_guard::unwrap_at(&p, (100, None), b"right", fake);
        assert_eq!(r.err(), Some(Refusal::Wait(1)), "counted: backing off");
        assert!(unlock_guard::unwrap_at(&p, (101, None), b"right", fake).is_ok());
    }

    #[test]
    fn flag_policy() {
        let ok = || Ok(());
        let on = flagged(CredMeta::default(), true, || false, ok).unwrap();
        assert_eq!(on.requires_reauth, Some(true));
        // Clearing needs an open window.
        assert_eq!(
            flagged(on.clone(), false, || false, ok).unwrap_err(),
            REAUTH_NEEDED
        );
        assert_eq!(
            flagged(on, false, || true, ok).unwrap(),
            CredMeta::default()
        );
        // No passphrase / not root: refused.
        assert!(flagged(CredMeta::default(), true, || true, || Err("no".into())).is_err());
        let sealed = CredMeta {
            sealed: Some(true),
            ..Default::default()
        };
        assert!(flagged(sealed, true, || true, ok).is_err());
    }

    #[test]
    fn set_keeps_the_flag_but_not_onto_a_sealed_value() {
        use crate::daemon_store::testkit;
        let uid = testkit::uid();
        testkit::set(uid, "RA_A", "v1");
        let mp = expiry::meta_path_for(&cred_path(uid, "RA_A"));
        let flagged = CredMeta {
            requires_reauth: Some(true),
            ..Default::default()
        };
        expiry::write_meta(&mp, &flagged).unwrap();
        testkit::set(uid, "RA_A", "v2");
        assert_eq!(testkit::meta(uid, "RA_A").requires_reauth, Some(true));
        testkit::set_sealed(uid, "RA_A", "v3");
        assert_eq!(testkit::meta(uid, "RA_A").requires_reauth, None);
    }

    /// Get, an alias of it, attachments and share sends all need the
    /// window; a failed passphrase check opens none.
    #[test]
    fn every_read_needs_a_window() {
        use crate::daemon_store::testkit;
        use kepr_core::protocol_records::{RecordsRequest, RecordsResponse};
        use kepr_core::protocol_store::StoreRequest;
        let uid = testkit::uid();
        testkit::set(uid, "RA_G", "v");
        let put = RecordsRequest::AttachPut {
            name: "RA_G".into(),
            file: "f".into(),
            upload: None,
            index: 0,
            chunk: ZeroString::from_string("c2VjcmV0".into()),
            last: true,
        };
        assert!(crate::daemon_recordsx::dispatch(uid, 0, "t", put).is_success());
        let link = StoreRequest::Link {
            alias: "RA_L".into(),
            target: "RA_G".into(),
        };
        assert!(crate::daemon_store::dispatch(uid, 0, "t", link).is_success());
        let mut m = testkit::meta(uid, "RA_G");
        m.requires_reauth = Some(true);
        expiry::write_meta(&expiry::meta_path_for(&cred_path(uid, "RA_G")), &m).unwrap();

        let get = |n| crate::daemon_handlers_get::handle_get(uid, 0, "t", n, None);
        let attach = || {
            let r = RecordsRequest::AttachGet {
                name: "RA_G".into(),
                file: "f".into(),
                index: 0,
            };
            crate::daemon_recordsx::dispatch(uid, 0, "t", r)
        };
        let share = || crate::daemon_share::new_payload((uid, 0), "RA_G", None).map(drop);
        let closed = || {
            assert_eq!(get("RA_G").err_msg(), Some(REAUTH_NEEDED));
            assert_eq!(get("RA_L").err_msg(), Some(REAUTH_NEEDED));
            assert_eq!(attach().err_msg(), Some(REAUTH_NEEDED));
            assert!(share().unwrap_err().contains("kepr reauth RA_G"));
        };
        closed();
        let (n, r) = open_window(uid, "ra_l", || Err("invalid password".into()));
        assert_eq!((n.as_str(), r), ("RA_G", Err("invalid password".into())));
        closed();
        let (_, r) = open_window(uid, "RA_NOPE", || Ok(()));
        assert_eq!(r.unwrap_err(), crate::crypto::SANITIZED_LOOKUP_ERROR);
        // Through the alias: the window belongs to the target.
        assert_eq!(open_window(uid, "ra_l", || Ok(())).1, Ok(()));
        assert!(matches!(get("RA_G"), Response::GetOk { .. }));
        assert!(matches!(get("RA_L"), Response::GetOk { .. }));
        assert!(matches!(
            attach(),
            Response::Records(RecordsResponse::AttachChunkOk { .. })
        ));
        assert!(share().is_ok());
    }

    #[test]
    fn readers_that_cannot_prompt_skip_it() {
        let m = CredMeta {
            requires_reauth: Some(true),
            ..Default::default()
        };
        assert!(!crate::daemon_store::files::readable_without_prompt(&m, 0));
        assert_eq!(refusal("expired", "K", "generic"), "generic");
    }
}
