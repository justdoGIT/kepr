// daemon_aws/checkout.rs — check-out / check-in (T7.11).
//
//   kepr checkout NAME [--for 2h]   take it: nobody else can take it
//   kepr checkin NAME [--rotate]    give it back (and rotate it first)
//
// A hold lives in the credential's `.meta` (`checkout`): the holder's
// uid, the SHA-256 of a token the daemon mints and returns once, and a
// deadline. A second checkout is refused while a hold is live, and only
// the token checks it back in — a different session, which never saw the
// token, can't release someone else's hold. Every hold runs out
// (`HOLD_MAX_SECS`), so a lost token can't lock a credential for good,
// and the sweeper clears the spent ones; one with a rotation schedule is
// rotated on the next sweep (T12.51), as nobody vouched for the value.
//
// What it enforces: one holder, accountable check-in, and no reads by
// *another* uid (a shared credential) while a hold is live. It is not a
// sandbox against the holder's own uid, which can always read its own
// credentials; within one account a hold is the coordination marker it
// looks like, shown by `kepr list`. Nothing here prints a credential
// value, and the token is not one (it only releases the hold).

use kepr_core::protocol::Response;
use kepr_core::protocol_aws::{AwsResponse, Hold, HOLD_MAX_SECS};

use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

/// The hold still running at `now`, if any.
pub fn live(meta: &CredMeta, now: u64) -> Option<&Hold> {
    meta.checkout.as_ref().filter(|h| h.until > now)
}

/// Read policy: a live hold of *another* uid refuses the read. The
/// reason is audit-only; the caller answers "credential unavailable".
pub fn gate(meta: &CredMeta, uid: u32, now: u64) -> Result<(), String> {
    match live(meta, now) {
        Some(h) if h.uid != uid => Err(format!("checked out by uid {}", h.uid)),
        _ => Ok(()),
    }
}

fn token() -> Result<String, String> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(hex::encode(buf))
}

fn meta_of(uid: u32, upper: &str) -> Result<(std::path::PathBuf, CredMeta), String> {
    if !crate::store::cred_exists(uid, upper) {
        return Err(crate::crypto::SANITIZED_LOOKUP_ERROR.into());
    }
    let mp = expiry::meta_path_for(&cred_path(uid, upper));
    match expiry::read_meta(&mp) {
        None => Ok((mp, CredMeta::default())),
        Some(Ok(m)) => Ok((mp, m)),
        Some(Err(_)) => Err("credential metadata unreadable".into()),
    }
}

fn write(mp: &std::path::Path, m: &mut CredMeta) -> Result<(), String> {
    if m.is_empty() {
        expiry::delete_meta(mp);
        Ok(())
    } else {
        expiry::write_meta(mp, m)
    }
}

fn take(uid: u32, upper: &str, for_secs: u64, now: u64) -> Result<(String, u64), String> {
    if !(1..=HOLD_MAX_SECS).contains(&for_secs) {
        return Err("--for must be between 1 second and 24 hours".into());
    }
    let _lock = crate::daemon_credlock::lock(uid, upper);
    let (mp, mut m) = meta_of(uid, upper)?;
    if let Some(h) = live(&m, now) {
        let left = (h.until - now).div_ceil(60);
        return Err(if h.uid == uid {
            format!("{upper} is already checked out ({left} min left)")
        } else {
            format!("{upper} is checked out by uid {} ({left} min left)", h.uid)
        });
    }
    let t = token()?;
    let until = now.saturating_add(for_secs);
    m.checkout = Some(Hold {
        uid,
        token_sha256: sha256_hex(&t),
        until,
    });
    write(&mp, &mut m)?;
    // A held credential may be one a gate cached.
    crate::daemon_gate::bump_generation();
    Ok((t, until))
}

fn give_back(uid: u32, upper: &str, tok: &str, now: u64) -> Result<(), String> {
    let _lock = crate::daemon_credlock::lock(uid, upper);
    let (mp, mut m) = meta_of(uid, upper)?;
    let Some(h) = live(&m, now) else {
        return Err(format!("{upper} is not checked out"));
    };
    // One message for a wrong token and for someone else's hold: a
    // guess learns nothing about either.
    let ours = h.uid == uid
        && kepr_core::http_lite::ct_eq(h.token_sha256.as_bytes(), sha256_hex(tok).as_bytes());
    if !ours {
        return Err(format!(
            "{upper} was checked out by another session; it frees itself when the hold runs out"
        ));
    }
    m.checkout = None;
    write(&mp, &mut m)?;
    crate::daemon_gate::bump_generation();
    Ok(())
}

pub fn handle_checkout(uid: u32, username: &str, name: &str, for_secs: u64) -> Response {
    let upper = name.to_uppercase();
    let r = validate_name(name).and_then(|_| take(uid, &upper, for_secs, expiry::now_unix()));
    super::audit_op("checkout", &upper, uid, username, r.as_ref().map(drop));
    match r {
        Ok((token, until)) => Response::Aws(AwsResponse::AwsCheckedOut {
            name: upper,
            token,
            until,
        }),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_checkin(
    uid: u32,
    username: &str,
    name: &str,
    token: &str,
    rotated: bool,
) -> Response {
    let upper = name.to_uppercase();
    let r = validate_name(name).and_then(|_| give_back(uid, &upper, token, expiry::now_unix()));
    let op = if rotated {
        "checkin-rotated"
    } else {
        "checkin"
    };
    super::audit_op(op, &upper, uid, username, r.as_ref().map(drop));
    match r {
        Ok(()) => Response::Aws(AwsResponse::AwsCheckedIn {
            name: upper,
            rotated,
        }),
        Err(e) => Response::fail(e),
    }
}

/// `handle_set` hook: a rotated value keeps the hold, so the holder can
/// rotate it and *then* check it in (`kepr checkin --rotate`).
pub fn carry_over(uid: u32, upper: &str, meta: &mut CredMeta) {
    if let Some(Ok(old)) = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))) {
        meta.checkout = old.checkout;
    }
}

/// What a sweep did to one hold.
#[derive(Debug, PartialEq, Eq)]
pub enum Lapse {
    Live,
    Cleared,
    /// Cleared, and the credential's scheduled rotation is due now.
    ClearedRotate,
}

/// Clear a hold that has run out at `now` (T12.51). A value handed out
/// and never checked back in may still be in use somewhere, so when the
/// credential has a rotation schedule its rotation becomes due at once
/// (the user-mode sweeper runs it on its next tick).
pub fn lapse(m: &mut CredMeta, now: u64) -> Lapse {
    if m.checkout.as_ref().is_none_or(|h| h.until > now) {
        return Lapse::Live;
    }
    m.checkout = None;
    if m.rotate_every_secs.is_some() && m.rotate_via.is_some() {
        m.rotate_next_at = Some(now);
        return Lapse::ClearedRotate;
    }
    Lapse::Cleared
}

/// Sweeper: clear the holds that have run out, so `kepr list` and the
/// read gate don't carry a hold nobody has; each is audited as
/// `checkout-lapsed`.
pub fn sweep(uid: u32, now: u64) {
    for (name, path) in crate::store::list_for_uid(uid) {
        let mp = expiry::meta_path_for(&path);
        let spent = matches!(expiry::read_meta(&mp), Some(Ok(ref m))
            if m.checkout.as_ref().is_some_and(|h| h.until <= now));
        if !spent {
            continue;
        }
        let _lock = crate::daemon_credlock::lock(uid, &name);
        let Some(Ok(mut m)) = expiry::read_meta(&mp) else {
            continue;
        };
        if lapse(&mut m, now) == Lapse::Live {
            continue;
        }
        let r = write(&mp, &mut m);
        if let Err(e) = &r {
            eprintln!("[kepr-daemon] checkout sweep: {e}");
        }
        let user = crate::audit::username_for_uid(uid);
        super::audit_op("checkout-lapsed", &name, uid, &user, r.as_ref().map(drop));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn out(uid: u32, name: &str, secs: u64) -> Response {
        handle_checkout(uid, "t", name, secs)
    }

    fn token_of(r: Response) -> String {
        match r {
            Response::Aws(AwsResponse::AwsCheckedOut { token, .. }) => token,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_second_checkout_is_refused_and_only_the_token_checks_it_in() {
        let uid = testkit::uid();
        let other = testkit::uid();
        testkit::set(uid, "K", "v");
        assert!(out(uid, "NOPE", 60).err_msg().is_some());
        assert!(out(uid, "K", 0).err_msg().is_some());
        assert!(out(uid, "K", HOLD_MAX_SECS + 1).err_msg().is_some());
        let token = token_of(out(uid, "k", 3600));
        assert_eq!(token.len(), 64);
        let m = testkit::meta(uid, "K");
        assert_eq!(m.checkout.as_ref().map(|h| h.uid), Some(uid));
        assert_ne!(m.checkout.as_ref().unwrap().token_sha256, token);
        // Second checkout: refused, and the hold is untouched.
        let e = out(uid, "K", 60).err_msg().unwrap().to_string();
        assert!(e.contains("already checked out"), "{e}");
        assert_eq!(testkit::meta(uid, "K").checkout, m.checkout);
        // Another session has no token, so it can't release it.
        let e = handle_checkin(uid, "t", "K", &"0".repeat(64), false)
            .err_msg()
            .unwrap()
            .to_string();
        assert!(e.contains("another session"), "{e}");
        assert!(testkit::meta(uid, "K").checkout.is_some());
        // Another uid is refused the read while it is held.
        let m = testkit::meta(uid, "K");
        let now = expiry::now_unix();
        assert!(gate(&m, uid, now).is_ok());
        assert!(gate(&m, other, now).is_err());
        assert!(
            gate(&m, other, m.checkout.as_ref().unwrap().until).is_ok(),
            "run out"
        );
        let r = handle_checkin(uid, "t", "K", &token, true);
        assert!(matches!(
            r,
            Response::Aws(AwsResponse::AwsCheckedIn { rotated: true, .. })
        ));
        assert_eq!(testkit::meta(uid, "K").checkout, None);
        assert!(handle_checkin(uid, "t", "K", &token, false)
            .err_msg()
            .is_some());
        // Free again: the next session can take it.
        assert!(out(uid, "K", 60).is_success());
    }

    fn held(until: u64, scheduled: bool) -> CredMeta {
        CredMeta {
            checkout: Some(Hold {
                uid: 1,
                token_sha256: "00".repeat(32),
                until,
            }),
            rotate_every_secs: scheduled.then_some(86_400),
            rotate_via: scheduled.then(|| "aws-iam".to_string()),
            rotate_next_at: scheduled.then_some(9_999_999),
            ..Default::default()
        }
    }

    #[test]
    fn a_spent_hold_with_a_schedule_rotates_now() {
        let mut m = held(100, true);
        assert_eq!(lapse(&mut m, 100), Lapse::ClearedRotate);
        assert_eq!((m.checkout, m.rotate_next_at), (None, Some(100)));
    }

    #[test]
    fn a_spent_hold_without_a_schedule_is_only_cleared() {
        let mut m = held(100, false);
        assert_eq!(lapse(&mut m, 150), Lapse::Cleared);
        assert_eq!((m.checkout, m.rotate_next_at), (None, None));
        // A schedule needs both an interval and a rotator.
        let mut m = held(100, true);
        m.rotate_via = None;
        assert_eq!(lapse(&mut m, 150), Lapse::Cleared);
        assert_eq!(m.rotate_next_at, Some(9_999_999));
    }

    #[test]
    fn a_live_hold_lapses_nothing() {
        let mut m = held(100, true);
        let before = m.clone();
        assert_eq!(lapse(&mut m, 99), Lapse::Live);
        assert_eq!(m, before);
        let mut none = CredMeta::default();
        assert_eq!(lapse(&mut none, 99), Lapse::Live);
    }

    #[test]
    fn the_sweeper_queues_the_rotation_of_a_lapsed_scheduled_hold() {
        let uid = testkit::uid();
        testkit::set(uid, "R", "v");
        let mp = expiry::meta_path_for(&cred_path(uid, "R"));
        let mut m = testkit::meta(uid, "R");
        m.rotate_every_secs = Some(86_400);
        m.rotate_via = Some("aws-iam".into());
        m.rotate_next_at = Some(u64::MAX - 1);
        expiry::write_meta(&mp, &m).unwrap();
        let now = expiry::now_unix();
        let _ = token_of(out(uid, "R", 1));
        sweep(uid, now + 10);
        let m = testkit::meta(uid, "R");
        assert_eq!(m.checkout, None);
        assert_eq!(m.rotate_next_at, Some(now + 10));
        assert!(super::super::rotate_sched::due(&m, now + 10));
    }

    #[test]
    fn a_hold_runs_out_and_the_sweeper_clears_it() {
        let uid = testkit::uid();
        testkit::set(uid, "S", "v");
        let token = token_of(out(uid, "S", 1));
        let until = testkit::meta(uid, "S").checkout.unwrap().until;
        // Past the deadline it holds nothing, whoever asks.
        assert!(
            take(uid, "S", 60, until).is_ok(),
            "retaken after it ran out"
        );
        assert!(give_back(uid, "S", &token, until).is_err(), "old token");
        sweep(uid, expiry::now_unix());
        assert!(testkit::meta(uid, "S").checkout.is_some(), "still live");
        sweep(uid, u64::MAX);
        assert_eq!(testkit::meta(uid, "S").checkout, None);
        // `kepr checkin --rotate`: a new value keeps the hold, so the
        // holder's own token still checks it in afterwards.
        let token = token_of(out(uid, "S", 3600));
        testkit::set(uid, "S", "v2");
        assert!(testkit::meta(uid, "S").checkout.is_some());
        assert!(give_back(uid, "S", &token, expiry::now_unix()).is_ok());
    }
}
