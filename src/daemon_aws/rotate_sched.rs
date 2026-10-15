// daemon_aws/rotate_sched.rs — scheduled rotation (T7.07).
//
// `kepr rotate NAME --every 30d --hook CMD | --aws-iam | --db` stores a
// schedule in the credential's `.meta` (`rotate_every_secs`, `rotate_via`,
// `rotate_next_at`). The sweeper (daemon_expiry.rs) calls `sweep` every
// minute; in user mode it runs each due rotation by spawning
// `kepr rotate NAME --scheduled` as the user, so the rotators and their
// network code stay in the CLI. The rotators commit through `set`, which
// keeps the schedule and restarts its clock (`carry_over`); a failure
// leaves the value alone and retries with backoff (15 min, doubling, at
// most a day or the interval). The system daemon (root) never runs user
// hooks: there the schedule is shown and `--scheduled` runs it by hand.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kepr_core::protocol::Response;
use kepr_core::protocol_aws::{
    valid_rotate_via, AwsResponse, ROTATE_EVERY_MAX_SECS, ROTATE_EVERY_MIN_SECS,
};

use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};

const FIRST_RETRY_SECS: u64 = 15 * 60;
const MAX_RETRY_SECS: u64 = 86_400;
const RUN_TIMEOUT: Duration = Duration::from_secs(600);

/// Is a scheduled rotation due at `now`?
pub fn due(m: &CredMeta, now: u64) -> bool {
    m.rotate_every_secs.is_some()
        && m.rotate_via.is_some()
        && m.rotate_next_at.is_some_and(|t| t <= now)
}

/// The wait after the `failures`-th failed try in a row.
pub fn backoff_secs(failures: u32, every: u64) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    (FIRST_RETRY_SECS << doublings)
        .min(MAX_RETRY_SECS)
        .min(every)
}

fn meta_path(uid: u32, upper: &str) -> PathBuf {
    expiry::meta_path_for(&cred_path(uid, upper))
}

/// `handle_set` hook: a new value keeps the schedule and restarts it.
pub fn carry_over(uid: u32, upper: &str, meta: &mut CredMeta, now: u64) {
    let Some(Ok(old)) = expiry::read_meta(&meta_path(uid, upper)) else {
        return;
    };
    if let (Some(every), Some(via)) = (old.rotate_every_secs, old.rotate_via) {
        meta.rotate_every_secs = Some(every);
        meta.rotate_via = Some(via);
        meta.rotate_next_at = Some(now.saturating_add(every));
        meta.rotate_failures = None;
    }
}

/// What may be scheduled on this credential, given how it rotates.
fn check_kind(m: &CredMeta, via: &str) -> Result<(), String> {
    let unreadable = m.sealed == Some(true) || m.ssh.is_some() || m.share_key.is_some();
    let db_login = m
        .bindings
        .iter()
        .flatten()
        .any(|b| b.inject.db_kind().is_some());
    match via {
        "db" if !(m.sealed == Some(true) && db_login) => {
            Err("--db rotates sealed database logins only (kepr agent add-db)".into())
        }
        "db" => Ok(()),
        _ if unreadable => {
            Err("this credential can't be read, so a hook or --aws-iam can't rotate it".into())
        }
        _ => Ok(()),
    }
}

fn schedule(
    uid: u32,
    upper: &str,
    every: Option<u64>,
    via: Option<&str>,
    now: u64,
) -> Result<Option<u64>, String> {
    let _lock = crate::daemon_credlock::lock(uid, upper);
    if !crate::store::cred_exists(uid, upper) {
        return Err(crate::crypto::SANITIZED_LOOKUP_ERROR.into());
    }
    let mp = meta_path(uid, upper);
    let mut m = match expiry::read_meta(&mp) {
        None => CredMeta::default(),
        Some(Ok(m)) => m,
        Some(Err(_)) => return Err("credential metadata unreadable".into()),
    };
    let next = match (every, via) {
        (None, None) => None,
        (Some(e), Some(v)) => {
            if !(ROTATE_EVERY_MIN_SECS..=ROTATE_EVERY_MAX_SECS).contains(&e) {
                return Err("--every must be between 1 hour and 10 years".into());
            }
            if !valid_rotate_via(v) {
                return Err("rotate with --hook /absolute/path, --aws-iam or --db".into());
            }
            check_kind(&m, v)?;
            Some((e, v.to_string(), now.saturating_add(e)))
        }
        _ => return Err("--every needs a way to rotate: --hook CMD, --aws-iam or --db".into()),
    };
    m.rotate_every_secs = next.as_ref().map(|n| n.0);
    m.rotate_via = next.as_ref().map(|n| n.1.clone());
    m.rotate_next_at = next.as_ref().map(|n| n.2);
    m.rotate_failures = None;
    if m.is_empty() {
        expiry::delete_meta(&mp);
    } else {
        expiry::write_meta(&mp, &m)?;
    }
    Ok(next.map(|n| n.2))
}

pub fn handle_schedule(
    uid: u32,
    username: &str,
    name: &str,
    every: Option<u64>,
    via: Option<&str>,
) -> Response {
    let upper = name.to_uppercase();
    let r = validate_name(name).and_then(|_| schedule(uid, &upper, every, via, expiry::now_unix()));
    let op = if every.is_some() {
        "rotate-schedule"
    } else {
        "rotate-unschedule"
    };
    super::audit_op(op, &upper, uid, username, r.as_ref().map(drop));
    match r {
        Ok(next_at) => Response::Aws(AwsResponse::AwsRotateScheduled {
            name: upper,
            next_at,
        }),
        Err(e) => Response::fail(e),
    }
}

/// After a scheduled try: on success make sure the clock moved (the
/// rotator's `set` normally did); on failure count it and back off.
fn record(uid: u32, upper: &str, now: u64, result: &Result<(), String>) {
    let username = crate::audit::username_for_uid(uid);
    super::audit_op(
        "rotate-scheduled",
        upper,
        uid,
        &username,
        result.as_ref().map(drop),
    );
    let _lock = crate::daemon_credlock::lock(uid, upper);
    let mp = meta_path(uid, upper);
    let Some(Ok(mut m)) = expiry::read_meta(&mp) else {
        return;
    };
    let Some(every) = m.rotate_every_secs else {
        return;
    };
    match result {
        Ok(()) if m.rotate_next_at.is_some_and(|t| t <= now) => {
            m.rotate_next_at = Some(now.saturating_add(every));
            m.rotate_failures = None;
        }
        Ok(()) => return,
        Err(_) => {
            let f = m.rotate_failures.unwrap_or(0).saturating_add(1);
            m.rotate_failures = Some(f);
            m.rotate_next_at = Some(now.saturating_add(backoff_secs(f, every)));
        }
    }
    if let Err(e) = expiry::write_meta(&mp, &m) {
        eprintln!("[kepr-daemon] rotate schedule: meta write: {e}");
    }
}

/// Run every due rotation of `uid` with `run`; how many ran.
pub fn run_due(uid: u32, now: u64, run: &dyn Fn(&str) -> Result<(), String>) -> usize {
    let mut ran = 0;
    for (name, _) in crate::store::list_for_uid(uid) {
        let is_due =
            matches!(expiry::read_meta(&meta_path(uid, &name)), Some(Ok(m)) if due(&m, now));
        if !is_due {
            continue;
        }
        let r = run(&name);
        record(uid, &name, now, &r);
        ran += 1;
    }
    ran
}

fn kepr_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("KEPR_BIN") {
        return PathBuf::from(p);
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| Some(e.parent()?.join("kepr")))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/kepr"))
}

/// `kepr rotate NAME --scheduled` as this (user-mode) daemon's user.
/// Its output is discarded: a hook may print what it rotates.
fn run_cli(name: &str) -> Result<(), String> {
    let mut child = Command::new(kepr_bin())
        .args(["rotate", name, "--scheduled"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn kepr: {e}"))?;
    let deadline = Instant::now() + RUN_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => return Ok(()),
            Ok(Some(st)) => return Err(format!("rotation exited with {st}")),
            Ok(None) if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("rotation timed out".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_secs(1)),
            Err(e) => return Err(format!("wait: {e}")),
        }
    }
}

static RUNNING: AtomicBool = AtomicBool::new(false);

/// Sweeper hook: run due rotations on a thread of their own (user mode
/// only; at most one batch at a time).
pub fn sweep(now: u64) {
    if !crate::user_mode() || RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let uid = crate::daemon_socket::effective_uid();
    let spawned = std::thread::Builder::new()
        .name("kepr-rotate".into())
        .spawn(move || {
            run_due(uid, now, &run_cli);
            RUNNING.store(false, Ordering::SeqCst);
        });
    if spawned.is_err() {
        RUNNING.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    const DAY: u64 = 86_400;

    fn sched(uid: u32, name: &str, every: Option<u64>, via: Option<&str>) -> Response {
        handle_schedule(uid, "t", name, every, via)
    }

    fn make_due(uid: u32, name: &str, at: u64) {
        let mp = meta_path(uid, name);
        let mut m = testkit::meta(uid, name);
        m.rotate_next_at = Some(at);
        expiry::write_meta(&mp, &m).unwrap();
    }

    #[test]
    fn due_and_backoff() {
        let m = CredMeta {
            rotate_every_secs: Some(30 * DAY),
            rotate_via: Some("aws-iam".into()),
            rotate_next_at: Some(100),
            ..Default::default()
        };
        assert!(!due(&m, 99) && due(&m, 100) && due(&m, 5000));
        assert!(!due(&CredMeta::default(), u64::MAX));
        let unscheduled = CredMeta {
            rotate_via: None,
            ..m.clone()
        };
        assert!(!due(&unscheduled, 5000));
        let b: Vec<u64> = (1..=9).map(|f| backoff_secs(f, 30 * DAY)).collect();
        assert_eq!(b[..4], [900, 1800, 3600, 7200]);
        assert_eq!(b[8], DAY, "capped at a day");
        assert_eq!(backoff_secs(5, 3600), 3600, "never beyond the interval");
        assert_eq!(backoff_secs(u32::MAX, 30 * DAY), DAY);
    }

    #[test]
    fn schedule_is_validated_and_shown_by_list() {
        let uid = testkit::uid();
        testkit::set(uid, "K", "old");
        assert!(sched(uid, "K", Some(60), Some("aws-iam"))
            .err_msg()
            .is_some());
        assert!(sched(uid, "K", Some(DAY), Some("hook:hex:rel.sh"))
            .err_msg()
            .is_some());
        assert!(sched(uid, "K", Some(DAY), None).err_msg().is_some());
        assert!(sched(uid, "K", Some(DAY), Some("db")).err_msg().is_some());
        assert!(sched(uid, "NOPE", Some(DAY), Some("aws-iam"))
            .err_msg()
            .is_some());
        let before = expiry::now_unix();
        match sched(uid, "K", Some(DAY), Some("hook:hex:/bin/true")) {
            Response::Aws(AwsResponse::AwsRotateScheduled { next_at, .. }) => {
                assert!(next_at.unwrap() >= before + DAY)
            }
            other => panic!("{other:?}"),
        }
        let list = crate::daemon_handlers_list::handle_list(uid, "t");
        let Response::ListOk { credentials, .. } = list else {
            panic!("list");
        };
        let k = credentials.iter().find(|c| c.name == "K").unwrap();
        assert_eq!(k.rotate_every_secs, Some(DAY));
        assert_eq!(k.rotate_via.as_deref(), Some("hook:hex:/bin/true"));
        assert!(k.rotate_next_at.is_some());
        testkit::set_sealed(uid, "S", "v");
        assert!(sched(uid, "S", Some(DAY), Some("aws-iam"))
            .err_msg()
            .is_some());
        assert!(sched(uid, "K", None, None).is_success());
        assert!(testkit::meta(uid, "K").rotate_via.is_none());
    }

    #[test]
    fn a_failed_rotation_keeps_the_old_value_and_backs_off() {
        let uid = testkit::uid();
        testkit::set(uid, "K", "old");
        assert!(sched(uid, "K", Some(30 * DAY), Some("aws-iam")).is_success());
        let now = expiry::now_unix();
        assert_eq!(run_due(uid, now, &|_| panic!("not due yet")), 0);
        make_due(uid, "K", now);
        let fail = |_: &str| -> Result<(), String> { Err("rotation exited with 1".into()) };
        assert_eq!(run_due(uid, now, &fail), 1);
        assert_eq!(testkit::value(uid, "K").as_deref(), Some("old"));
        let m = testkit::meta(uid, "K");
        assert_eq!(
            (m.rotate_failures, m.rotate_next_at),
            (Some(1), Some(now + 900))
        );
        assert_eq!(run_due(uid, now + 899, &fail), 0, "waits out the backoff");
        assert_eq!(run_due(uid, now + 900, &fail), 1);
        let m = testkit::meta(uid, "K");
        assert_eq!(
            (m.rotate_failures, m.rotate_next_at),
            (Some(2), Some(now + 900 + 1800))
        );
    }

    #[test]
    fn a_successful_rotation_restarts_the_clock_through_set() {
        let uid = testkit::uid();
        testkit::set(uid, "K", "old");
        assert!(sched(uid, "K", Some(DAY), Some("hook:hex:/bin/true")).is_success());
        let now = expiry::now_unix();
        make_due(uid, "K", now);
        let rotate = |name: &str| -> Result<(), String> {
            testkit::set(uid, name, "new");
            Ok(())
        };
        assert_eq!(run_due(uid, now, &rotate), 1);
        assert_eq!(testkit::value(uid, "K").as_deref(), Some("new"));
        let m = testkit::meta(uid, "K");
        assert!(m.rotate_next_at.unwrap() >= now + DAY);
        assert_eq!(m.rotate_failures, None);
        assert_eq!(m.rotate_via.as_deref(), Some("hook:hex:/bin/true"));
        // A rotator that exits 0 without a `set` still moves the clock.
        make_due(uid, "K", now);
        assert_eq!(run_due(uid, now, &|_| Ok(())), 1);
        assert_eq!(testkit::meta(uid, "K").rotate_next_at, Some(now + DAY));
    }
}
