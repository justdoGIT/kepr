// daemon_policy/approvals.rs — T9.04: consent prompts answered from a
// desktop notification or a phone instead of the polkit dialog.
//
// A credential opts in with `.meta` `approve_via` (desktop | ntfy | any;
// setting it needs a polkit approval, since it changes how consent is
// asked). The user runs `kepr approvals serve`, which registers once (a
// polkit approval again) and gets an approver key; from then on only that
// process (same SO_PEERCRED pid, same key) may poll and answer.
//
// When a consent-gated `get` / gate resolve arrives and a live approver
// is registered, the request waits here (like it waits for pkcheck) for
// an answer carrying the pending entry's one-time token; no answer by the
// deadline = deny. With no live approver it falls back to polkit.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use kepr_core::protocol_policy::PendingApproval;

/// How long a request waits for an answer.
pub const TIMEOUT: Duration = Duration::from_secs(60);
/// An approver that hasn't polled for this long is gone.
const STALE: Duration = Duration::from_secs(15);
/// Most requests waiting per user.
const MAX_PENDING: usize = 16;

struct Approver {
    pid: i32,
    key: Zeroizing<String>,
    last_poll: Instant,
}

struct Pending {
    id: String,
    token: Zeroizing<String>,
    uid: u32,
    name: String,
    via: String,
    requester: String,
    deadline: Instant,
    expires_at: u64,
    answer: Option<bool>,
}

#[derive(Default)]
struct Reg {
    approvers: HashMap<u32, Approver>,
    pending: Vec<Pending>,
}

static REG: Mutex<Option<Reg>> = Mutex::new(None);
static CV: Condvar = Condvar::new();

fn with<T>(f: impl FnOnce(&mut Reg) -> T) -> T {
    let mut g = REG.lock().unwrap_or_else(|p| p.into_inner());
    f(g.get_or_insert_with(Reg::default))
}

fn random_hex(n: usize) -> Result<String, String> {
    let mut b = Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut b).map_err(|_| "no randomness".to_string())?;
    Ok(hex::encode(&*b))
}

pub(super) fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Register the caller as `uid`'s approver once `granted()` (polkit)
/// says yes; returns its key. A new registration replaces the old one.
pub fn register(uid: u32, pid: i32, granted: impl FnOnce() -> bool) -> Result<String, String> {
    if !granted() {
        return Err("approval denied (polkit)".into());
    }
    let key = random_hex(32)?;
    with(|r| {
        r.approvers.insert(
            uid,
            Approver {
                pid,
                key: Zeroizing::new(key.clone()),
                last_poll: Instant::now(),
            },
        )
    });
    Ok(key)
}

fn check(r: &mut Reg, uid: u32, pid: i32, key: &str) -> Result<(), String> {
    match r.approvers.get_mut(&uid) {
        Some(a) if a.pid == pid && ct_eq(&a.key, key) => {
            a.last_poll = Instant::now();
            Ok(())
        }
        _ => Err("not the registered approver (run kepr approvals serve)".into()),
    }
}

/// The registered approver's view of what waits for an answer.
pub fn poll(uid: u32, pid: i32, key: &str) -> Result<Vec<PendingApproval>, String> {
    with(|r| {
        check(r, uid, pid, key)?;
        let now = Instant::now();
        Ok(r.pending
            .iter()
            .filter(|p| p.uid == uid && p.answer.is_none() && p.deadline > now)
            .map(|p| PendingApproval {
                id: p.id.clone(),
                token: p.token.to_string(),
                name: p.name.clone(),
                via: p.via.clone(),
                requester: p.requester.clone(),
                expires_at: p.expires_at,
            })
            .collect())
    })
}

/// Answer pending `id`; the token must be that entry's. Returns its name.
pub fn answer(
    uid: u32,
    pid: i32,
    key: &str,
    (id, token): (&str, &str),
    allow: bool,
) -> Result<String, String> {
    let name = with(|r| {
        check(r, uid, pid, key)?;
        let p = r
            .pending
            .iter_mut()
            .find(|p| p.uid == uid && p.id == id && p.answer.is_none())
            .filter(|p| ct_eq(&p.token, token))
            .ok_or("no such pending approval (answered or expired)")?;
        p.answer = Some(allow);
        Ok::<_, String>(p.name.clone())
    })?;
    CV.notify_all();
    Ok(name)
}

/// Ask the live approver about `name`; `None` when there is none (the
/// caller asks polkit instead). Blocks until answered or `timeout`.
pub fn ask(
    uid: u32,
    (name, via, requester): (&str, &str, String),
    timeout: Duration,
) -> Option<bool> {
    let id = random_hex(8).ok()?;
    let token = Zeroizing::new(random_hex(16).ok()?);
    let deadline = Instant::now() + timeout;
    let mut g = REG.lock().unwrap_or_else(|p| p.into_inner());
    let r = g.get_or_insert_with(Reg::default);
    let live = r
        .approvers
        .get(&uid)
        .is_some_and(|a| a.last_poll.elapsed() < STALE);
    if !live {
        return None;
    }
    r.pending.retain(|p| p.deadline > Instant::now());
    if r.pending.iter().filter(|p| p.uid == uid).count() >= MAX_PENDING {
        return Some(false);
    }
    r.pending.push(Pending {
        id: id.clone(),
        token,
        uid,
        name: name.to_string(),
        via: via.to_string(),
        requester,
        deadline,
        expires_at: crate::expiry::now_unix() + timeout.as_secs(),
        answer: None,
    });
    loop {
        let r = g.get_or_insert_with(Reg::default);
        let i = r.pending.iter().position(|p| p.id == id)?;
        let now = Instant::now();
        if let Some(a) = r.pending[i].answer {
            r.pending.remove(i);
            return Some(a);
        }
        if now >= deadline {
            r.pending.remove(i);
            return Some(false); // timeout = deny
        }
        g = CV
            .wait_timeout(g, deadline - now)
            .unwrap_or_else(|p| p.into_inner())
            .0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_for(uid: u32) -> String {
        register(uid, 7, || true).unwrap()
    }

    #[test]
    fn registration_needs_polkit() {
        assert!(register(9_001, 7, || false).is_err());
        assert!(ask(9_001, ("K", "any", "x".into()), TIMEOUT).is_none());
    }

    #[test]
    fn timeout_is_deny() {
        let _k = key_for(9_002);
        let t = Instant::now();
        assert_eq!(
            ask(9_002, ("K", "any", "x".into()), Duration::from_millis(50)),
            Some(false)
        );
        assert!(t.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn only_the_approver_with_the_token_answers() {
        let uid = 9_003;
        let key = key_for(uid);
        let asker = std::thread::spawn(move || {
            ask(
                uid,
                ("DB_PASS", "ntfy", "/usr/bin/python3 (pid 42)".into()),
                TIMEOUT,
            )
        });
        let p = loop {
            if let Some(p) = poll(uid, 7, &key).unwrap().pop() {
                break p;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!((p.name.as_str(), p.via.as_str()), ("DB_PASS", "ntfy"));
        // Another process, a wrong key, a wrong token: all refused.
        assert!(poll(uid, 8, &key).is_err());
        assert!(answer(uid, 8, &key, (&p.id, &p.token), true).is_err());
        assert!(answer(uid, 7, "nope", (&p.id, &p.token), true).is_err());
        assert!(answer(uid, 7, &key, (&p.id, "0000"), true).is_err());
        assert_eq!(
            answer(uid, 7, &key, (&p.id, &p.token), true).unwrap(),
            "DB_PASS"
        );
        assert_eq!(asker.join().unwrap(), Some(true));
        // One-time: the token is spent.
        assert!(answer(uid, 7, &key, (&p.id, &p.token), true).is_err());
    }

    #[test]
    fn a_silent_approver_goes_stale() {
        let uid = 9_004;
        key_for(uid);
        with(|r| {
            let a = r.approvers.get_mut(&uid).unwrap();
            a.last_poll = a.last_poll.checked_sub(STALE).unwrap();
        });
        assert!(ask(uid, ("K", "any", "x".into()), TIMEOUT).is_none());
    }
}
