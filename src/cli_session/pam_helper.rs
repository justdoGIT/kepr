// cli_session/pam_helper.rs — the helpers pam_kepr.so (crates/kepr-pam)
// runs as the logging-in user (T13.25):
//
//   kepr pam-unlock          stdin: PASSWORD [NUL NEW]. Detaches so the
//                            login never waits, waits for the user's daemon
//                            (KEPR_PAM_WAIT s, default 15, at most 60; the
//                            user unit starts it with the session), sends
//                            `LoginUnlock`, and with NEW (the password was
//                            changed during this login) `ChangePassphrase`.
//   kepr pam-unlock --hint   a login without a password (ssh key,
//                            fingerprint): says why kepr stays locked.
//   kepr pam-passwd          stdin: OLD NUL NEW. `passwd` changed the login
//                            password; the store passphrase follows it.
//
// Each does nothing unless login unlock is on for this user (`kepr
// login-unlock on`), never starts a daemon (one started from a login's
// bare environment would miss the user's settings), takes passwords only
// on stdin and makes itself undumpable before reading them. The
// synchronous ones answer pam_kepr on one stdout line, `CODE [MESSAGE]`:
// 0 done (MESSAGE, if any, is for the user), 10 login unlock is off,
// 11 no daemon is running, 12 refused (MESSAGE says why). Keep the codes
// in step with crates/kepr-pam/src/logic.rs.

use std::io::Read;
use std::time::{Duration, Instant};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_session::{SessionRequest, SessionResponse};
use zeroize::Zeroizing;

const MAX_PASSWORD: usize = 1024;
const MAX_INPUT: usize = 2 * MAX_PASSWORD + 2;
const DEFAULT_WAIT: u64 = 15;
const MAX_WAIT: u64 = 60;

pub const DONE: u8 = 0;
pub const OFF: u8 = 10;
pub const NOT_RUNNING: u8 = 11;
pub const REFUSED: u8 = 12;

const HINT: &str = "kepr: no password was typed at this login, so kepr stays locked; \
                    run `kepr unlock` to use its keys";

/// Seconds to wait for the daemon, from `KEPR_PAM_WAIT`.
pub fn wait_secs(v: Option<&str>) -> u64 {
    v.and_then(|s| s.parse::<u64>().ok())
        .map_or(DEFAULT_WAIT, |n| n.min(MAX_WAIT))
}

/// One or two passwords: NUL-separated as pam_kepr writes them, or lines
/// when typed by hand.
pub fn split_input(buf: &[u8]) -> Result<(ZeroString, Option<ZeroString>), String> {
    let sep = if buf.contains(&0) { 0 } else { b'\n' };
    let mut it = buf.split(|b| *b == sep);
    let take = |p: &[u8]| -> Result<ZeroString, String> {
        if p.len() > MAX_PASSWORD {
            return Err("password too long".into());
        }
        let s = std::str::from_utf8(p).map_err(|_| "password is not UTF-8")?;
        Ok(ZeroString::from(s))
    };
    let first = it.next().unwrap_or_default();
    if first.is_empty() {
        return Err("no usable password on stdin".into());
    }
    let second = it.next().filter(|p| !p.is_empty()).map(take).transpose()?;
    Ok((take(first)?, second))
}

fn read_stdin() -> Result<Zeroizing<Vec<u8>>, String> {
    // Room for all of it up front: a growing Vec would leave copies.
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_INPUT + 64));
    std::io::stdin()
        .lock()
        .take(MAX_INPUT as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| "cannot read the password")?;
    if buf.len() > MAX_INPUT {
        return Err("input too long".into());
    }
    Ok(buf)
}

fn undumpable() {
    // SAFETY: prctl(PR_SET_DUMPABLE) takes plain integers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
}

fn enabled() -> bool {
    let home = std::env::var_os("HOME").unwrap_or_default();
    kepr_core::login_unlock::enabled(std::path::Path::new(&home))
}

fn daemon_up() -> bool {
    matches!(
        crate::client::send_existing(&Request::Ping),
        Ok(Response::Pong)
    )
}

fn send(r: SessionRequest) -> Option<Response> {
    crate::client::send_existing(&Request::Session(r)).ok()
}

/// Wait up to `wait` for `up`; whether it came.
pub fn wait_until(wait: Duration, up: &dyn Fn() -> bool) -> bool {
    let until = Instant::now() + wait;
    while !up() {
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    true
}

/// `LoginUnlock`, then the change made during this login: whether the
/// store was unlocked.
pub fn unlock_then_change(
    password: ZeroString,
    new: Option<ZeroString>,
    send: &dyn Fn(SessionRequest) -> Option<Response>,
) -> bool {
    let unlocked = matches!(
        send(SessionRequest::LoginUnlock {
            password: ZeroString::from(password.as_str()),
        }),
        Some(Response::UnlockedOk)
    );
    if let (true, Some(new)) = (unlocked, new) {
        let _ = send(SessionRequest::ChangePassphrase {
            old: password,
            new,
            login: true,
        });
    }
    unlocked
}

/// The answer line for pam_kepr.
fn reply(code: u8, message: Option<&str>) -> Response {
    match message {
        Some(m) => println!("{code} {m}"),
        None => println!("{code}"),
    }
    Response::Pong
}

/// What `--hint` says, from the switch and the daemon's `Status`.
pub fn hint_for(on: bool, status: Option<&Response>) -> (u8, Option<&'static str>) {
    match status {
        _ if !on => (OFF, None),
        Some(Response::StatusOk { locked: false, .. })
        | Some(Response::StatusOk {
            password_protected: false,
            ..
        }) => (DONE, None),
        // Locked, or not started yet (a passphrase store starts locked).
        _ => (DONE, Some(HINT)),
    }
}

pub fn cmd_pam_unlock(args: &[&str]) -> Response {
    undumpable();
    if args.contains(&"--hint") {
        let status = enabled()
            .then(|| crate::client::send_existing(&Request::Status).ok())
            .flatten();
        let (code, msg) = hint_for(enabled(), status.as_ref());
        return reply(code, msg);
    }
    // Read first: pam_kepr is writing, whatever we decide.
    let (password, new) = match read_stdin().and_then(|b| split_input(&b)) {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
    if !enabled() {
        return Response::Pong;
    }
    let wait = Duration::from_secs(wait_secs(std::env::var("KEPR_PAM_WAIT").ok().as_deref()));
    // SAFETY: this process is single-threaded here (nothing has spawned a
    // thread yet), so the child may keep running ordinary Rust code.
    match unsafe { libc::fork() } {
        -1 => Response::fail("cannot detach"),
        0 => {
            // SAFETY: plain syscalls on descriptors this process owns.
            unsafe {
                libc::setsid();
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                if null >= 0 {
                    for fd in 0..3 {
                        libc::dup2(null, fd);
                    }
                }
            }
            if wait_until(wait, &daemon_up) {
                unlock_then_change(password, new, &send);
            }
            // SAFETY: ends the detached child without running the parent's destructors twice.
            unsafe { libc::_exit(0) }
        }
        _ => Response::Pong,
    }
}

/// The answer to a `ChangePassphrase` from the password hook.
pub fn passwd_reply(r: Option<Response>) -> (u8, String) {
    match r {
        Some(Response::Session(SessionResponse::PassphraseChanged)) => (
            DONE,
            "kepr: the store passphrase follows the new login password".into(),
        ),
        Some(Response::Err { error }) => (
            REFUSED,
            format!("kepr: the store passphrase was not changed ({error}); use `kepr passwd`"),
        ),
        _ => (NOT_RUNNING, String::new()),
    }
}

pub fn cmd_pam_passwd(_args: &[&str]) -> Response {
    undumpable();
    let (old, new) = match read_stdin().and_then(|b| split_input(&b)) {
        Ok((old, Some(new))) => (old, new),
        Ok(_) => return reply(REFUSED, Some("kepr: no new password")),
        Err(e) => return reply(REFUSED, Some(&format!("kepr: {e}"))),
    };
    if !enabled() {
        return reply(OFF, None);
    }
    if !wait_until(Duration::from_secs(2), &daemon_up) {
        return reply(NOT_RUNNING, None);
    }
    let (code, msg) = passwd_reply(send(SessionRequest::ChangePassphrase {
        old,
        new,
        login: true,
    }));
    reply(code, (!msg.is_empty()).then_some(msg.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn the_wait_is_bounded() {
        assert_eq!(wait_secs(None), 15);
        assert_eq!(wait_secs(Some("5")), 5);
        assert_eq!(wait_secs(Some("9999")), 60);
        assert_eq!(wait_secs(Some("soon")), 15);
    }

    #[test]
    fn input_is_one_or_two_passwords() {
        let (p, n) = split_input(b"login-pw\0").unwrap();
        assert_eq!((p.as_str(), n.is_none()), ("login-pw", true));
        let (p, n) = split_input(b"old\0new\0").unwrap();
        assert_eq!((p.as_str(), n.unwrap().as_str()), ("old", "new"));
        // Typed by hand: lines. A NUL wins, so a password may hold "\n".
        let (p, n) = split_input(b"a\nb\n").unwrap();
        assert_eq!((p.as_str(), n.unwrap().as_str()), ("a", "b"));
        let (p, _) = split_input(b"x\ny\0").unwrap();
        assert_eq!(p.as_str(), "x\ny");
        for bad in [&b""[..], b"\0", b"\n", &[0xff, 0xfe, 0]] {
            assert!(split_input(bad).is_err(), "{bad:?}");
        }
        let long = [vec![b'a'; MAX_PASSWORD + 1], vec![0]].concat();
        assert!(split_input(&long).is_err());
    }

    #[test]
    fn no_daemon_means_no_wait_beyond_the_bound() {
        let t = Instant::now();
        assert!(!wait_until(Duration::from_millis(200), &|| false));
        assert!(t.elapsed() < Duration::from_secs(3));
        let polls = std::cell::Cell::new(0);
        assert!(wait_until(Duration::from_secs(5), &|| {
            polls.set(polls.get() + 1);
            polls.get() >= 3
        }));
    }

    fn fake(
        log: &RefCell<Vec<String>>,
        unlock: bool,
    ) -> impl Fn(SessionRequest) -> Option<Response> + '_ {
        move |r| {
            Some(match r {
                SessionRequest::LoginUnlock { password } => {
                    log.borrow_mut()
                        .push(format!("unlock {}", password.as_str()));
                    if unlock {
                        Response::UnlockedOk
                    } else {
                        Response::fail("invalid password")
                    }
                }
                SessionRequest::ChangePassphrase { old, new, login } => {
                    assert!(login, "the hook's change goes on the login budget");
                    log.borrow_mut()
                        .push(format!("change {} {}", old.as_str(), new.as_str()));
                    Response::Session(SessionResponse::PassphraseChanged)
                }
                other => panic!("unexpected {other:?}"),
            })
        }
    }

    #[test]
    fn unlock_then_the_change_made_at_this_login() {
        let log = RefCell::new(vec![]);
        assert!(unlock_then_change("pw".into(), None, &fake(&log, true)));
        assert_eq!(*log.borrow(), ["unlock pw"]);
        let log = RefCell::new(vec![]);
        assert!(unlock_then_change(
            "old".into(),
            Some("new".into()),
            &fake(&log, true)
        ));
        assert_eq!(*log.borrow(), ["unlock old", "change old new"]);
        // No change when the old password didn't open the store.
        let log = RefCell::new(vec![]);
        assert!(!unlock_then_change(
            "old".into(),
            Some("new".into()),
            &fake(&log, false)
        ));
        assert_eq!(*log.borrow(), ["unlock old"]);
    }

    #[test]
    fn the_hint_only_when_kepr_will_stay_locked() {
        let status = |locked, password_protected| Response::StatusOk {
            locked,
            password_protected,
            info: Default::default(),
        };
        assert_eq!(hint_for(false, None), (OFF, None));
        assert_eq!(hint_for(false, Some(&status(true, true))), (OFF, None));
        assert_eq!(hint_for(true, Some(&status(false, true))), (DONE, None));
        assert_eq!(hint_for(true, Some(&status(true, false))), (DONE, None));
        assert_eq!(
            hint_for(true, Some(&status(true, true))),
            (DONE, Some(HINT))
        );
        assert_eq!(hint_for(true, None), (DONE, Some(HINT)), "not started yet");
    }

    #[test]
    fn passwd_replies() {
        let (c, m) = passwd_reply(Some(Response::Session(SessionResponse::PassphraseChanged)));
        assert_eq!(c, DONE);
        assert!(m.contains("follows"));
        let (c, m) = passwd_reply(Some(Response::fail("invalid password")));
        assert_eq!(c, REFUSED);
        assert!(m.contains("invalid password") && m.contains("kepr passwd"));
        assert_eq!(passwd_reply(None), (NOT_RUNNING, String::new()));
    }
}
