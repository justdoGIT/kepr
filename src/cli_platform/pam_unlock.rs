// cli_platform/pam_unlock.rs — `kepr pam-unlock`, the helper `pam_kepr.so`
// (crates/kepr-pam) runs as the logging-in user after authentication.
//
// It reads the login password from stdin (one line, 1 KiB at most; never
// argv), detaches into the background so the login does not wait, waits for
// the user's daemon to come up (`KEPR_PAM_WAIT` seconds, default 15, at most
// 60; the user manager starts it with the session), then sends the same
// `Unlock` request `kepr unlock` does. It only helps when the store's
// passphrase is the login password. A wrong password, a store with no
// passphrase or a daemon that never appears all end silently: the login is
// never held up and nothing is retried (a retry would count against the
// unlock back-off, T11.13).

use std::io::Read;
use std::time::{Duration, Instant};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};

const MAX_PASSWORD: u64 = 1024;
const DEFAULT_WAIT: u64 = 15;
const MAX_WAIT: u64 = 60;

/// Seconds to wait for the daemon, from `KEPR_PAM_WAIT`.
pub fn wait_secs(v: Option<&str>) -> u64 {
    v.and_then(|s| s.parse::<u64>().ok())
        .map_or(DEFAULT_WAIT, |n| n.min(MAX_WAIT))
}

/// The password from stdin: the first line, without its newline.
fn read_password() -> Result<ZeroString, String> {
    let mut buf = zeroize::Zeroizing::new(String::new());
    std::io::stdin()
        .lock()
        .take(MAX_PASSWORD + 1)
        .read_to_string(&mut buf)
        .map_err(|_| "cannot read the password")?;
    let line = buf.lines().next().unwrap_or_default();
    if line.is_empty() || line.len() as u64 > MAX_PASSWORD {
        return Err("no usable password on stdin".into());
    }
    Ok(ZeroString::from_string(line.to_string()))
}

fn daemon_up() -> bool {
    matches!(
        crate::client::send_request(&Request::Ping),
        Ok(Response::Pong)
    )
}

/// Wait up to `wait` for `up`, then run `unlock`; whether it was accepted.
pub fn unlock_when(
    password: ZeroString,
    wait: Duration,
    (up, unlock): (&dyn Fn() -> bool, &dyn Fn(ZeroString) -> bool),
) -> bool {
    let until = Instant::now() + wait;
    while !up() {
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    unlock(password)
}

fn unlock_for_real(password: ZeroString) -> bool {
    matches!(
        crate::client::send_request(&Request::Unlock { password }),
        Ok(Response::UnlockedOk)
    )
}

pub fn cmd_pam_unlock(_args: &[String]) -> Response {
    let password = match read_password() {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
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
            let _ = unlock_when(password, wait, (&daemon_up, &unlock_for_real));
            // SAFETY: ends the detached child without running the parent's destructors twice.
            unsafe { libc::_exit(0) }
        }
        _ => Response::Pong,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_is_bounded() {
        assert_eq!(wait_secs(None), 15);
        assert_eq!(wait_secs(Some("5")), 5);
        assert_eq!(wait_secs(Some("9999")), 60);
        assert_eq!(wait_secs(Some("soon")), 15);
    }

    #[test]
    fn no_daemon_means_no_unlock_and_no_hang() {
        let t = Instant::now();
        let never = |_: ZeroString| panic!("unlocked a daemon that is not there");
        assert!(!unlock_when(
            ZeroString::from("pw"),
            Duration::from_millis(200),
            (&|| false, &never)
        ));
        assert!(t.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn the_unlock_runs_once_the_daemon_is_up() {
        let polls = std::cell::Cell::new(0);
        let up = || {
            polls.set(polls.get() + 1);
            polls.get() >= 3
        };
        let got = std::cell::RefCell::new(String::new());
        let unlock = |p: ZeroString| {
            *got.borrow_mut() = p.as_str().to_string();
            true
        };
        assert!(unlock_when(
            ZeroString::from("login-pw"),
            Duration::from_secs(5),
            (&up, &unlock)
        ));
        assert_eq!(*got.borrow(), "login-pw");
        assert_eq!(polls.get(), 3);
    }
}
