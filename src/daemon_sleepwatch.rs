// daemon_sleepwatch.rs — lock on suspend and screen lock (agent vault
// T3.05). The user-mode daemon follows logind's signals on the system
// bus through `gdbus monitor` (no D-Bus library dependency) and, on
// `PrepareForSleep(true)`, a session `Lock` or a session's `LockedHint`
// turning true (T12.24: desktops that lock the screen themselves set it
// instead of sending `Lock`), does what `kepr panic`
// does: stop every gate for the owner (their key caches die with them)
// and lock the store if it is passphrase-protected. That keeps keys out
// of RAM while a laptop sleeps, where a cold-boot attack could find them.
//
// Opt out with KEPR_LOCK_ON_SLEEP=0. Without gdbus or a system bus it
// does nothing (`kepr doctor` says so).

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Suspend,
    ScreenLock,
}

/// One line of `gdbus monitor --system --dest org.freedesktop.login1`.
pub fn parse(line: &str) -> Option<Event> {
    if line.contains("org.freedesktop.login1.Manager.PrepareForSleep (true,)") {
        Some(Event::Suspend)
    } else if line.contains("org.freedesktop.login1.Session.Lock ()") || locked_hint(line) {
        Some(Event::ScreenLock)
    } else {
        None
    }
}

/// A screen locker set a logind session's `LockedHint` to true.
fn locked_hint(line: &str) -> bool {
    line.contains(
        "org.freedesktop.DBus.Properties.PropertiesChanged ('org.freedesktop.login1.Session',",
    ) && line.contains("'LockedHint': <true>")
}

pub fn enabled() -> bool {
    std::env::var("KEPR_LOCK_ON_SLEEP").as_deref() != Ok("0")
}

/// Start the watcher thread for `owner_uid` (user mode only).
pub fn spawn(owner_uid: u32) {
    if !enabled() {
        return;
    }
    std::thread::spawn(move || {
        let child = Command::new("gdbus")
            .args(["monitor", "--system", "--dest", "org.freedesktop.login1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else { return };
        let Some(out) = child.stdout.take() else {
            return;
        };
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if let Some(ev) = parse(&line) {
                let (gates, locked) = crate::daemon_platform::fingerprint::soft_lock(owner_uid);
                eprintln!("[kepr-daemon] {ev:?}: stopped {gates} gate(s), locked={locked}");
            }
        }
        let _ = child.wait();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_logind_signals() {
        assert_eq!(
            parse(
                "/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (true,)"
            ),
            Some(Event::Suspend)
        );
        assert_eq!(
            parse(
                "/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (false,)"
            ),
            None
        );
        assert_eq!(
            parse("/org/freedesktop/login1/session/_32: org.freedesktop.login1.Session.Lock ()"),
            Some(Event::ScreenLock)
        );
        assert_eq!(
            parse("/org/freedesktop/login1/session/_32: org.freedesktop.login1.Session.Unlock ()"),
            None
        );
        assert_eq!(parse("random"), None);
    }

    /// T12.24: desktops that lock the screen themselves set the logind
    /// session's LockedHint instead of sending Session.Lock.
    #[test]
    fn parses_locked_hint() {
        let locked = "/org/freedesktop/login1/session/_32: \
            org.freedesktop.DBus.Properties.PropertiesChanged \
            ('org.freedesktop.login1.Session', {'LockedHint': <true>}, @as [])";
        assert_eq!(parse(locked), Some(Event::ScreenLock));
        assert_eq!(parse(&locked.replace("<true>", "<false>")), None);
        let manager = locked.replace("login1.Session'", "login1.Manager'");
        assert_eq!(parse(&manager), None);
    }
}
