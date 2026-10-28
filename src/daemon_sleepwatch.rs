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
//
// T12.25: a second watcher does the same when a FIDO2 security key is
// unplugged (`udevadm monitor`), when unlocking needs one or with
// KEPR_LOCK_ON_KEY_REMOVAL=1 (`0` turns it off). Any FIDO2 token counts;
// without udevadm it does nothing.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Suspend,
    ScreenLock,
    KeyRemoved,
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

/// Start the watcher threads for `owner_uid` (user mode only).
pub fn spawn(owner_uid: u32) {
    spawn_key_watch(owner_uid); // its own opt-out
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

/// One block of `udevadm monitor --udev --subsystem-match=hidraw
/// --property`: a FIDO2 token's removal. systemd's 60-fido-id.rules sets
/// `ID_FIDO_TOKEN=1`, and the remove event carries the stored properties.
pub fn parse_udev(block: &str) -> Option<Event> {
    let has = |kv: &str| block.lines().any(|l| l.trim() == kv);
    (has("ACTION=remove") && has("ID_FIDO_TOKEN=1")).then_some(Event::KeyRemoved)
}

/// `KEPR_LOCK_ON_KEY_REMOVAL`: `0` off, `1` on; unset (or anything else)
/// follows whether unlocking needs a FIDO2 security key.
fn key_watch_enabled(env: Option<&str>, fido2_factor: bool) -> bool {
    match env {
        Some("0") => false,
        Some("1") => true,
        _ => fido2_factor,
    }
}

/// Hand each blank-line-separated block of the monitor's output to
/// `parse_udev`.
fn udev_events(out: impl BufRead, mut on: impl FnMut(Event)) {
    let mut block = String::new();
    for line in out.lines().map_while(Result::ok) {
        if !line.trim().is_empty() {
            block.push_str(&line);
            block.push('\n');
            continue;
        }
        if let Some(ev) = parse_udev(&block) {
            on(ev);
        }
        block.clear();
    }
}

/// Until the watch applies, re-check once a minute (a key enrolled later
/// needs no restart); then follow `udevadm monitor`. Every removal checks
/// again, so a store that dropped its security key stops locking.
fn spawn_key_watch(owner_uid: u32) {
    let env = std::env::var("KEPR_LOCK_ON_KEY_REMOVAL").ok();
    let udevadm = std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("udevadm").is_file()));
    if env.as_deref() == Some("0") || !udevadm {
        return; // off, or nothing to watch with (`kepr doctor` says so)
    }
    let applies =
        move || key_watch_enabled(env.as_deref(), crate::daemon_seal::fido2_kek::enrolled());
    std::thread::spawn(move || {
        while !applies() {
            std::thread::sleep(Duration::from_secs(60));
        }
        let child = Command::new("udevadm")
            .args([
                "monitor",
                "--udev",
                "--subsystem-match=hidraw",
                "--property",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else { return };
        let Some(out) = child.stdout.take() else {
            return;
        };
        udev_events(BufReader::new(out), |ev| {
            if applies() {
                let (gates, locked) = crate::daemon_platform::fingerprint::soft_lock(owner_uid);
                eprintln!("[kepr-daemon] {ev:?}: stopped {gates} gate(s), locked={locked}");
            }
        });
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

    /// One `udevadm monitor --udev --subsystem-match=hidraw --property`
    /// event: a security key's hidraw node going away.
    const FIDO_REMOVE: &str = "\
UDEV  [5123.456789] remove   /devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/0003:1050:0407.0005/hidraw/hidraw3 (hidraw)
ACTION=remove
DEVPATH=/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/0003:1050:0407.0005/hidraw/hidraw3
SUBSYSTEM=hidraw
DEVNAME=/dev/hidraw3
SEQNUM=4242
USEC_INITIALIZED=5000000000
ID_FIDO_TOKEN=1
ID_SECURITY_TOKEN=1
MAJOR=241
MINOR=3
";

    /// T12.25: only a FIDO2 token's removal counts.
    #[test]
    fn parses_udev_removal_of_a_security_key() {
        assert_eq!(parse_udev(FIDO_REMOVE), Some(Event::KeyRemoved));
        assert_eq!(parse_udev(&FIDO_REMOVE.replace("remove", "add")), None);
        let mouse: String = FIDO_REMOVE
            .lines()
            .filter(|l| !l.starts_with("ID_"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(parse_udev(&mouse), None);
        assert_eq!(parse_udev(""), None);
    }

    #[test]
    fn key_watch_truth_table() {
        for (env, factor, want) in [
            (Some("0"), true, false),
            (Some("0"), false, false),
            (Some("1"), true, true),
            (Some("1"), false, true),
            (None, true, true),
            (None, false, false),
            (Some("yes"), false, false),
        ] {
            assert_eq!(key_watch_enabled(env, factor), want, "{env:?} {factor}");
        }
    }

    /// The monitor's stream: a banner, then one block per event.
    #[test]
    fn udev_stream_is_read_block_by_block() {
        let stream = format!(
            "monitor will print the received events for:\n\
             UDEV - the event which udev sends out after rule processing\n\n\
             {}\n{}\n",
            FIDO_REMOVE.replace("remove", "add"),
            FIDO_REMOVE
        );
        let mut seen = Vec::new();
        udev_events(stream.as_bytes(), |e| seen.push(e));
        assert_eq!(seen, vec![Event::KeyRemoved]);
    }
}
