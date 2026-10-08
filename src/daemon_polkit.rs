// daemon_polkit.rs — same-uid consent prompt via polkit's pkcheck.
//
// Phase 2 ε. A credential set with `--requires-consent` cannot be
// retrieved by `kepr get` without explicit polkit authorisation
// for the requesting process. The check happens server-side in
// `handle_get` (see `crate::daemon_handlers::precheck_meta`) so a
// malicious client that bypasses the kepr CLI cannot bypass the
// prompt either.
//
// Polkit-subject correctness (codex P1 from PR #77 review):
//
//   The `--process` argument to pkcheck identifies WHICH process
//   is being authorised. The daemon runs as root; the daemon's
//   own PID is wrong here — polkit would evaluate root's
//   authorisation, not the calling user's, and either always
//   grant (root rule) or always deny (no auth agent for root).
//   Either is wrong: the consent gate must reflect the calling
//   user's intent.
//
//   Fix: use the PEER PID captured at connect-time via
//   SO_PEERCRED (see `daemon_peer::get_peer_creds`). To defend
//   against PID-reuse race conditions (the kernel may recycle
//   the peer's PID by the time pkcheck runs), pair the PID with
//   the process start-time read from /proc/<PID>/stat field 22.
//   pkcheck's `PID,START_TIME` subject form makes the
//   authorisation specific to that exact (pid, start) tuple — a
//   recycled PID would have a different start_time and pkcheck
//   would reject as "no such process".
//
//   If /proc/<PID>/stat can't be read (process exited between
//   connect and consent check), fail-closed: return false,
//   surface "credential unavailable" on the wire.
//
// Failure modes (all fail-closed by returning false):
//
//   - pkcheck binary missing → ENOENT on spawn
//   - polkit daemon not running → pkcheck exits non-zero
//   - no auth agent in user session → polkit denies
//   - user clicks Cancel on the prompt → exit 1
//   - peer process exited between connect and check → /proc fail
//   - action ID not registered → exit 1, "Not Authorized"
//
// Action registration: install.sh copies
// `systemd/polkit/io.kepr.policy` to /usr/share/polkit-1/actions/.
// Without that file, pkcheck returns "Not Authorized" for the
// kepr.read-credential action regardless of user response.

use std::process::Command;

/// Polkit action ID. Must match the `<action id="..."` attribute
/// in `systemd/polkit/io.kepr.policy`. If you rename either,
/// rename both — pkcheck's exit code on an unregistered action
/// is the same as a denied action, so a typo here silently
/// denies every consent-flagged credential.
pub(crate) const ACTION_ID: &str = "io.kepr.read-credential";

/// Path to the pkcheck binary. Hardcoded against
/// /usr/bin/pkcheck rather than relying on $PATH so a
/// privilege-escalation that planted a fake `pkcheck` earlier
/// in $PATH can't bypass the consent gate.
const PKCHECK_BIN: &str = "/usr/bin/pkcheck";

/// Run the consent check for the calling process identified by
/// `peer_pid`. Returns `true` only if pkcheck exits 0
/// (authorised); every other outcome — non-zero exit, ENOENT
/// on spawn, /proc unreadable, IO failure — yields `false`
/// (fail-closed).
///
/// The `peer_pid` MUST be the PID captured at connect-time via
/// SO_PEERCRED, not the daemon's own PID. Passing the daemon
/// PID was the codex P1 from PR #77 review and the reason for
/// the revert in #78; this function takes the peer pid by name
/// to make the contract explicit at every call site.
pub fn consent_granted(peer_pid: i32) -> bool {
    authorized(peer_pid, ACTION_ID)
}

/// The same check for any kepr polkit action (T10.03: `io.kepr.unlock`).
pub fn authorized(peer_pid: i32, action_id: &str) -> bool {
    // Read /proc/<pid>/stat to get the process start-time. Pair
    // it with the pid so a kernel pid-reuse between the
    // SO_PEERCRED capture and the pkcheck call can't authorise
    // the wrong process.
    let start_time = match read_proc_starttime(peer_pid) {
        Some(t) => t,
        None => return false, // peer gone or /proc unreadable
    };
    let subject = format!("{peer_pid},{start_time}");
    let child = Command::new(PKCHECK_BIN)
        .arg("--action-id")
        .arg(action_id)
        .arg("--allow-user-interaction")
        .arg("--process")
        .arg(&subject)
        .spawn();
    match child {
        Ok(c) => wait_with_deadline(c, PROMPT_DEADLINE),
        Err(_) => false,
    }
}

/// How long a consent prompt may stay unanswered. pkcheck waits for the
/// user indefinitely, and each wait holds one daemon worker; without a
/// deadline a few ignored prompts would exhaust the pool. Timeout = deny.
const PROMPT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

fn wait_with_deadline(mut child: std::process::Child, deadline: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if start.elapsed() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// Read field 22 (starttime, jiffies-after-boot) from
/// /proc/<pid>/stat. The `comm` field at index 1 is in
/// parentheses and may itself contain spaces; the standard
/// parse strategy is to split on the LAST `) ` so everything
/// after that is the rest of the line, space-separated.
///
/// Public-ish via the module path so a future test that mocks
/// /proc can drive this in isolation; today it's only called
/// from `consent_granted`.
fn read_proc_starttime(pid: i32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Split on the closing paren of the comm field; everything
    // after is space-delimited fields starting from `state`
    // (field 3 in 1-indexed proc(5) numbering).
    let after_comm = s.rsplit_once(") ")?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // proc(5) field 22 (starttime) is index 19 in `after_comm`
    // because we already consumed pid + comm before splitting.
    fields.get(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_denies_and_reaps() {
        let c = Command::new("sleep").arg("5").spawn().unwrap();
        let t = std::time::Instant::now();
        assert!(!wait_with_deadline(
            c,
            std::time::Duration::from_millis(300)
        ));
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
        assert!(wait_with_deadline(
            Command::new("true").spawn().unwrap(),
            PROMPT_DEADLINE
        ));
        assert!(!wait_with_deadline(
            Command::new("false").spawn().unwrap(),
            PROMPT_DEADLINE
        ));
    }

    /// Pin the fail-closed contract: in any environment where the
    /// kepr action ID isn't registered (every CI runner + this
    /// test sandbox), `consent_granted` must return false. A
    /// regression that flipped the polarity (returning true on
    /// pkcheck failure) would let every consent-flagged credential
    /// through unprotected.
    #[test]
    fn consent_denied_when_action_not_registered() {
        // Use the test process's own PID; /proc/<self>/stat
        // exists, so the start-time read succeeds — the
        // pkcheck-side denial is what should drive the false
        // result. (If pkcheck isn't installed, we still get
        // false via the spawn-error branch.)
        let pid = std::process::id() as i32;
        let granted = consent_granted(pid);
        assert!(
            !granted,
            "consent_granted must be false in an unregistered/headless env"
        );
    }

    #[test]
    fn read_proc_starttime_returns_some_for_self() {
        let pid = std::process::id() as i32;
        let t = read_proc_starttime(pid);
        assert!(t.is_some(), "self /proc/{pid}/stat must parse");
        assert!(t.unwrap() > 0, "starttime is jiffies since boot");
    }

    #[test]
    fn read_proc_starttime_returns_none_for_nonexistent_pid() {
        // PID 0 is reserved (kernel idle task); there is no
        // /proc/0/stat. Any process with a PID this low would
        // be the kernel itself.
        assert_eq!(read_proc_starttime(0), None);
    }

    #[test]
    fn read_proc_starttime_handles_comm_with_parens() {
        // /proc/<pid>/stat's comm field is in parens and CAN
        // contain inner parens or spaces. We use rsplit_once on
        // ") " which matches the LAST `)` followed by space,
        // tolerating embedded close-parens in comm. Pin the
        // logic by invoking against self (which won't have inner
        // parens for our test binary, but the code path is
        // exercised against a real /proc entry).
        let pid = std::process::id() as i32;
        // Just confirms no panic and a parseable u64.
        let _ = read_proc_starttime(pid).expect("self stat parses");
    }
}
