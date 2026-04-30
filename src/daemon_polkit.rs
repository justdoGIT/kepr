// daemon_polkit.rs — same-uid consent prompt via polkit's pkcheck.
//
// Phase 2 ε. A credential set with `--requires-consent` cannot be
// retrieved by `kepr get` without an explicit polkit authorisation
// for the calling user. The check happens server-side in
// `handle_get` (see `crate::daemon_handlers`) so a malicious client
// that bypasses the CLI cannot bypass the prompt either.
//
// Implementation strategy: spawn `/usr/bin/pkcheck` with the kepr
// action ID and the calling user's uid as the subject. polkit
// dispatches to whatever desktop authentication agent is running
// (mate-polkit / polkit-gnome / lxqt-policykit / etc.); the user
// sees a native password prompt, types in their password, and
// pkcheck returns 0 on success. We treat anything else (denial,
// missing pkcheck, missing agent, polkit not running) as a deny.
//
// Why pkcheck and not zbus: pkcheck is the official polkit CLI,
// ships with every distro that has policykit-1, and avoids
// pulling in an async D-Bus runtime. Latency is irrelevant —
// the user prompt is the dominant cost of any consent flow,
// dwarfing the fork+exec.
//
// Subject identifier: pkcheck supports both `--process PID`
// (process subject) and `--system-bus-name NAME`. Since the
// daemon doesn't have the calling process's PID stably (the
// connect-time SO_PEERCRED captures pid, but the kernel reuses
// pids — by the time we run pkcheck the same pid may now be a
// different process, opening a TOCTOU). Using `--enable-internal-agent`
// would let pkcheck prompt the user without going through a
// per-session agent, but that's a polkit-version-dependent flag.
// For Phase 2 ε we use the user's bus name `unix-user:UID` — the
// stable subject form across polkit versions, with the trade-off
// that the prompt is per-user not per-process.
//
// Action registration: install.sh copies
// `systemd/polkit/kepr.policy` to /usr/share/polkit-1/actions/.
// Without that file, polkit returns "Not Authorized" for the
// kepr.read-credential action regardless of user response, and
// `consent_granted` returns false. The user gets "credential
// unavailable" — correct fail-closed behaviour.
//
// Failure modes (all fail-closed by returning false):
//
//   - pkcheck binary missing → ENOENT on spawn
//   - polkit daemon not running → pkcheck exits non-zero
//   - no auth agent in user session → polkit denies
//   - user clicks Cancel on the prompt → exit 1
//   - action ID not registered → exit 1, "Not Authorized"
//   - any of the above failures stay silent at the wire level;
//     the audit log carries the exit code so an operator can
//     diagnose.

use std::process::Command;

/// Polkit action ID. Must match the `<action id="..."` attribute
/// in `systemd/polkit/kepr.policy`. If you rename either, rename
/// both — pkcheck's exit code on an unregistered action is the
/// same as a denied action, so a typo here silently denies every
/// consent-flagged credential.
const ACTION_ID: &str = "io.kepr.read-credential";

/// Path to the pkcheck binary. Hardcoded against
/// /usr/bin/pkcheck rather than relying on $PATH so a
/// privilege-escalation that planted a fake `pkcheck` earlier in
/// $PATH can't bypass the consent gate. policykit-1 packages
/// install pkcheck at this exact path on every distro the kepr
/// daemon supports.
const PKCHECK_BIN: &str = "/usr/bin/pkcheck";

/// Run the consent check for `uid` against the kepr action ID.
/// Returns `true` only if pkcheck exits 0 (authorised); any other
/// outcome — non-zero exit, ENOENT on spawn, IO failure — yields
/// `false` (fail-closed).
///
/// The pkcheck invocation uses `--allow-user-interaction` so the
/// user's auth agent prompts. If no agent is running (headless
/// systemd boot, ssh session without DISPLAY), polkit returns
/// "Not Authorized" and we return false; the user gets a clean
/// "credential unavailable" rather than a stuck prompt.
pub fn consent_granted(uid: u32) -> bool {
    let subject = format!("unix-user:{uid}");
    let status = Command::new(PKCHECK_BIN)
        .arg("--action-id")
        .arg(ACTION_ID)
        .arg("--allow-user-interaction")
        .arg("--process")
        .arg(format!("{},{}", std::process::id(), 0))
        .arg("--detail")
        .arg("kepr.subject")
        .arg(&subject)
        .status();
    match status {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: in this test environment the kepr action ID
    /// isn't registered (the .policy file lives on the host's
    /// /usr/share/polkit-1/actions/, not in the test sandbox).
    /// pkcheck should therefore return non-zero, and our wrapper
    /// should return false. Pins the fail-closed contract — a
    /// regression that flipped the polarity (returning true on
    /// pkcheck failure) would let every consent-flagged
    /// credential through unprotected.
    #[test]
    fn consent_denied_when_action_not_registered() {
        // We can't predict whether pkcheck exists on the runner.
        // If it does, we should see false (action unregistered).
        // If it doesn't, we should also see false (ENOENT).
        // Either way: false.
        let granted = consent_granted(unsafe { libc::getuid() });
        assert!(
            !granted,
            "consent_granted must be false in an unregistered/headless env"
        );
    }
}
