// daemon_seal/presence.rs — a person at the machine must approve the two
// requests that move a keychain-sealed master key out of the keychain's
// reach (T12.53).
//
// With `KEPR_MASTER_KEY_SEAL=keychain` (T10.04) the key is protected by the
// login keychain, whose item only the daemon binary may read. `kepr lock`
// (a passphrase envelope replaces the key file) and `kepr recovery-key
// enrol` (the key wrapped under words the caller chose) are requests any
// process of the same user can send, an agent included, and each leaves a
// way to open the store that the keychain does not guard. On such a store
// the daemon asks the logged-in user first, with a macOS dialog that
// names the action and defaults to Deny; no answer in 60 s, no dialog
// (no GUI session) or any error is a refusal. Other sealers are
// unchanged: their own fences (owner, no gate, polkit) stay as they were.
//
// T13.21: on Linux the same two requests can ask through polkit
// (`io.kepr.protect`), opt in with KEPR_PRESENCE=polkit.

use std::process::{Command, Stdio};
use std::time::Duration;

const OSASCRIPT: &str = "/usr/bin/osascript";
const WAIT: Duration = Duration::from_secs(60);
const REFUSED: &str = "this needs approval at the machine, and it was not given";

/// Asks the person at the machine.
pub trait Presence {
    /// `Ok` only when they approved `action`. `peer_pid` is the process
    /// that asked (the polkit subject).
    fn confirm(&self, action: &str, peer_pid: i32) -> Result<(), String>;
}

/// The macOS dialog, through `osascript`.
pub struct MacDialog;

impl Presence for MacDialog {
    fn confirm(&self, action: &str, _peer_pid: i32) -> Result<(), String> {
        if !cfg!(target_os = "macos") {
            return Err(REFUSED.into());
        }
        // `action` is one of this module's fixed strings: no quoting needed.
        let script = format!(
            "display dialog \"kepr: {action}?\" buttons {{\"Deny\", \"Allow\"}} \
             default button \"Deny\" cancel button \"Deny\" with icon caution \
             giving up after {}",
            WAIT.as_secs()
        );
        let out = Command::new(OSASCRIPT)
            .args(["-e", &script])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| REFUSED.to_string())?;
        approved(out.status.success(), &String::from_utf8_lossy(&out.stdout))
            .then_some(())
            .ok_or_else(|| REFUSED.into())
    }
}

/// `osascript` prints `button returned:Allow, gave up:false` on approval;
/// Deny exits non-zero (it is the cancel button) and a timeout says
/// `gave up:true`.
fn approved(success: bool, stdout: &str) -> bool {
    success && stdout.contains("button returned:Allow") && stdout.contains("gave up:false")
}

/// Linux (T13.21): polkit asks the person at the machine, every time
/// (`io.kepr.protect` is `auth_self`, never `auth_self_keep`), for the
/// process that sent the request.
pub struct PolkitPresence;

impl Presence for PolkitPresence {
    fn confirm(&self, _action: &str, peer_pid: i32) -> Result<(), String> {
        if peer_pid > 0 && crate::daemon_polkit::authorized(peer_pid, PROTECT_ACTION_ID) {
            Ok(())
        } else {
            Err(REFUSED.into())
        }
    }
}

/// Must match the `<action id=` in `systemd/polkit/io.kepr.policy`.
pub const PROTECT_ACTION_ID: &str = "io.kepr.protect";

/// Which check this environment asks for.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Kind {
    None,
    MacDialog,
    Polkit,
}

/// The macOS dialog when the key is sealed in the keychain; polkit when
/// `KEPR_PRESENCE=polkit` (opt-in: it needs a polkit agent in the user's
/// session, which headless hosts and CI do not have, so it is never
/// switched on by default). `KEPR_MASTER_KEY_SEAL=keychain` always asks.
pub fn kind_for(seal: Option<&str>, presence: Option<&str>) -> Kind {
    if seal == Some("keychain") {
        Kind::MacDialog
    } else if presence == Some("polkit") {
        Kind::Polkit
    } else {
        Kind::None
    }
}

fn kind() -> Kind {
    kind_for(
        std::env::var("KEPR_MASTER_KEY_SEAL").ok().as_deref(),
        std::env::var("KEPR_PRESENCE").ok().as_deref(),
    )
}

/// The check for `action` on a store where `required` says so.
pub fn require_with(
    required: bool,
    p: &dyn Presence,
    action: &str,
    peer_pid: i32,
) -> Result<(), String> {
    if required {
        p.confirm(action, peer_pid).map_err(|_| REFUSED.to_string())
    } else {
        Ok(())
    }
}

pub fn require(action: &str, peer_pid: i32) -> Result<(), String> {
    match kind() {
        Kind::None => Ok(()),
        Kind::MacDialog => require_with(true, &MacDialog, action, peer_pid),
        Kind::Polkit => require_with(true, &PolkitPresence, action, peer_pid),
    }
}

pub const LOCK: &str = "protect the master key with a passphrase";
pub const ENROL: &str = "create a recovery key for the master key";

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fake {
        answer: bool,
        asked: RefCell<Vec<String>>,
    }

    impl Presence for Fake {
        fn confirm(&self, action: &str, _pid: i32) -> Result<(), String> {
            self.asked.borrow_mut().push(action.into());
            if self.answer {
                Ok(())
            } else {
                Err("no".into())
            }
        }
    }

    fn fake(answer: bool) -> Fake {
        Fake {
            answer,
            asked: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn other_sealers_are_never_asked() {
        let f = fake(false);
        assert!(require_with(false, &f, LOCK, 1).is_ok());
        assert!(f.asked.borrow().is_empty());
    }

    #[test]
    fn a_keychain_store_asks_and_obeys_the_answer() {
        let yes = fake(true);
        assert!(require_with(true, &yes, ENROL, 1).is_ok());
        assert_eq!(*yes.asked.borrow(), [ENROL]);
        let no = fake(false);
        assert_eq!(require_with(true, &no, LOCK, 1).unwrap_err(), REFUSED);
    }

    #[test]
    fn the_check_follows_the_environment() {
        assert_eq!(kind_for(None, None), Kind::None);
        assert_eq!(kind_for(Some("keychain"), None), Kind::MacDialog);
        assert_eq!(kind_for(Some("keychain"), Some("polkit")), Kind::MacDialog);
        assert_eq!(kind_for(None, Some("polkit")), Kind::Polkit);
        assert_eq!(kind_for(Some("host"), Some("off")), Kind::None);
    }

    #[test]
    fn polkit_refuses_without_a_peer() {
        assert_eq!(PolkitPresence.confirm(LOCK, 0).unwrap_err(), REFUSED);
        assert_eq!(PolkitPresence.confirm(LOCK, -1).unwrap_err(), REFUSED);
    }

    #[test]
    fn the_polkit_action_is_in_the_shipped_policy() {
        let xml = include_str!("../../systemd/polkit/io.kepr.policy");
        let at = xml
            .find(&format!("<action id=\"{PROTECT_ACTION_ID}\""))
            .expect("action missing");
        let block = &xml[at..xml[at..].find("</action>").map_or(xml.len(), |e| at + e)];
        assert!(block.contains("<allow_active>auth_self</allow_active>"));
        assert!(!xml.contains("auth_self_keep</allow"));
    }

    #[test]
    fn only_an_explicit_allow_in_time_counts() {
        assert!(approved(true, "button returned:Allow, gave up:false\n"));
        assert!(!approved(true, "button returned:Allow, gave up:true\n"));
        assert!(!approved(true, "button returned:Deny, gave up:false\n"));
        assert!(!approved(false, "button returned:Allow, gave up:false\n"));
        assert!(!approved(true, ""));
    }

    #[test]
    fn without_macos_the_dialog_refuses() {
        if !cfg!(target_os = "macos") {
            assert_eq!(MacDialog.confirm(LOCK, 1).unwrap_err(), REFUSED);
        }
    }
}
