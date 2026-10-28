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

use std::process::{Command, Stdio};
use std::time::Duration;

const OSASCRIPT: &str = "/usr/bin/osascript";
const WAIT: Duration = Duration::from_secs(60);
const REFUSED: &str = "this needs approval at the machine, and it was not given";

/// Asks the person at the machine.
pub trait Presence {
    /// `Ok` only when they approved `action`.
    fn confirm(&self, action: &str) -> Result<(), String>;
}

/// The macOS dialog, through `osascript`.
pub struct MacDialog;

impl Presence for MacDialog {
    fn confirm(&self, action: &str) -> Result<(), String> {
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

/// Does the environment seal the master key in the macOS keychain?
pub fn required() -> bool {
    std::env::var("KEPR_MASTER_KEY_SEAL").is_ok_and(|s| s == "keychain")
}

/// The check for `action` on a store where `required` says so.
pub fn require_with(required: bool, p: &dyn Presence, action: &str) -> Result<(), String> {
    if required {
        p.confirm(action).map_err(|_| REFUSED.to_string())
    } else {
        Ok(())
    }
}

pub fn require(action: &str) -> Result<(), String> {
    require_with(required(), &MacDialog, action)
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
        fn confirm(&self, action: &str) -> Result<(), String> {
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
        assert!(require_with(false, &f, LOCK).is_ok());
        assert!(f.asked.borrow().is_empty());
    }

    #[test]
    fn a_keychain_store_asks_and_obeys_the_answer() {
        let yes = fake(true);
        assert!(require_with(true, &yes, ENROL).is_ok());
        assert_eq!(*yes.asked.borrow(), [ENROL]);
        let no = fake(false);
        assert_eq!(require_with(true, &no, LOCK).unwrap_err(), REFUSED);
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
            assert_eq!(MacDialog.confirm(LOCK).unwrap_err(), REFUSED);
        }
    }
}
