// daemon_seal/recovery_key.rs — a recovery key for a sealed master key
// (T12.31).
//
// A store whose master key is sealed (host key, TPM2, a key service, a
// token or the keychain) has no passphrase to fall back on when the seal
// stops opening. `kepr recovery-key enrol` makes 32 random bytes in the
// CLI and sends them as 24 recovery words; the daemon keeps the master key
// wrapped under them (the shipped Argon2id envelope, key_unlock.rs) in
// `master.key.recovery`. Nothing comes back but the key's fingerprint.
//
// Fences, in order: the owner only (root for the shared store), no agent
// gate of any user running, not a passphrase store (that one has the
// recovery kit and recovery words), the store unlocked. Replacing an
// enrolled key needs its words, which must open the old envelope to the
// running key. Every attempt is audited as `recovery-key-enrol` (op only).

use std::path::{Path, PathBuf};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_seal::SealResponse;
use kepr_core::recovery_words;
use zeroize::Zeroizing;

use crate::daemon_recovery::fingerprint;
use crate::{crypto, key_unlock};

const OWNER: &str = "only root may manage the recovery key of the shared store";
const GATES: &str = "stop running agent sessions first (kepr panic)";
const PASSPHRASE: &str = "this store has a passphrase: use `kepr recovery-kit create --words`";
const ENROLLED: &str = "a recovery key is already enrolled: `kepr recovery-key enrol --replace`";
const WRONG_CURRENT: &str = "the current recovery words do not open the enrolled recovery key";

/// The wrapped master key, next to the key file.
pub fn path() -> PathBuf {
    crate::state_dir().join("master.key.recovery")
}

/// What the fences look at, read once per request.
#[derive(Clone, Copy)]
pub(crate) struct Fence {
    pub user_mode: bool,
    /// Any agent gate of any user (a poisoned registry counts as one).
    pub gates_running: bool,
    /// The store has a passphrase envelope.
    pub passphrase: bool,
}

impl Fence {
    pub fn now() -> Self {
        Self {
            user_mode: crate::user_mode(),
            gates_running: crate::daemon_gate_registry::GATES
                .lock()
                .map_or(true, |g| !g.is_empty()),
            passphrase: crate::protected_master_key_path().exists(),
        }
    }

    /// The owner, no gate, a sealed store: shared by enrol and unlock.
    pub fn check(&self, uid: u32) -> Result<(), String> {
        if !self.user_mode && uid != 0 {
            return Err(OWNER.into());
        }
        if self.gates_running {
            return Err(GATES.into());
        }
        if self.passphrase {
            return Err(PASSPHRASE.into());
        }
        Ok(())
    }
}

/// The new envelope: `live` wrapped under the key the words encode. With
/// an envelope already there, `current` must open it to `live`.
pub fn enrol(
    live: &[u8; 32],
    existing: Option<&[u8]>,
    words: &str,
    current: Option<&str>,
) -> Result<Vec<u8>, String> {
    if let Some(old) = existing {
        let current = current.ok_or(ENROLLED)?;
        // One answer for words that don't decode, don't open the
        // envelope or open it to another key: never which.
        let opened = recovery_words::decode(current)
            .and_then(|k| key_unlock::unwrap(old, k.as_ref()))
            .map_err(|_| WRONG_CURRENT.to_string())?;
        if *opened != *live {
            return Err(WRONG_CURRENT.into());
        }
    }
    let key = recovery_words::decode(words)?;
    key_unlock::wrap(live, key.as_ref())
}

/// Read the enrolled envelope, if any (it holds no plaintext key).
fn existing(file: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(file) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("cannot read the enrolled recovery key".into()),
    }
}

/// Enrol over injected fences, live key and file; returns the fingerprint.
fn enrol_at(
    uid: u32,
    fence: Fence,
    live: impl FnOnce() -> Result<Zeroizing<[u8; 32]>, String>,
    file: &Path,
    words: &str,
    current: Option<&str>,
) -> Result<String, String> {
    fence.check(uid)?;
    let live = live()?;
    let old = existing(file)?;
    let envelope = enrol(&live, old.as_deref(), words, current)?;
    crate::atomic_file::write(file, &envelope, 0o600)
        .map_err(|e| format!("cannot write the recovery key: {e}"))?;
    Ok(fingerprint(&live))
}

pub fn handle_enrol(
    uid: u32,
    username: &str,
    words: &ZeroString,
    current: Option<&ZeroString>,
) -> Response {
    let r = enrol_at(
        uid,
        Fence::now(),
        crypto::snapshot_key,
        &path(),
        words.as_str(),
        current.map(|c| c.as_str()),
    );
    let status = r.as_ref().map(|_| ()).map_err(Clone::clone);
    super::audit_result("recovery-key-enrol", uid, username, &status);
    match r {
        Ok(fingerprint) => Response::Seal(SealResponse::RecoveryKeyEnrolled { fingerprint }),
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE: [u8; 32] = [0x42; 32];
    const OPEN: Fence = Fence {
        user_mode: true,
        gates_running: false,
        passphrase: false,
    };

    fn words(seed: u8) -> ZeroString {
        recovery_words::encode(&[seed; 32])
    }

    fn opens(envelope: &[u8], w: &ZeroString) -> Option<[u8; 32]> {
        let key = recovery_words::decode(w.as_str()).unwrap();
        key_unlock::unwrap(envelope, key.as_ref()).ok().map(|k| *k)
    }

    #[test]
    fn enrol_wraps_the_live_key_under_the_words() {
        let w = words(1);
        let env = enrol(&LIVE, None, w.as_str(), None).unwrap();
        assert_eq!(opens(&env, &w), Some(LIVE));
        // The envelope never holds the key or the words in the clear.
        assert!(!env.windows(32).any(|x| x == LIVE));
        assert!(!env.windows(8).any(|x| x == &w.as_bytes()[..8]));
    }

    #[test]
    fn a_second_enrol_needs_the_current_words() {
        let (old, new) = (words(1), words(2));
        let env = enrol(&LIVE, None, old.as_str(), None).unwrap();
        let e = enrol(&LIVE, Some(&env), new.as_str(), None).unwrap_err();
        assert_eq!(e, ENROLLED);
        let e = enrol(&LIVE, Some(&env), new.as_str(), Some(words(3).as_str())).unwrap_err();
        assert_eq!(e, WRONG_CURRENT);
        // Not words at all: the same answer, never which word.
        let e = enrol(&LIVE, Some(&env), new.as_str(), Some("abacus nope")).unwrap_err();
        assert_eq!(e, WRONG_CURRENT);
        // Words that open the envelope, but to another key.
        let other = enrol(&[7; 32], None, old.as_str(), None).unwrap();
        let e = enrol(&LIVE, Some(&other), new.as_str(), Some(old.as_str())).unwrap_err();
        assert_eq!(e, WRONG_CURRENT);
        let replaced = enrol(&LIVE, Some(&env), new.as_str(), Some(old.as_str())).unwrap();
        assert_eq!(opens(&replaced, &new), Some(LIVE));
        assert_eq!(opens(&replaced, &old), None);
    }

    #[test]
    fn bad_new_words_name_a_position_never_a_word() {
        let e = enrol(&LIVE, None, "abacus notaword", None).unwrap_err();
        assert_eq!(e, "word 2 is not in the recovery word list");
    }

    fn at(fence: Fence, file: &Path, w: &ZeroString) -> Result<String, String> {
        enrol_at(
            0,
            fence,
            || Ok(Zeroizing::new(LIVE)),
            file,
            w.as_str(),
            None,
        )
    }

    #[test]
    fn enrol_writes_an_owner_only_file_and_answers_the_fingerprint() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("master.key.recovery");
        let w = words(4);
        assert_eq!(at(OPEN, &file, &w).unwrap(), fingerprint(&LIVE));
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(opens(&std::fs::read(&file).unwrap(), &w), Some(LIVE));
        // A second plain enrol leaves the first in place.
        assert_eq!(at(OPEN, &file, &words(5)).unwrap_err(), ENROLLED);
        assert_eq!(opens(&std::fs::read(&file).unwrap(), &w), Some(LIVE));
    }

    #[test]
    fn refused_on_a_passphrase_store() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("r");
        let fence = Fence {
            passphrase: true,
            ..OPEN
        };
        let e = at(fence, &file, &words(1)).unwrap_err();
        assert!(e.contains("recovery-kit create --words"), "{e}");
        assert!(!file.exists());
    }

    #[test]
    fn refused_for_non_root_in_system_mode() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("r");
        let system = Fence {
            user_mode: false,
            ..OPEN
        };
        let r = enrol_at(1000, system, || Ok(Zeroizing::new(LIVE)), &file, "", None);
        assert_eq!(r.unwrap_err(), OWNER);
        // Root in system mode, and the owner in user mode, pass.
        assert!(system.check(0).is_ok());
        assert!(OPEN.check(1000).is_ok());
        assert!(!file.exists());
    }

    #[test]
    fn refused_while_the_store_is_locked() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("r");
        let locked = || Err("credential store is locked".to_string());
        let r = enrol_at(0, OPEN, locked, &file, words(1).as_str(), None);
        assert_eq!(r.unwrap_err(), "credential store is locked");
        assert!(!file.exists());
    }

    #[test]
    fn refused_while_any_gate_runs() {
        use crate::daemon_gate_registry::{track_gate, Handle};
        let (conn, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        // Another user's gate: the master key is every user's.
        track_gate(-3_999_031, 3_999_031, Some(Handle::Conn(conn)));
        let fence = Fence::now();
        let r = handle_enrol(0, "root", &words(1), None);
        track_gate(-3_999_031, 3_999_031, None);
        assert!(fence.gates_running);
        assert_eq!(fence.check(0).unwrap_err(), GATES);
        let Response::Err { error } = r else {
            panic!("enrolled while a gate runs");
        };
        assert_eq!(error, GATES);
    }
}
