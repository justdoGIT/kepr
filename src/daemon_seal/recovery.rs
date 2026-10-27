// daemon_seal/recovery.rs — the master key as 24 recovery words (T4.10).
//
// The words are the master key itself (kepr_core::recovery_words), so
// both directions reuse the recovery kit's fences (daemon_recovery.rs):
// create needs a passphrase-protected store and that passphrase again,
// the owner only, no agent gate running; restore must prove the key
// against the credential files and refuses while the loaded key works.
// Both are audited (`recovery-words`, `recovery-restore`); the words never
// reach a log line, and decode errors name a position, never a word.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_seal::SealResponse;
use kepr_core::recovery_words;

use crate::daemon_recovery::{fingerprint, install_rebuilt_key, release_live_key};

pub fn handle_create(uid: u32, username: &str, password: &[u8]) -> Response {
    let r = release_live_key(uid, username, password)
        .map(|key| (fingerprint(&key), recovery_words::encode(&key)));
    let status = r.as_ref().map(|_| ()).map_err(Clone::clone);
    super::audit_result("recovery-words", uid, username, &status);
    match r {
        Ok((fingerprint, words)) => {
            Response::Seal(SealResponse::RecoveryWordsOk { fingerprint, words })
        }
        Err(e) => Response::fail(e),
    }
}

pub fn handle_restore(
    uid: u32,
    username: &str,
    words: &ZeroString,
    new_password: &[u8],
) -> Response {
    let r = restore(uid, words, new_password);
    let status = r.as_ref().map(|_| ()).map_err(Clone::clone);
    super::audit_result("recovery-restore", uid, username, &status);
    match r {
        Ok((fingerprint, credentials_opened)) => Response::RecoveryRestoreOk {
            fingerprint,
            credentials_opened,
        },
        Err(e) => Response::fail(e),
    }
}

fn restore(uid: u32, words: &ZeroString, new_password: &[u8]) -> Result<(String, usize), String> {
    if !crate::user_mode() && uid != 0 {
        return Err("only root may manage the recovery kit of the shared store".into());
    }
    if new_password.is_empty() {
        return Err("a new passphrase is required".into());
    }
    let key = recovery_words::decode(words.as_str())?;
    let opened = install_rebuilt_key(&key, new_password)?;
    Ok((fingerprint(&key), opened))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_words_fail_before_touching_the_store() {
        let words = ZeroString::from("abacus notaword");
        let e = restore(0, &words, b"new").unwrap_err();
        assert_eq!(e, "word 2 is not in the recovery word list");
        let e = restore(0, &words, b"").unwrap_err();
        assert!(e.contains("new passphrase"), "{e}");
    }

    #[test]
    fn words_carry_the_kits_fingerprint() {
        let key = [5u8; 32];
        let w = recovery_words::encode(&key);
        let back = recovery_words::decode(w.as_str()).unwrap();
        assert_eq!(fingerprint(&back), fingerprint(&key));
    }
}
