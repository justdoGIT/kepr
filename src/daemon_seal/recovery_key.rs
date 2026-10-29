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
//
// T12.32: `kepr recovery-key unlock` is the one path that opens the
// envelope, and only while the sealed key did not unseal at start-up
// (startup.rs), under the same fences. Any wrong word gets one error after
// a 1 s pause; the key must open at least one credential file (or the
// vault image) before it is installed; then it is sealed again for the
// current boot state and written over the key file. Audited as
// `recovery-unlock`. It is sealed again only by the same kind of sealer
// that sealed the old key: a daemon started without its sealer settings
// would otherwise swap a TPM2- or key-service-bound seal for the host key
// or the owner-only file. Then the store stays unlocked for this run only.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_seal::SealResponse;
use kepr_core::recovery_words;
use zeroize::Zeroizing;

use crate::daemon_recovery::fingerprint;
use crate::master_key::Sealer;
use crate::{crypto, key_unlock};

const OWNER: &str = "only root may manage the recovery key of the shared store";
const GATES: &str = "stop running agent sessions first (kepr panic)";
const PASSPHRASE: &str = "this store has a passphrase: use `kepr recovery-kit create --words`";
const ENROLLED: &str = "a recovery key is already enrolled: `kepr recovery-key enrol --replace`";
const WRONG_CURRENT: &str = "the current recovery words do not open the enrolled recovery key";
const WRONG: &str = "these words do not open the enrolled recovery key";
const NOTHING: &str = "the master key unsealed; nothing to recover";

/// The wrapped master key, next to the key file.
pub fn path() -> PathBuf {
    crate::state_dir().join("master.key.recovery")
}

/// One enrol or unlock at a time: two first enrolments racing would
/// both see no envelope, and the words printed first would open nothing.
static ONE: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    ONE.lock().unwrap_or_else(|p| p.into_inner())
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
    peer_pid: i32,
    username: &str,
    words: &ZeroString,
    current: Option<&ZeroString>,
) -> Response {
    let _one = one_at_a_time();
    let fence = Fence::now();
    // T12.53: on a keychain-sealed store the owner approves at the machine.
    let r = fence
        .check(uid)
        .and_then(|()| super::presence::require(super::presence::ENROL, peer_pid))
        .and_then(|()| {
            enrol_at(
                uid,
                fence,
                crypto::snapshot_key,
                &path(),
                words.as_str(),
                current.map(|c| c.as_str()),
            )
        });
    let status = r.as_ref().map(|_| ()).map_err(Clone::clone);
    if r.is_ok() {
        write_family(&path(), &crate::master_key_path());
    }
    super::audit_result("recovery-key-enrol", uid, username, &status);
    match r {
        Ok(fingerprint) => Response::Seal(SealResponse::RecoveryKeyEnrolled { fingerprint }),
        Err(e) => Response::fail(e),
    }
}

/// What `kepr recovery-key unlock` works on, injected for tests.
pub(crate) struct Unlock<'a> {
    /// startup.rs's "did not unseal" flag.
    pub flag: &'a AtomicBool,
    pub envelope: &'a Path,
    pub key_file: &'a Path,
    /// (credential files the key opens, files checked), image included.
    pub probe: &'a dyn Fn(&[u8; 32]) -> (usize, usize),
    /// Install the key in the backend (unlocks the store).
    pub install: &'a dyn Fn(&[u8; 32]) -> Result<(), String>,
    pub sealer: &'a dyn Fn() -> Result<Box<dyn Sealer>, String>,
    /// The pause before a wrong-words reply.
    pub pause: &'a dyn Fn(),
}

/// The sealer family a key blob belongs to, by its header; `None` for
/// what systemd-creds wrote or a file too damaged to tell (the reason the
/// recovery key is being used).
const KNOWN_FAMILIES: [&str; 4] = ["tpm2", "key service", "keychain", "owner-only file"];

fn family(blob: &[u8]) -> Option<&'static str> {
    const KNOWN: [(&[u8], &str); 4] = [
        (b"kepr-tpm2-v1\n", "tpm2"),
        (b"kepr-kek1\n", "key service"),
        (b"kepr-keychain-v1\n", "keychain"),
        (b"kepr-local-v1\n", "owner-only file"),
    ];
    KNOWN
        .iter()
        .find(|(magic, _)| blob.starts_with(magic))
        .map(|(_, name)| *name)
}

/// `master.key.recovery.seal`: the sealer family the key file had when the
/// recovery key was enrolled (`default` for systemd-creds's), so a key file
/// that has since broken, or been swapped, can't change what it is sealed
/// with again.
fn family_path(envelope: &Path) -> PathBuf {
    let mut name = envelope.file_name().unwrap_or_default().to_os_string();
    name.push(".seal");
    envelope.with_file_name(name)
}

fn write_family(envelope: &Path, key_file: &Path) {
    let name = std::fs::read(key_file)
        .ok()
        .as_deref()
        .and_then(family)
        .unwrap_or("default");
    let _ = crate::atomic_file::write(&family_path(envelope), name.as_bytes(), 0o600);
}

/// Refuse to replace the key file with a seal of another family or other
/// binding than the one it has (`master.key.seal` records `host`, `tpm2`
/// or `host+tpm2`).
fn not_weaker(
    key_file: &Path,
    envelope: &Path,
    sealer: &dyn Sealer,
    blob: &[u8],
) -> Result<(), String> {
    let differs = |what: &str| {
        Err(format!(
            "the sealer settings differ from the ones that sealed this key ({what}); \
             start the daemon with its usual KEPR_MASTER_KEY_SEAL settings, then unlock again"
        ))
    };
    // The family recorded at enrolment, else the old file's own header,
    // must be the new file's too.
    let recorded = std::fs::read_to_string(family_path(envelope)).ok();
    let was = match recorded.as_deref().map(str::trim) {
        Some("default") => None,
        Some(name) => KNOWN_FAMILIES.iter().copied().find(|k| *k == name),
        None => std::fs::read(key_file).ok().as_deref().and_then(family),
    };
    let recorded_default = recorded.as_deref().map(str::trim) == Some("default");
    if (was.is_some() || recorded_default) && family(blob) != was {
        return differs(was.unwrap_or("host key"));
    }
    let recorded = std::fs::read_to_string(crate::master_key::seal_record_path(key_file)).ok();
    match (recorded.as_deref().map(str::trim), sealer.seal_kind()) {
        (Some(was), now) if now.as_deref() != Some(was) => differs(was),
        _ => Ok(()),
    }
}

/// Ok(None): unlocked and sealed again. Ok(Some(e)): unlocked for this
/// run only, sealing again failed with `e`.
fn unlock_with(uid: u32, fence: Fence, words: &str, u: &Unlock) -> Result<Option<String>, String> {
    fence.check(uid)?;
    if !u.flag.load(Ordering::SeqCst) {
        return Err(NOTHING.into());
    }
    // One answer, after a pause, for words that don't decode, a missing
    // envelope or one they don't open.
    let opened = std::fs::read(u.envelope).map_err(|_| ()).and_then(|env| {
        let key = recovery_words::decode(words).map_err(|_| ())?;
        key_unlock::unwrap(&env, key.as_ref()).map_err(|_| ())
    });
    let Ok(key) = opened else {
        (u.pause)();
        return Err(WRONG.into());
    };
    let (opens, total) = (u.probe)(&key);
    if opens == 0 {
        return Err(format!(
            "the recovered key opens none of the {total} credential file(s) here; \
             nothing was changed"
        ));
    }
    (u.install)(&key)?;
    let resealed = (u.sealer)().and_then(|s| {
        let blob = s.seal(&key)?;
        not_weaker(u.key_file, u.envelope, s.as_ref(), &blob)?;
        crate::atomic_file::write(u.key_file, &blob, 0o600)
            .map_err(|e| format!("cannot write master key: {e}"))?;
        crate::master_key::record_seal_kind(u.key_file, s.as_ref()); // T12.33
        Ok(())
    });
    match resealed {
        Ok(()) => {
            u.flag.store(false, Ordering::SeqCst);
            Ok(None)
        }
        Err(e) => Ok(Some(e)),
    }
}

pub fn handle_unlock(uid: u32, username: &str, words: &ZeroString) -> Response {
    let _one = one_at_a_time();
    let user = crate::user_mode();
    let key_file = crate::master_key_path();
    let u = Unlock {
        flag: super::startup::unseal_failed_flag(),
        envelope: &path(),
        key_file: &key_file,
        probe: &crate::daemon_recovery::probe,
        install: &crypto::unlock_backend,
        sealer: &|| crate::master_key::sealer_from_env(user, &key_file),
        pause: &|| std::thread::sleep(std::time::Duration::from_secs(1)),
    };
    let r = unlock_with(uid, Fence::now(), words.as_str(), &u);
    let status = r.as_ref().map(|_| ()).map_err(Clone::clone);
    super::audit_result("recovery-unlock", uid, username, &status);
    match r {
        Ok(None) => Response::UnlockedOk,
        Ok(Some(error)) => {
            eprintln!(
                "[kepr-daemon] recovery unlock: sealing the master key again failed: {error}"
            );
            Response::Seal(SealResponse::UnlockedNotResealed { error })
        }
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

    use crate::daemon_seal::startup::mock::Counting;
    use std::cell::Cell;

    /// An unlock over temp files: a key file that won't unseal and an
    /// envelope of LIVE under words(1).
    struct Rig {
        dir: tempfile::TempDir,
        flag: AtomicBool,
        sealer: std::sync::Arc<Counting>,
        installed: std::sync::Mutex<Option<[u8; 32]>>,
        pauses: Cell<u32>,
        opens: usize,
        /// What the new sealer says it binds a key to.
        kind: Option<&'static str>,
    }

    impl Rig {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let env = enrol(&LIVE, None, words(1).as_str(), None).unwrap();
            std::fs::write(dir.path().join("rec"), env).unwrap();
            std::fs::write(dir.path().join("key"), b"sealed elsewhere").unwrap();
            Self {
                dir,
                flag: AtomicBool::new(true),
                sealer: Default::default(),
                installed: Default::default(),
                pauses: Cell::new(0),
                opens: 2,
                kind: None,
            }
        }

        fn key_file(&self) -> PathBuf {
            self.dir.path().join("key")
        }

        fn run(&self, uid: u32, fence: Fence, w: &str) -> Result<Option<String>, String> {
            let (env, key) = (self.dir.path().join("rec"), self.key_file());
            let (sealer, kind) = (self.sealer.clone(), self.kind);
            let probe = |k: &[u8; 32]| (if *k == LIVE { self.opens } else { 0 }, 3);
            let install = |k: &[u8; 32]| {
                *self.installed.lock().unwrap() = Some(*k);
                Ok(())
            };
            let u = Unlock {
                flag: &self.flag,
                envelope: &env,
                key_file: &key,
                probe: &probe,
                install: &install,
                sealer: &move || Ok(Box::new(Shared(sealer.clone(), kind)) as Box<dyn Sealer>),
                pause: &|| self.pauses.set(self.pauses.get() + 1),
            };
            unlock_with(uid, fence, w, &u)
        }

        fn installed(&self) -> Option<[u8; 32]> {
            *self.installed.lock().unwrap()
        }
    }

    /// The rig's counting sealer behind a Box.
    struct Shared(std::sync::Arc<Counting>, Option<&'static str>);

    impl Sealer for Shared {
        fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
            self.0.seal(key)
        }
        fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
            self.0.unseal(blob)
        }
        fn seal_kind(&self) -> Option<String> {
            self.1.map(String::from)
        }
    }

    #[test]
    fn right_words_unlock_and_reseal_once() {
        let rig = Rig::new();
        // A sealer that can't say what it binds to drops the stale record
        // (T12.33) when the old key had none.
        let record = crate::master_key::seal_record_path(&rig.key_file());
        std::fs::write(&record, b"host").unwrap();
        let mut rig = rig;
        rig.kind = Some("host");
        assert_eq!(rig.run(0, OPEN, words(1).as_str()), Ok(None));
        assert_eq!(std::fs::read(&record).unwrap(), b"host");
        assert_eq!(rig.installed(), Some(LIVE));
        assert_eq!(rig.sealer.seals(), 1);
        let blob = std::fs::read(rig.key_file()).unwrap();
        assert_eq!(
            blob,
            [b"MOCK".as_slice(), &LIVE].concat(),
            "key file replaced"
        );
        assert!(!rig.flag.load(Ordering::SeqCst), "the flag is cleared");
        assert_eq!(rig.pauses.get(), 0);
        // Sealed again: a second unlock has nothing to do.
        assert_eq!(rig.run(0, OPEN, words(1).as_str()).unwrap_err(), NOTHING);
    }

    #[test]
    fn wrong_words_keep_the_store_locked() {
        let rig = Rig::new();
        for w in [words(2).as_str(), "abacus nope", ""] {
            assert_eq!(rig.run(0, OPEN, w).unwrap_err(), WRONG, "{w:?}");
        }
        assert_eq!(rig.pauses.get(), 3, "every wrong answer waits");
        assert_eq!(rig.installed(), None);
        assert_eq!(rig.sealer.seals(), 0);
        assert!(rig.flag.load(Ordering::SeqCst));
        assert_eq!(std::fs::read(rig.key_file()).unwrap(), b"sealed elsewhere");
    }

    #[test]
    fn a_key_that_opens_no_credential_is_refused() {
        let mut rig = Rig::new();
        rig.opens = 0;
        let e = rig.run(0, OPEN, words(1).as_str()).unwrap_err();
        assert!(e.contains("none of the 3 credential"), "{e}");
        assert_eq!((rig.installed(), rig.sealer.seals()), (None, 0));
        assert!(rig.flag.load(Ordering::SeqCst));
    }

    #[test]
    fn a_failed_reseal_leaves_it_unlocked_for_this_run() {
        let mut rig = Rig::new();
        rig.sealer = std::sync::Arc::new(Counting::broken());
        let r = rig.run(0, OPEN, words(1).as_str()).unwrap();
        assert_eq!(r.as_deref(), Some("master-key seal failed"));
        assert_eq!(rig.installed(), Some(LIVE));
        assert_eq!(std::fs::read(rig.key_file()).unwrap(), b"sealed elsewhere");
        // The next start needs the recovery key again; so may a retry now.
        assert!(rig.flag.load(Ordering::SeqCst));
    }

    #[test]
    fn a_weaker_sealer_never_replaces_the_key_file() {
        let words = words(1);
        // Another family: the key service blob would become the host key.
        let rig = Rig::new();
        std::fs::write(rig.key_file(), b"kepr-kek1\nrest").unwrap();
        let r = rig.run(0, OPEN, words.as_str()).unwrap();
        assert!(r.unwrap().contains("sealer settings differ"));
        assert_eq!(std::fs::read(rig.key_file()).unwrap(), b"kepr-kek1\nrest");
        assert_eq!(rig.installed(), Some(LIVE), "unlocked for this run");
        assert!(
            rig.flag.load(Ordering::SeqCst),
            "the next start needs it again"
        );
        // Same family, other binding: host+tpm2 must not become host.
        let mut rig = Rig::new();
        let record = crate::master_key::seal_record_path(&rig.key_file());
        std::fs::write(&record, b"host+tpm2").unwrap();
        rig.kind = Some("host");
        assert!(rig.run(0, OPEN, words.as_str()).unwrap().is_some());
        // ... and a sealer that can't say what it binds to is no match.
        rig.kind = None;
        assert!(rig.run(0, OPEN, words.as_str()).unwrap().is_some());
        assert_eq!(std::fs::read(rig.key_file()).unwrap(), b"sealed elsewhere");
        rig.kind = Some("host+tpm2");
        assert_eq!(rig.run(0, OPEN, words.as_str()), Ok(None));
    }

    #[test]
    fn the_family_recorded_at_enrolment_beats_a_broken_key_file() {
        let words = words(1);
        let rig = Rig::new();
        // Enrolled while the key file was a key-service blob; broken since.
        std::fs::write(rig.key_file(), b"kepr-kek1\nrest").unwrap();
        write_family(&rig.dir.path().join("rec"), &rig.key_file());
        std::fs::write(rig.key_file(), b"no longer unseals").unwrap();
        let r = rig.run(0, OPEN, words.as_str()).unwrap();
        assert!(r.unwrap().contains("sealer settings differ"));
        assert_eq!(std::fs::read(rig.key_file()).unwrap(), b"no longer unseals");
        // Enrolled on a default (systemd-creds) key: a different family
        // from the mock's (none) is fine, an owner-only file is not.
        let rig = Rig::new();
        write_family(&rig.dir.path().join("rec"), &rig.key_file());
        assert_eq!(
            std::fs::read(family_path(&rig.dir.path().join("rec"))).unwrap(),
            b"default"
        );
        assert_eq!(rig.run(0, OPEN, words.as_str()), Ok(None));
    }

    #[test]
    fn refused_when_the_key_unsealed() {
        let rig = Rig::new();
        rig.flag.store(false, Ordering::SeqCst);
        assert_eq!(rig.run(0, OPEN, words(1).as_str()).unwrap_err(), NOTHING);
        assert_eq!((rig.installed(), rig.pauses.get()), (None, 0));
    }

    #[test]
    fn unlock_is_fenced_like_enrol() {
        let rig = Rig::new();
        let w = words(1);
        let system = Fence {
            user_mode: false,
            ..OPEN
        };
        assert_eq!(rig.run(1000, system, w.as_str()).unwrap_err(), OWNER);
        let gate = Fence {
            gates_running: true,
            ..OPEN
        };
        assert_eq!(rig.run(0, gate, w.as_str()).unwrap_err(), GATES);
        // A store that got a passphrase since (a recovery-kit restore).
        let pw = Fence {
            passphrase: true,
            ..OPEN
        };
        assert_eq!(rig.run(0, pw, w.as_str()).unwrap_err(), PASSPHRASE);
        assert_eq!((rig.installed(), rig.sealer.seals()), (None, 0));
    }

    #[test]
    fn refused_while_any_gate_runs() {
        use crate::daemon_gate_registry::{track_gate, Handle};
        let (conn, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        // Another user's gate: the master key is every user's.
        track_gate(-3_999_031, 3_999_031, Some(Handle::Conn(conn)));
        let fence = Fence::now();
        let r = handle_enrol(0, 0, "root", &words(1), None);
        track_gate(-3_999_031, 3_999_031, None);
        assert!(fence.gates_running);
        assert_eq!(fence.check(0).unwrap_err(), GATES);
        let Response::Err { error } = r else {
            panic!("enrolled while a gate runs");
        };
        assert_eq!(error, GATES);
    }
}
