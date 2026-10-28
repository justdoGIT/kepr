// daemon_seal/startup.rs — the master key at daemon start (T12.32).
//
// A passphrase store starts locked, as before, without asking the
// sealer. Otherwise the sealed key file is unsealed, or a key is made on
// the first start. When the sealed key won't unseal (PCRs changed after a
// firmware or kernel update, a changed boot chain, a lost key service) and
// a recovery key is enrolled (recovery_key.rs, T12.31), the daemon starts
// locked instead of exiting and `kepr recovery-key unlock` opens it. The
// same goes for a key file that is gone while a recovery key is there: a
// fresh key would orphan every credential, so none is made. Without a
// recovery key a failed unseal still stops the daemon, as before.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::master_key::{self, Sealer};
use crate::version_state::VersionState;

pub enum Boot {
    Unlocked(Zeroizing<[u8; 32]>),
    Locked,
}

/// Set when the sealed key did not unseal at start-up and a recovery key
/// can open the store instead; cleared once it is sealed again.
static UNSEAL_FAILED: AtomicBool = AtomicBool::new(false);

pub fn unseal_failed() -> bool {
    UNSEAL_FAILED.load(Ordering::SeqCst)
}

pub(crate) fn unseal_failed_flag() -> &'static AtomicBool {
    &UNSEAL_FAILED
}

pub fn bootstrap(user: bool) -> Result<Boot, String> {
    let (key, protected) = (crate::master_key_path(), crate::protected_master_key_path());
    if protected.exists() {
        return Ok(Boot::Locked); // no sealer is even built
    }
    let sealer = master_key::sealer_from_env(user, &key)?;
    let recovery = super::recovery_key::path();
    bootstrap_with(sealer.as_ref(), &key, &protected, &recovery, &UNSEAL_FAILED)
}

fn bootstrap_with(
    sealer: &dyn Sealer,
    key: &Path,
    protected: &Path,
    recovery: &Path,
    flag: &AtomicBool,
) -> Result<Boot, String> {
    if protected.exists() {
        return Ok(Boot::Locked);
    }
    let recoverable = recovery.exists();
    // Never a new key over the old credentials while a recovery key for
    // the old one is there.
    if recoverable && !key.exists() {
        flag.store(true, Ordering::SeqCst);
        eprintln!(
            "[kepr-daemon] the master key file is missing; unlock with `kepr recovery-key unlock`"
        );
        return Ok(Boot::Locked);
    }
    match master_key::load_or_generate(key, sealer) {
        Ok(k) => Ok(Boot::Unlocked(k)),
        Err(e) if recoverable && key.exists() => {
            flag.store(true, Ordering::SeqCst);
            eprintln!(
                "[kepr-daemon] the sealed master key did not unseal ({e}); \
                 unlock with `kepr recovery-key unlock`"
            );
            Ok(Boot::Locked)
        }
        Err(e) => Err(e),
    }
}

fn exit(what: &str, e: &str) -> ! {
    eprintln!("[kepr-daemon] {what}: {e}");
    std::process::exit(1);
}

/// daemon.rs's start-up: bootstrap the key, install the backend with it,
/// lock the backend when there is none. Exits on failure, as before.
pub fn start(user: bool, versions: Arc<VersionState>) {
    let boot = bootstrap(user).unwrap_or_else(|e| exit("cannot bootstrap master key", &e));
    let key = match &boot {
        Boot::Unlocked(k) => Some(k),
        Boot::Locked => None,
    };
    crate::crypto::initialize_inproc_backend(key.map_or(&[0u8; 32], |k| &**k), versions)
        .unwrap_or_else(|e| exit("cannot install backend", &e));
    if key.is_none() {
        crate::crypto::lock_backend().unwrap_or_else(|e| exit("cannot lock protected backend", &e));
        if !unseal_failed() {
            eprintln!("[kepr-daemon] credential store is locked; run `kepr unlock`");
        }
    }
}

/// Test sealers: one that counts, one whose unseal always fails.
#[cfg(test)]
pub(crate) mod mock {
    use std::sync::atomic::{AtomicU32, Ordering};

    use zeroize::Zeroizing;

    use crate::master_key::Sealer;

    #[derive(Default)]
    pub struct Counting {
        pub seals: AtomicU32,
        pub unseals: AtomicU32,
        /// Every seal and unseal fails.
        pub broken: bool,
    }

    impl Counting {
        pub fn broken() -> Self {
            Self {
                broken: true,
                ..Self::default()
            }
        }
        pub fn seals(&self) -> u32 {
            self.seals.load(Ordering::SeqCst)
        }
        pub fn unseals(&self) -> u32 {
            self.unseals.load(Ordering::SeqCst)
        }
    }

    impl Sealer for Counting {
        fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
            self.seals.fetch_add(1, Ordering::SeqCst);
            if self.broken {
                return Err("master-key seal failed".into());
            }
            Ok([b"MOCK".as_slice(), key].concat())
        }

        fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
            self.unseals.fetch_add(1, Ordering::SeqCst);
            let key = blob.strip_prefix(b"MOCK").filter(|_| !self.broken);
            let key: [u8; 32] = key
                .and_then(|k| k.try_into().ok())
                .ok_or("master-key unseal failed")?;
            Ok(Zeroizing::new(key))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::Counting;
    use super::*;

    struct Dir {
        _tmp: tempfile::TempDir,
        key: std::path::PathBuf,
        protected: std::path::PathBuf,
        recovery: std::path::PathBuf,
    }

    fn dir() -> Dir {
        let tmp = tempfile::tempdir().unwrap();
        Dir {
            key: tmp.path().join("master.key"),
            protected: tmp.path().join("master.key.argon2id"),
            recovery: tmp.path().join("master.key.recovery"),
            _tmp: tmp,
        }
    }

    fn boot(s: &Counting, d: &Dir, flag: &AtomicBool) -> Result<Boot, String> {
        bootstrap_with(s, &d.key, &d.protected, &d.recovery, flag)
    }

    #[test]
    fn a_key_that_will_not_unseal_starts_locked_with_a_recovery_key() {
        let d = dir();
        std::fs::write(&d.key, b"sealed for another boot state").unwrap();
        std::fs::write(&d.recovery, b"envelope").unwrap();
        let (s, flag) = (Counting::broken(), AtomicBool::new(false));
        assert!(matches!(boot(&s, &d, &flag), Ok(Boot::Locked)));
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!((s.unseals(), s.seals()), (1, 0));
        // The sealed key stays as it was: never a new one over it.
        assert_eq!(
            std::fs::read(&d.key).unwrap(),
            b"sealed for another boot state"
        );
    }

    #[test]
    fn without_a_recovery_key_it_still_exits() {
        let d = dir();
        std::fs::write(&d.key, b"sealed for another boot state").unwrap();
        let (s, flag) = (Counting::broken(), AtomicBool::new(false));
        let e = boot(&s, &d, &flag)
            .err()
            .expect("no recovery key: an error");
        assert_eq!(e, "master-key unseal failed");
        assert!(!flag.load(Ordering::SeqCst));
        assert_eq!(s.seals(), 0);
    }

    #[test]
    fn a_missing_key_file_is_generated_as_today() {
        let d = dir();
        let (s, flag) = (Counting::default(), AtomicBool::new(false));
        let Ok(Boot::Unlocked(key)) = boot(&s, &d, &flag) else {
            panic!("a first start makes a key");
        };
        assert_eq!(s.seals(), 1);
        assert_eq!(
            std::fs::read(&d.key).unwrap(),
            [b"MOCK".as_slice(), &*key].concat()
        );
        assert!(!flag.load(Ordering::SeqCst));
        // The next start unseals the same key.
        let Ok(Boot::Unlocked(again)) = boot(&s, &d, &flag) else {
            panic!("the key unseals");
        };
        assert_eq!(*again, *key);
        assert_eq!((s.seals(), s.unseals()), (1, 1));
    }

    #[test]
    fn a_missing_key_file_with_a_recovery_key_starts_locked() {
        let d = dir();
        std::fs::write(&d.recovery, b"envelope").unwrap();
        let (s, flag) = (Counting::default(), AtomicBool::new(false));
        assert!(matches!(boot(&s, &d, &flag), Ok(Boot::Locked)));
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!((s.seals(), s.unseals()), (0, 0));
        assert!(!d.key.exists(), "no fresh key over the old credentials");
    }

    #[test]
    fn a_key_that_unseals_ignores_the_recovery_key() {
        let d = dir();
        std::fs::write(&d.key, [b"MOCK".as_slice(), &[9u8; 32]].concat()).unwrap();
        std::fs::write(&d.recovery, b"envelope").unwrap();
        let (s, flag) = (Counting::default(), AtomicBool::new(false));
        let Ok(Boot::Unlocked(key)) = boot(&s, &d, &flag) else {
            panic!("the key unseals");
        };
        assert_eq!(*key, [9u8; 32]);
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn a_passphrase_store_never_calls_the_sealer() {
        let d = dir();
        std::fs::write(&d.protected, b"kepr_pw1\n...").unwrap();
        std::fs::write(&d.recovery, b"envelope").unwrap();
        let (s, flag) = (Counting::broken(), AtomicBool::new(false));
        assert!(matches!(boot(&s, &d, &flag), Ok(Boot::Locked)));
        assert_eq!((s.seals(), s.unseals()), (0, 0));
        assert!(!flag.load(Ordering::SeqCst));
        assert!(!d.key.exists());
    }
}
