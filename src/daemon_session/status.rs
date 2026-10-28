// daemon_session/status.rs — `Request::Status` (T11.24): the lock state
// plus mode, profile, store backend, what seals the master key, the
// caller's running gates, escrow, FIPS and (T12.31) whether a recovery
// key is enrolled. Nothing here is secret; the gate count is the caller's
// own. T12.33: what seals the master key is read from the key file's
// prefix and its seal record, never from the user-mode key file, which
// holds the key itself.

use std::path::Path;

use kepr_core::protocol::Response;
use kepr_core::protocol_session::StatusInfo;
use zeroize::Zeroizing;

/// The files `key_sealer` looks at.
pub struct KeyFiles<'a> {
    /// The passphrase envelope.
    pub protected: &'a Path,
    /// The sealed key file and its `master.key.seal` record.
    pub key: &'a Path,
    pub record: &'a Path,
}

/// Reads the sealed key file (tests count the calls).
pub type ReadKey<'a> = &'a dyn Fn(&Path) -> Option<Zeroizing<Vec<u8>>>;

/// What protects the master key at rest, as a token for `kepr status`
/// (never the backend's name): `passphrase` / `passphrase+fido2`;
/// T12.32 `unseal-failed`; `file` for the user-mode key file, which holds
/// the key itself and so is never read here; else T12.33's description
/// of the sealed key file (daemon_seal/describe.rs). `configured`: the
/// environment picks a sealer other than the default one.
pub fn key_sealer(
    f: &KeyFiles,
    user_mode: bool,
    configured: bool,
    unseal_failed: bool,
    read: ReadKey,
) -> String {
    if f.protected.exists() {
        // The envelope holds no plaintext key; only its magic counts.
        let fido2 =
            std::fs::read(f.protected).is_ok_and(|e| crate::daemon_seal::fido2_kek::is_fido2(&e));
        return if fido2 {
            "passphrase+fido2"
        } else {
            "passphrase"
        }
        .into();
    }
    if unseal_failed {
        return "unseal-failed".into();
    }
    if user_mode && !configured {
        return "file".into();
    }
    let blob = read(f.key).unwrap_or_default();
    let recorded = std::fs::read_to_string(f.record).ok();
    crate::daemon_seal::describe::describe(&blob, recorded.as_deref())
}

/// T12.31: whether a recovery key is enrolled, on a sealed store; on a
/// passphrase store (which has the recovery kit instead) only when one is
/// left from before `kepr lock`.
pub fn recovery_key(password_protected: bool, enrolled: bool) -> Option<bool> {
    (!password_protected || enrolled).then_some(enrolled)
}

pub fn handle(uid: u32) -> Response {
    let password_protected = crate::protected_master_key_path().exists();
    let user = crate::user_mode();
    let key = crate::master_key_path();
    let backend = if crate::daemon_vault::active().is_some() {
        "image"
    } else {
        "file"
    };
    Response::StatusOk {
        locked: crate::crypto::backend_is_locked(),
        password_protected,
        info: StatusInfo {
            mode: Some(if user { "user" } else { "system" }.into()),
            profile: Some(kepr_core::profile::display_name()),
            store_backend: Some(backend.into()),
            key_sealer: Some(key_sealer(
                &KeyFiles {
                    protected: &crate::protected_master_key_path(),
                    key: &key,
                    record: &crate::master_key::seal_record_path(&key),
                },
                user,
                crate::daemon_seal::configured_from_env(),
                crate::daemon_seal::startup::unseal_failed(),
                &|p| std::fs::read(p).ok().map(Zeroizing::new),
            )),
            gates: Some(crate::daemon_gate_registry::gates_for(uid) as u32),
            escrow: Some(crate::state_dir().join("escrow.bin").exists()),
            fips: Some(crate::daemon_eco::cipher::describe().1),
            recovery_key: recovery_key(
                password_protected,
                crate::daemon_seal::recovery_key::path().exists(),
            ),
            login_failures: Some(
                super::unlock_guard::login_failures().min(u32::from(u8::MAX)) as u8,
            )
            .filter(|&n| user && password_protected && n > 0),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;

    struct Files {
        dir: tempfile::TempDir,
    }

    impl Files {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
            }
        }
        fn path(&self, n: &str) -> std::path::PathBuf {
            self.dir.path().join(n)
        }
        fn put(&self, n: &str, bytes: &[u8]) {
            std::fs::write(self.path(n), bytes).unwrap();
        }
        /// key_sealer over these files; also how often the key was read.
        fn sealer(&self, user: bool, configured: bool, failed: bool) -> (String, u32) {
            let reads = Cell::new(0);
            let read = |p: &Path| {
                reads.set(reads.get() + 1);
                std::fs::read(p).ok().map(Zeroizing::new)
            };
            let (protected, key, record) = (
                self.path("master.key.argon2id"),
                self.path("master.key"),
                self.path("master.key.seal"),
            );
            let f = KeyFiles {
                protected: &protected,
                key: &key,
                record: &record,
            };
            let t = key_sealer(&f, user, configured, failed, &read);
            (t, reads.get())
        }
    }

    #[test]
    fn a_passphrase_store_says_so_and_names_a_security_key() {
        let f = Files::new();
        f.put("master.key.argon2id", b"kepr_pw1\nenvelope");
        assert_eq!(f.sealer(false, false, false), ("passphrase".into(), 0));
        // A passphrase put in place since (a recovery-kit restore) wins.
        assert_eq!(f.sealer(true, true, true), ("passphrase".into(), 0));
        f.put("master.key.argon2id", b"kepr_pw2\nenvelope");
        assert_eq!(f.sealer(true, false, false).0, "passphrase+fido2");
    }

    #[test]
    fn a_key_that_did_not_unseal_says_so() {
        let f = Files::new();
        f.put("master.key", b"kepr-tpm2-v1\n\x03");
        assert_eq!(f.sealer(false, false, true), ("unseal-failed".into(), 0));
        assert_eq!(f.sealer(true, true, true), ("unseal-failed".into(), 0));
    }

    #[test]
    fn the_user_mode_key_file_is_never_read() {
        let f = Files::new();
        // Whatever is there, it is never opened.
        f.put("master.key", b"kepr-tpm2-v1\n\x03");
        f.put("master.key.seal", b"host+tpm2");
        assert_eq!(f.sealer(true, false, false), ("file".into(), 0));
    }

    #[test]
    fn a_sealed_key_file_is_described() {
        let f = Files::new();
        f.put("master.key", b"kepr-tpm2-v1\n\x03rest");
        assert_eq!(
            f.sealer(true, true, false),
            ("tpm2+pin+pcrs+counter".into(), 1)
        );
        assert_eq!(f.sealer(false, false, false).0, "tpm2+pin+pcrs+counter");
        f.put("master.key", b"opaque blob of the credential backend");
        assert_eq!(f.sealer(false, false, false).0, "host-unrecorded");
        f.put("master.key.seal", b"host");
        assert_eq!(f.sealer(false, false, false).0, "host");
        f.put("master.key.seal", b"host+tpm2");
        assert_eq!(f.sealer(false, false, false).0, "host+tpm2");
        std::fs::remove_file(f.path("master.key")).unwrap();
        assert_eq!(f.sealer(false, false, false).0, "host+tpm2");
    }

    #[test]
    fn recovery_key_shows_on_sealed_stores() {
        assert_eq!(recovery_key(false, false), Some(false));
        assert_eq!(recovery_key(false, true), Some(true));
        assert_eq!(recovery_key(true, false), None);
        assert_eq!(recovery_key(true, true), Some(true));
    }

    #[test]
    fn every_field_is_filled() {
        let Response::StatusOk { info, .. } = handle(4_242_424) else {
            panic!("not a status");
        };
        assert!(matches!(info.mode.as_deref(), Some("user" | "system")));
        assert!(info.profile.is_some() && info.key_sealer.is_some());
        assert!(matches!(
            info.store_backend.as_deref(),
            Some("file" | "image")
        ));
        assert_eq!(info.gates, Some(0));
        assert!(info.escrow.is_some() && info.fips.is_some());
    }
}
