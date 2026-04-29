// crypto_inproc.rs — In-process AES-256-GCM credential backend (daemon-only,
// gated by the `inproc-aead` feature flag).
//
// Phase 0 plan α2a: implement the crypto path. α2b adds master_key.rs
// (load-or-generate + sealing). α3 wires this backend into the daemon as
// the default and flips kepr.service back to NoNewPrivileges=yes. Until α3,
// this module is dead code from the daemon's perspective; the test suite
// is what proves it correct.
//
// File format on disk (in /etc/credstore.encrypted/<cred_name>):
//
//   bytes  0..8   : magic prefix b"kepr_v1\n"        (8 bytes)
//   bytes  8..20  : 96-bit nonce (12 bytes, fresh per encrypt)
//   bytes 20..N   : ciphertext || 16-byte GCM tag
//
// Every encrypt generates a fresh nonce via `OsRng`, so re-encrypting the
// same value under the same key/AAD yields a different ciphertext —
// nonce-reuse, the only way to lose AES-GCM's confidentiality, is
// statistically impossible (CSPRNG, 96-bit nonce, < 2^32 lifetime
// re-encrypts per credential).
//
// Additional Authenticated Data (AAD) binds each ciphertext to:
//   - the canonical owner uid (4 bytes, little-endian u32)
//   - the canonical credential name (UTF-8 bytes, validated upstream)
//
// AAD does not appear in the ciphertext but is mixed into the auth tag.
// A swap of two on-disk files (or a rename across uids) will fail the
// MAC check at decrypt time, closing the cross-substitution path the
// shipped systemd-creds backend leaves open.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::Aes256Gcm;
use zeroize::Zeroizing;

use kepr_core::generate::ZeroString;

use crate::crypto::Backend;
use crate::store;

const MAGIC: &[u8] = b"kepr_v1\n";
const MAGIC_LEN: usize = 8;
const NONCE_LEN: usize = 12; // 96 bits — AES-GCM canonical nonce size
const TAG_LEN: usize = 16; // 128 bits — AES-GCM tag

/// AES-256-GCM credential backend. Holds the 32-byte master key in a
/// `Zeroizing<[u8; 32]>` so it is wiped on drop, and binds every ciphertext
/// to `(uid, name)` via AEAD additional data.
pub struct InProcBackend {
    master_key: Zeroizing<[u8; 32]>,
    store_dir: PathBuf,
}

impl InProcBackend {
    /// Construct with the production credstore at /etc/credstore.encrypted/.
    pub fn new(master_key: [u8; 32]) -> Self {
        Self::with_store_dir(master_key, PathBuf::from(store::CREDSTORE))
    }

    /// Construct with an explicit store dir. Tests use this to redirect
    /// writes to a `tempfile::TempDir` so they never touch the live
    /// credstore. The daemon will also use this in α3 if a config file
    /// ever moves the credstore off the systemd-creds default path.
    pub fn with_store_dir(master_key: [u8; 32], store_dir: PathBuf) -> Self {
        Self {
            master_key: Zeroizing::new(master_key),
            store_dir,
        }
    }

    fn cred_path(&self, uid: u32, name: &str) -> PathBuf {
        self.store_dir.join(store::to_cred_name(uid, name))
    }

    fn aad(uid: u32, name: &str) -> Vec<u8> {
        // u32 LE || name bytes. Stable wire format for the AEAD additional
        // data; future schemes can introduce a new MAGIC and alternate AAD
        // layout side-by-side.
        let mut out = Vec::with_capacity(4 + name.len());
        out.extend_from_slice(&uid.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(self.master_key.as_slice().into())
    }
}

impl Backend for InProcBackend {
    fn encrypt(&self, uid: u32, name: &str, value: &[u8]) -> Result<(), String> {
        let cipher = self.cipher();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = Self::aad(uid, name);

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: value,
                    aad: &aad,
                },
            )
            .map_err(|_| "encryption failed".to_string())?;

        let mut out = Vec::with_capacity(MAGIC_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ciphertext);

        write_atomic(&self.cred_path(uid, name), &out)
    }

    fn decrypt(&self, uid: u32, name: &str) -> Result<ZeroString, String> {
        let cred_path = self.cred_path(uid, name);
        if !cred_path.exists() {
            return Err(format!("credential not found: {name}"));
        }
        let blob = fs::read(&cred_path).map_err(|e| format!("read failed: {e}"))?;

        let header_len = MAGIC_LEN + NONCE_LEN;
        if blob.len() < header_len + TAG_LEN {
            return Err("decryption failed: truncated".to_string());
        }
        if &blob[..MAGIC_LEN] != MAGIC {
            return Err("decryption failed: unrecognised format".to_string());
        }

        let nonce_bytes: [u8; NONCE_LEN] = blob[MAGIC_LEN..header_len]
            .try_into()
            .expect("nonce slice is NONCE_LEN by construction");
        let ciphertext = &blob[header_len..];
        let aad = Self::aad(uid, name);

        let plaintext = self
            .cipher()
            .decrypt(
                &nonce_bytes.into(),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "decryption failed: authentication".to_string())?;

        let s = String::from_utf8(plaintext)
            .map_err(|_| "credential contains invalid UTF-8".to_string())?;
        Ok(ZeroString::from_string(
            s.trim_end_matches('\n').to_string(),
        ))
    }

    fn delete(&self, uid: u32, name: &str) -> Result<(), String> {
        let cred_path = self.cred_path(uid, name);
        if !cred_path.exists() {
            return Err(format!("credential not found: {name}"));
        }
        fs::remove_file(&cred_path).map_err(|e| format!("cannot delete credential: {e}"))
    }
}

/// Atomic write of `bytes` to `path`: temp file in the same directory,
/// created at mode `0o600` from the moment `open(2)` returns, then
/// renamed over the target. `fs::rename` is atomic on the same fs and
/// preserves the source mode, so the final file inherits `0o600` too.
///
/// Codex flagged the previous shape (write-then-chmod) as racy:
/// `fs::write` creates the file with `0o666 & ~umask`, leaving a brief
/// window where group/other could open the temp file before the
/// subsequent `chmod`. `OpenOptions::mode(0o600)` closes the window —
/// the inode never exists at any mode wider than what the bits below
/// declare.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("invalid credential path")?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|e| format!("cannot create credstore: {e}"))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot chmod credstore: {e}"))?;
    }

    // Disambiguate the temp filename by (pid, thread_id) so two daemon
    // workers writing the same credential never collide on the temp
    // path. Codex flagged the (pid)-only variant as racy; the bounded
    // worker pool means concurrent same-name writes are uncommon but
    // not impossible. ThreadId is unique within a process and fmts to
    // a stable string, which combined with the pid is unique across
    // the host.
    let tmp = path.with_extension(format!(
        "tmp.{}.{:?}",
        std::process::id(),
        std::thread::current().id()
    ));

    // Open with create_new(true) — `mode(0o600)` only applies to a
    // NEW inode (Linux open(2) ignores the mode argument when O_EXCL
    // is absent and the file already exists). With plain create(true),
    // a stale `*.tmp.<pid>.<tid>` left by a crashed previous run
    // would be reopened at its original (possibly broader) mode and
    // then renamed into place, exposing credential contents. Codex
    // flagged this on the re-review of #55.
    //
    // On EEXIST we make a single retry: the (pid, thread-id) suffix
    // makes a collision with a LIVE thread impossible, so any
    // pre-existing file at this path is stale. Remove it and try
    // once more under the same security shape; a second failure is
    // a real error.
    let mut f = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp);
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("open temp failed (after stale-cleanup): {e}"))?
        }
        Err(e) => return Err(format!("open temp failed: {e}")),
    };
    if let Err(e) = f.write_all(bytes) {
        drop(f);
        let _ = fs::remove_file(&tmp);
        return Err(format!("write failed: {e}"));
    }
    drop(f); // explicit flush before rename

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("cannot install credential: {e}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Backend;
    use tempfile::TempDir;

    // Per-test isolation: each test owns a `tempfile::TempDir` that is
    // auto-cleaned on drop. The backend writes everything under that
    // temp dir, so tests never touch /etc/credstore.encrypted/ and can
    // run as a non-root user.
    //
    // `TEST_UID` is well outside the real-uid range so cross-uid swap
    // scenarios don't accidentally collide with a real account if a
    // future test ever runs against the live store.
    const TEST_UID: u32 = 999_999;

    /// Spin up a backend pointing at a fresh temp directory. Returns the
    /// backend AND the `TempDir` guard — keep the guard in scope until
    /// the assertions finish, otherwise the directory gets removed and
    /// reads / writes fail.
    fn fresh_backend() -> (InProcBackend, TempDir) {
        // Deterministic 32-byte test key. GCM's security comes from the
        // (key, nonce) pair being unique, not the key being secret from
        // the test runner; nonces are still drawn from OsRng inside the
        // backend so per-encrypt freshness is preserved.
        let dir = tempfile::tempdir().expect("create tempdir");
        let backend = InProcBackend::with_store_dir([0xAB; 32], dir.path().to_owned());
        (backend, dir)
    }

    #[test]
    fn round_trip_succeeds() {
        let (b, _dir) = fresh_backend();
        b.encrypt(TEST_UID, "ROUND_TRIP", b"hunter2").unwrap();
        let got = b.decrypt(TEST_UID, "ROUND_TRIP").unwrap();
        assert_eq!(got.as_str(), "hunter2");
    }

    #[test]
    fn decrypt_with_wrong_uid_fails() {
        let (b, _dir) = fresh_backend();
        b.encrypt(TEST_UID, "WRONG_UID", b"hunter2").unwrap();

        // Move the on-disk file from TEST_UID to TEST_UID + 1 so the
        // file content is identical but the requested uid changes.
        // AAD = (uid LE || name) so the MAC must reject the swap.
        let from = b.cred_path(TEST_UID, "WRONG_UID");
        let to = b.cred_path(TEST_UID + 1, "WRONG_UID");
        fs::rename(&from, &to).unwrap();

        let err = match b.decrypt(TEST_UID + 1, "WRONG_UID") {
            Ok(_) => panic!("must reject swapped uid"),
            Err(e) => e,
        };
        assert!(err.contains("authentication"), "got: {err}");
    }

    #[test]
    fn decrypt_with_wrong_name_fails() {
        let (b, _dir) = fresh_backend();
        b.encrypt(TEST_UID, "NAME_A", b"hunter2").unwrap();

        // Same file content, requested under a different name. AAD
        // changes; MAC must reject.
        let from = b.cred_path(TEST_UID, "NAME_A");
        let to = b.cred_path(TEST_UID, "NAME_B");
        fs::rename(&from, &to).unwrap();

        let err = match b.decrypt(TEST_UID, "NAME_B") {
            Ok(_) => panic!("must reject swapped name"),
            Err(e) => e,
        };
        assert!(err.contains("authentication"), "got: {err}");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (b, _dir) = fresh_backend();
        b.encrypt(TEST_UID, "TAMPER", b"hunter2").unwrap();

        // Flip the last byte (inside the GCM auth tag region).
        let p = b.cred_path(TEST_UID, "TAMPER");
        let mut blob = fs::read(&p).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        fs::write(&p, &blob).unwrap();

        let err = match b.decrypt(TEST_UID, "TAMPER") {
            Ok(_) => panic!("must reject tamper"),
            Err(e) => e,
        };
        assert!(err.contains("authentication"), "got: {err}");
    }

    #[test]
    fn magic_prefix_required() {
        let (b, _dir) = fresh_backend();

        // Write a blob that lacks the kepr_v1 magic.
        let p = b.cred_path(TEST_UID, "MAGIC");
        let bogus = vec![0u8; MAGIC_LEN + NONCE_LEN + TAG_LEN + 1];
        fs::write(&p, &bogus).unwrap();

        let err = match b.decrypt(TEST_UID, "MAGIC") {
            Ok(_) => panic!("must reject foreign magic"),
            Err(e) => e,
        };
        assert!(err.contains("unrecognised format"), "got: {err}");
    }

    #[test]
    fn truncated_blob_fails() {
        let (b, _dir) = fresh_backend();

        // Magic + half a nonce, no tag: structurally too small.
        let p = b.cred_path(TEST_UID, "TRUNCATED");
        let mut bogus = MAGIC.to_vec();
        bogus.extend_from_slice(&[0u8; NONCE_LEN / 2]);
        fs::write(&p, &bogus).unwrap();

        let err = match b.decrypt(TEST_UID, "TRUNCATED") {
            Ok(_) => panic!("must reject truncated blob"),
            Err(e) => e,
        };
        assert!(err.contains("truncated"), "got: {err}");
    }

    #[test]
    fn decrypt_missing_credential_returns_not_found() {
        let (b, _dir) = fresh_backend();

        let err = match b.decrypt(TEST_UID, "MISSING") {
            Ok(_) => panic!("must say not found"),
            Err(e) => e,
        };
        assert!(err.contains("credential not found"), "got: {err}");
    }

    #[test]
    fn delete_removes_the_file() {
        let (b, _dir) = fresh_backend();

        b.encrypt(TEST_UID, "DELETE", b"hunter2").unwrap();
        b.delete(TEST_UID, "DELETE").unwrap();
        assert!(!b.cred_path(TEST_UID, "DELETE").exists());
        // Idempotency: a second delete returns the not-found error.
        let err = match b.delete(TEST_UID, "DELETE") {
            Ok(()) => panic!("must say not found"),
            Err(e) => e,
        };
        assert!(err.contains("credential not found"), "got: {err}");
    }

    #[test]
    fn fresh_nonce_per_encrypt() {
        // Same key, same uid, same name, same value — but the on-disk
        // ciphertext must differ because nonces are drawn fresh from
        // OsRng. This is GCM's only confidentiality requirement; pin it.
        let (b, _dir) = fresh_backend();
        b.encrypt(TEST_UID, "NONCE", b"same").unwrap();
        let first = fs::read(b.cred_path(TEST_UID, "NONCE")).unwrap();
        b.encrypt(TEST_UID, "NONCE", b"same").unwrap();
        let second = fs::read(b.cred_path(TEST_UID, "NONCE")).unwrap();
        assert_ne!(first, second, "nonce must change per encrypt");
        // Both files still decrypt to the original value.
        let got = b.decrypt(TEST_UID, "NONCE").unwrap();
        assert_eq!(got.as_str(), "same");
    }
}
