// crypto_inproc.rs — In-process AES-256-GCM credential backend.
//
// Default backend since Phase 0 α3. Per-credential operations are
// pure in-process AES-256-GCM keyed off the master key loaded from
// /var/lib/kepr/master.key (see master_key.rs). The systemd-creds
// fork+exec only happens once at daemon startup to seal/unseal the
// master key, not per get/set/delete.
//
// File format on disk (in /etc/credstore.encrypted/<cred_name>):
//
//   bytes  0..8   : magic prefix b"kepr_v2\n"  (current; v1 readable for migration)
//   bytes  8..20  : 96-bit nonce (12 bytes, fresh per encrypt)
//   bytes 20..N   : ciphertext || 16-byte GCM tag
//
// v2 plaintext (inside the AEAD encryption) layout:
//
//   bytes  0..8   : per-credential monotonic counter (u64, little-endian)
//   bytes  8..M   : the secret value
//
// Every encrypt generates a fresh nonce via `getrandom`, so re-encrypting the
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
//
// The plaintext-embedded counter, plus the daemon-side high-water mark
// in VersionState, closes the rollback finding (Public review #2): a
// wholesale `/etc/credstore.encrypted/` snapshot restore reinstates
// ciphertexts with stale counters; the daemon detects the regression
// and refuses to decrypt.
//
// Legacy v1 files (no counter prefix in plaintext) still decrypt
// cleanly when the cred has never been seen as v2. As soon as the
// cred is re-set under v2, the counter is recorded and any future
// v1 swap-in is rejected as a downgrade attack.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use zeroize::Zeroizing;

use kepr_core::generate::ZeroString;
use kepr_core::secmem::GuardedKey;

use crate::crypto::Backend;
use crate::daemon_eco::cipher;
use crate::store;
use crate::version_state::VersionState;

const MAGIC_V1: &[u8] = b"kepr_v1\n";
const MAGIC_V2: &[u8] = b"kepr_v2\n";
const MAGIC_LEN: usize = 8;
const NONCE_LEN: usize = 12; // 96 bits — AES-GCM canonical nonce size
const TAG_LEN: usize = 16; // 128 bits — AES-GCM tag
const COUNTER_LEN: usize = 8; // u64 LE inside the v2 plaintext

/// AES-256-GCM credential backend. Holds the 32-byte master key as a
/// `GuardedKey` (T12.21: two XOR shares in secret memory, wiped and
/// unmapped on drop), and binds every ciphertext to `(uid, name)` via
/// AEAD additional data.
///
/// Wire formats supported:
///
///   kepr_v1 — legacy (Phase 0 α2a–α3). No counter; rollback
///             protection is opt-out for these files. The first
///             `set` rewrites them as v2.
///
///   kepr_v2 — current. Plaintext begins with an 8-byte little-endian
///             u64 counter that the daemon stamps from
///             `VersionState::next`. On decrypt the counter is checked
///             against the persisted high-water mark; a strictly lower
///             value means the on-disk file was rolled back and the
///             read is refused.
pub struct InProcBackend {
    master_key: Arc<RwLock<Option<GuardedKey<32>>>>,
    store_dir: PathBuf,
    versions: Arc<VersionState>,
}

impl InProcBackend {
    pub fn new(master_key: &[u8; 32], versions: Arc<VersionState>) -> Self {
        Self::with_store_dir(master_key, crate::store::store_dir(), versions)
    }

    pub fn with_store_dir(
        master_key: &[u8; 32],
        store_dir: PathBuf,
        versions: Arc<VersionState>,
    ) -> Self {
        Self {
            master_key: Arc::new(RwLock::new(Some(crate::crypto::guard_key(master_key)))),
            store_dir,
            versions,
        }
    }

    /// Drop the key: its regions are wiped and unmapped.
    pub fn lock(&self) {
        *self.master_key.write().expect("master-key lock poisoned") = None;
    }

    /// Install `master_key` in fresh secret regions (new addresses, new
    /// mask), so a snapshot from before the lock doesn't say where it is.
    pub fn unlock(&self, master_key: &[u8; 32]) -> Result<(), String> {
        let mut key = self
            .master_key
            .write()
            .map_err(|_| "master-key lock poisoned")?;
        if key.is_some() {
            return Err("credential store is already unlocked".to_string());
        }
        *key = Some(crate::crypto::guard_key(master_key));
        Ok(())
    }

    /// T12.22: move the key's shares to fresh random addresses under a
    /// fresh mask (every 60 s, from the sweeper). Ok when locked.
    pub fn relocate(&self) -> Result<(), String> {
        let mut key = self
            .master_key
            .write()
            .map_err(|_| "master-key lock poisoned")?;
        key.as_mut().map_or(Ok(()), GuardedKey::relocate)
    }

    pub fn is_locked(&self) -> bool {
        self.master_key
            .read()
            .map(|key| key.is_none())
            .unwrap_or(true)
    }

    /// A wiped-on-drop copy of the key, for callers that wrap or compare
    /// it (lock, recovery, escrow); None when locked.
    pub fn snapshot_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.with_key(|k| {
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(k);
            Ok(out)
        })
        .ok()
    }

    /// Where the key's shares are (diagnostics and tests); None when
    /// locked or held in ordinary memory.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn key_addrs(&self) -> Option<(usize, usize)> {
        self.master_key.read().ok()?.as_ref()?.addrs()
    }

    fn cred_path(&self, uid: u32, name: &str) -> PathBuf {
        self.store_dir.join(store::to_cred_name(uid, name))
    }

    fn aad(uid: u32, name: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + name.len());
        out.extend_from_slice(&uid.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out
    }

    /// Run `f` on the master key, recombined only for its duration; AEAD
    /// runs through the `daemon_eco::cipher` seam (RustCrypto, or
    /// aws-lc-rs with `fips`).
    fn with_key<R>(&self, f: impl FnOnce(&[u8; 32]) -> Result<R, String>) -> Result<R, String> {
        let key = self
            .master_key
            .read()
            .map_err(|_| "master-key lock poisoned".to_string())?;
        match key.as_ref() {
            Some(k) => k.with_key(f),
            None => Err(LOCKED.to_string()),
        }
    }
}

const LOCKED: &str = "credential store is locked";

impl Backend for InProcBackend {
    fn encrypt(&self, uid: u32, name: &str, value: &[u8]) -> Result<(), String> {
        let cred_name = store::to_cred_name(uid, name);
        // Fail before the counter moves; a lock racing in after this
        // fails the seal below and with_next rolls the counter back.
        if self.is_locked() {
            return Err(LOCKED.to_string());
        }
        let aad = Self::aad(uid, name);
        let cred_path = self.cred_path(uid, name);

        // Transactional counter advance: with_next holds the
        // VersionState mutex through the file write so a failed
        // write_atomic does not advance the recorded high-water mark
        // (which would brick the existing on-disk file at the older
        // counter), and so concurrent encrypts can't lose a
        // persistence ordering and let state regress on disk. Codex
        // flagged both failure modes on the prior shape.
        self.versions
            .with_next(&cred_name, |counter| {
                let mut nonce_bytes = [0u8; NONCE_LEN];
                getrandom::fill(&mut nonce_bytes).map_err(|e| format!("CSPRNG failure: {e}"))?;

                // v2 plaintext = [8B counter LE u64][secret bytes].
                // The counter is inside the AEAD plaintext so the GCM
                // tag binds it: any tamper with the counter on disk
                // fails the auth check.
                let mut plaintext = Zeroizing::new(Vec::with_capacity(COUNTER_LEN + value.len()));
                plaintext.extend_from_slice(&counter.to_le_bytes());
                plaintext.extend_from_slice(value);

                let ciphertext = self.with_key(|key| {
                    cipher::seal(key, &nonce_bytes, &aad, &plaintext)
                        .map_err(|_| "encryption failed".to_string())
                })?;

                let mut out = Vec::with_capacity(MAGIC_LEN + NONCE_LEN + ciphertext.len());
                out.extend_from_slice(MAGIC_V2);
                out.extend_from_slice(&nonce_bytes);
                out.extend_from_slice(&ciphertext);

                write_atomic(&cred_path, &out)
            })
            .map(|_| ())
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

        // Detect the wire version from the magic. A v1 file is treated
        // as counter=0 against the rollback check; the cred-name's
        // recorded counter must therefore be 0 too (no v2 has ever
        // been seen) for the decrypt to proceed. As soon as the
        // cred is rewritten via `set`, it becomes v2.
        let is_v2 = match &blob[..MAGIC_LEN] {
            m if m == MAGIC_V2 => true,
            m if m == MAGIC_V1 => false,
            _ => return Err("decryption failed: unrecognised format".to_string()),
        };

        let nonce_bytes: [u8; NONCE_LEN] = blob[MAGIC_LEN..header_len]
            .try_into()
            .expect("nonce slice is NONCE_LEN by construction");
        let ciphertext = &blob[header_len..];
        let aad = Self::aad(uid, name);

        // Zeroizing: the decrypted secret must not linger in freed heap.
        let plaintext = self.with_key(|key| {
            cipher::open(key, &nonce_bytes, &aad, ciphertext)
                .map_err(|_| "decryption failed: authentication".to_string())
        })?;

        // Split off the counter (v2) or treat as 0 (v1) BEFORE
        // building the ZeroString, so the secret bytes never share a
        // String with the counter prefix.
        let cred_name = store::to_cred_name(uid, name);
        let secret_bytes: &[u8] = if is_v2 {
            if plaintext.len() < COUNTER_LEN {
                return Err("decryption failed: v2 plaintext too short for counter".to_string());
            }
            let counter = u64::from_le_bytes(
                plaintext[..COUNTER_LEN]
                    .try_into()
                    .expect("COUNTER_LEN slice"),
            );
            self.versions
                .verify(&cred_name, counter)
                .map_err(|e| format!("decryption failed: {e}"))?;
            &plaintext[COUNTER_LEN..]
        } else {
            self.versions
                .verify(&cred_name, 0)
                .map_err(|e| format!("decryption failed: {e}"))?;
            &plaintext[..]
        };

        let s = std::str::from_utf8(secret_bytes)
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

        // Order matters: tombstone the counter FIRST, then remove
        // the file. Codex flagged the inverse on a re-review:
        // if remove_file succeeded and tombstone then failed
        // (e.g. /var/lib/kepr unwritable, ENOSPC), the on-disk
        // state had the ciphertext gone but the recorded counter
        // unchanged, leaving an attacker with a pre-delete
        // snapshot able to replay it because verify still
        // accepted the old counter.
        //
        // With the tombstone-first ordering, a tombstone failure
        // leaves the file intact and the counter unchanged — the
        // caller sees an error and the cred is unmodified. A
        // remove_file failure AFTER tombstone success leaves the
        // counter advanced and the file on disk; subsequent
        // decrypts would fail verify (file_counter < recorded),
        // so the cred reads as "credential unavailable" — better
        // than silently letting a replay through.
        let cred_name = store::to_cred_name(uid, name);
        self.versions.tombstone(&cred_name)?;
        fs::remove_file(&cred_path).map_err(|e| format!("cannot delete credential: {e}"))?;
        Ok(())
    }
}

/// Durable write of a credential file (see atomic_file.rs), creating the
/// store directory on first use.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("invalid credential path")?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|e| format!("cannot create credstore: {e}"))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot chmod credstore: {e}"))?;
    }
    crate::atomic_file::write(path, bytes, 0o600)
        .map_err(|e| format!("cannot install credential: {e}"))
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

    /// Spin up a backend pointing at a fresh temp directory, with a
    /// fresh VersionState in the same directory. Returns the backend
    /// AND the `TempDir` guard — keep the guard in scope until the
    /// assertions finish, otherwise the directory gets removed and
    /// reads / writes fail.
    fn fresh_backend() -> (InProcBackend, TempDir) {
        // Deterministic 32-byte test key. GCM's security comes from the
        // (key, nonce) pair being unique, not the key being secret from
        // the test runner; nonces are still drawn fresh from `getrandom`
        // inside the backend so per-encrypt freshness is preserved.
        let dir = tempfile::tempdir().expect("create tempdir");
        let state_path = dir.path().join("cred-versions.json");
        let versions = Arc::new(VersionState::load(state_path).expect("load fresh state"));
        let backend = InProcBackend::with_store_dir(&[0xAB; 32], dir.path().to_owned(), versions);
        (backend, dir)
    }

    /// Every mapping in /proc/self/maps as (start, end).
    fn mappings() -> Vec<(usize, usize)> {
        let maps = fs::read_to_string("/proc/self/maps").unwrap();
        maps.lines()
            .filter_map(|l| {
                let (a, b) = l.split_whitespace().next()?.split_once('-')?;
                Some((
                    usize::from_str_radix(a, 16).ok()?,
                    usize::from_str_radix(b, 16).ok()?,
                ))
            })
            .collect()
    }

    /// T12.21: two XOR shares in two secret regions, never one heap array.
    #[test]
    fn master_key_is_held_in_split_regions() {
        let (b, _dir) = fresh_backend();
        let (a, c) = b.key_addrs().expect("key held as split shares");
        assert_ne!(a, c);
        let maps = mappings();
        for addr in [a, c] {
            assert!(
                maps.iter().any(|(lo, hi)| *lo <= addr && addr < *hi),
                "share at {addr:#x} is not in any mapping"
            );
        }
        b.encrypt(TEST_UID, "SPLIT", b"hunter2").unwrap();
        assert_eq!(b.decrypt(TEST_UID, "SPLIT").unwrap().as_str(), "hunter2");
    }

    #[test]
    fn lock_drops_the_key() {
        let (b, _dir) = fresh_backend();
        b.lock();
        assert!(b.key_addrs().is_none());
        assert!(b.snapshot_key().is_none());
        let err = b.encrypt(TEST_UID, "LOCKED", b"v").unwrap_err();
        assert_eq!(err, "credential store is locked");
    }

    #[test]
    fn unlock_places_the_key_at_new_addresses() {
        let (b, _dir) = fresh_backend();
        b.encrypt(TEST_UID, "BEFORE_LOCK", b"kept").unwrap();
        let before = b.key_addrs().unwrap();
        b.lock();
        b.unlock(&[0xAB; 32]).unwrap();
        assert_ne!(b.key_addrs().unwrap(), before);
        assert_eq!(b.decrypt(TEST_UID, "BEFORE_LOCK").unwrap().as_str(), "kept");
    }

    /// T12.22: the sweeper's 60 s relocation.
    #[test]
    fn relocate_moves_shares_and_keeps_the_key() {
        let (b, _dir) = fresh_backend();
        b.encrypt(TEST_UID, "BEFORE_MOVE", b"kept").unwrap();
        let before = b.key_addrs().unwrap();
        b.relocate().unwrap();
        assert_ne!(b.key_addrs().unwrap(), before);
        assert_eq!(b.decrypt(TEST_UID, "BEFORE_MOVE").unwrap().as_str(), "kept");
    }

    #[test]
    fn relocate_on_a_locked_store_is_ok() {
        let (b, _dir) = fresh_backend();
        b.lock();
        assert_eq!(b.relocate(), Ok(()));
        assert!(b.is_locked() && b.key_addrs().is_none());
    }

    /// T7.16: the file format is the same whichever suite is active. A v2
    /// file written by the default build's RustCrypto opens through the
    /// backend (aws-lc-rs under `--features fips`), and the backend's own
    /// files open with RustCrypto.
    #[test]
    fn files_cross_between_default_and_fips_builds() {
        use crate::daemon_eco::cipher::{CipherSuite, RustCrypto};
        let (b, dir) = fresh_backend();
        let key = [0xAB; 32];
        let aad = InProcBackend::aad(TEST_UID, "CROSS");
        let nonce = [3u8; NONCE_LEN];
        let mut plain = 1u64.to_le_bytes().to_vec();
        plain.extend_from_slice(b"from-default-build");
        let ct = RustCrypto::seal(&key, &nonce, &aad, &plain).unwrap();
        let blob = [MAGIC_V2, &nonce, &ct].concat();
        let path = dir.path().join(store::to_cred_name(TEST_UID, "CROSS"));
        fs::write(&path, &blob).unwrap();
        assert_eq!(
            b.decrypt(TEST_UID, "CROSS").unwrap().as_str(),
            "from-default-build"
        );

        b.encrypt(TEST_UID, "CROSS", b"from-active-suite").unwrap();
        let blob = fs::read(&path).unwrap();
        let nonce: [u8; NONCE_LEN] = blob[MAGIC_LEN..MAGIC_LEN + NONCE_LEN].try_into().unwrap();
        let plain = RustCrypto::open(&key, &nonce, &aad, &blob[MAGIC_LEN + NONCE_LEN..]).unwrap();
        assert_eq!(&plain[COUNTER_LEN..], b"from-active-suite");
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
        let mut bogus = MAGIC_V2.to_vec();
        bogus.extend_from_slice(&[0u8; NONCE_LEN / 2]);
        fs::write(&p, &bogus).unwrap();

        let err = match b.decrypt(TEST_UID, "TRUNCATED") {
            Ok(_) => panic!("must reject truncated blob"),
            Err(e) => e,
        };
        assert!(err.contains("truncated"), "got: {err}");
    }

    #[test]
    fn delete_blocks_replay_of_pre_delete_snapshot() {
        // Codex re-review P1: deletion must keep a tombstone that
        // rejects replay of any ciphertext that existed before the
        // delete. Capture the latest ciphertext, delete, plant the
        // capture back — the decrypt must fail with rollback even
        // though the file's counter equals what was the high-water
        // mark immediately before the delete.
        let (b, _dir) = fresh_backend();
        b.encrypt(TEST_UID, "TOMBSTONE", b"original").unwrap();
        let captured = fs::read(b.cred_path(TEST_UID, "TOMBSTONE")).unwrap();

        b.delete(TEST_UID, "TOMBSTONE").unwrap();
        // Plant the captured ciphertext back as if from a snapshot.
        fs::write(b.cred_path(TEST_UID, "TOMBSTONE"), &captured).unwrap();

        let err = match b.decrypt(TEST_UID, "TOMBSTONE") {
            Ok(_) => panic!("replay of pre-delete file must be rejected"),
            Err(e) => e,
        };
        assert!(err.contains("rollback detected"), "got: {err}");
    }

    #[test]
    fn rollback_replay_is_rejected() {
        // Prove the rollback protection: capture the on-disk file at
        // counter=1, overwrite with counter=2, then drop the v2 file
        // back to its counter=1 form. Decrypt must refuse — the AEAD
        // tag accepts the file (it's the legitimate counter=1
        // ciphertext we kept), but VersionState's recorded high-water
        // mark is now 2, so verify() rejects.
        let (b, _dir) = fresh_backend();
        b.encrypt(TEST_UID, "ROLLBACK", b"v1-secret").unwrap();
        let counter1_blob = fs::read(b.cred_path(TEST_UID, "ROLLBACK")).unwrap();

        // Second encrypt = counter 2 on disk + state.
        b.encrypt(TEST_UID, "ROLLBACK", b"v2-secret").unwrap();

        // Sanity: decrypt of the current file returns the new value.
        let got = b.decrypt(TEST_UID, "ROLLBACK").unwrap();
        assert_eq!(got.as_str(), "v2-secret");

        // Drop the file back to the counter=1 ciphertext — this is
        // what an attacker with a stale snapshot of /etc/credstore.encrypted/
        // would do.
        fs::write(b.cred_path(TEST_UID, "ROLLBACK"), &counter1_blob).unwrap();

        // The AEAD will validate (counter=1 ciphertext is genuine),
        // but the rollback check must reject.
        let err = match b.decrypt(TEST_UID, "ROLLBACK") {
            Ok(_) => panic!("rollback must be rejected"),
            Err(e) => e,
        };
        assert!(err.contains("rollback detected"), "got: {err}");
    }

    #[test]
    fn legacy_v1_file_still_decrypts_when_state_is_clean() {
        // A pre-v2 file (kepr_v1 magic, no counter prefix in
        // plaintext) must still decrypt successfully when the
        // VersionState has never seen the cred. This is the
        // legitimate post-α3 / pre-rollback-protection upgrade path.
        let (b, dir) = fresh_backend();

        // Manually craft a v1 file: kepr_v1 magic + nonce + AES-GCM
        // ciphertext over the plaintext bytes (no counter prefix).
        let key = b.snapshot_key().unwrap();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).unwrap();
        let aad = InProcBackend::aad(TEST_UID, "LEGACY");
        let ciphertext = cipher::seal(&key[..], &nonce_bytes, &aad, b"legacy-value").unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC_V1);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);

        let path = dir.path().join(store::to_cred_name(TEST_UID, "LEGACY"));
        fs::write(&path, &blob).unwrap();

        // Decrypt against a fresh VersionState (recorded=0); v1 files
        // are treated as counter=0, so the verify passes.
        let got = b.decrypt(TEST_UID, "LEGACY").unwrap();
        assert_eq!(got.as_str(), "legacy-value");
    }

    #[test]
    fn legacy_v1_rejected_after_v2_has_been_seen() {
        // Once any v2 file has been written for a cred (state's
        // counter > 0), an attacker swapping in a v1 file is a
        // downgrade attack: the v1 file's implicit counter=0 is
        // strictly lower than the recorded counter, so verify
        // rejects.
        let (b, dir) = fresh_backend();
        b.encrypt(TEST_UID, "DOWNGRADE", b"v2-secret").unwrap(); // state=1

        // Plant a syntactically-valid v1 file under the same cred-name.
        let key = b.snapshot_key().unwrap();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).unwrap();
        let aad = InProcBackend::aad(TEST_UID, "DOWNGRADE");
        let ciphertext = cipher::seal(&key[..], &nonce_bytes, &aad, b"old-secret").unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC_V1);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        let path = dir.path().join(store::to_cred_name(TEST_UID, "DOWNGRADE"));
        fs::write(&path, &blob).unwrap();

        let err = match b.decrypt(TEST_UID, "DOWNGRADE") {
            Ok(_) => panic!("v1 swap-in after v2 must be rejected"),
            Err(e) => e,
        };
        assert!(err.contains("rollback detected"), "got: {err}");
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
        // `getrandom`. This is GCM's only confidentiality requirement; pin it.
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
