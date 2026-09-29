// master_key.rs — load-or-generate the 32-byte AES-256-GCM master key.
//
// System mode seals the random key with systemd-creds. User mode uses a
// local owner-only file by default. `kepr lock` can remove that unwrapped
// file and replace it with the Argon2id + AES-GCM envelope implemented in
// key_unlock.rs; the daemon then starts locked until `kepr unlock`.
//
// The Sealer trait keeps system and local startup protection injectable and
// testable. Password protection is deliberately a separate envelope: the
// credential-encryption key remains random 256-bit material and is never
// derived directly from a human password.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

const MASTER_KEY_LEN: usize = 32;
const URANDOM_PATH: &str = "/dev/urandom";
const SYSTEMD_CREDS_BIN: &str = "/usr/bin/systemd-creds";
const KEY_TYPE: &str = "host";
const SEALED_NAME: &str = "kepr-master-key";

/// Read 32 random bytes from /dev/urandom. Linux's CSPRNG is the right
/// source for long-term key material; getrandom(2) would be equivalent
/// but adds an extra dependency.
pub fn random_master_key() -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, String> {
    let mut key = [0u8; MASTER_KEY_LEN];
    let mut f = fs::File::open(URANDOM_PATH).map_err(|e| format!("open {URANDOM_PATH}: {e}"))?;
    f.read_exact(&mut key)
        .map_err(|e| format!("read {URANDOM_PATH}: {e}"))?;
    Ok(Zeroizing::new(key))
}

/// Pluggable seal/unseal layer. Production uses `SystemdCredsSealer`;
/// tests inject a `MockSealer` (defined in the test module) so the
/// orchestrator's logic can be exercised without a subprocess.
pub trait Sealer: Send + Sync {
    fn seal(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>, String>;
    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, String>;
}

/// Wraps `/usr/bin/systemd-creds {encrypt,decrypt} --with-key=host` over
/// stdin/stdout pipes. The host key is derived by systemd from a
/// per-machine secret; this is the same primitive the existing
/// SystemdCredsBackend uses, just applied once at startup to a 32-byte
/// blob instead of per-credential.
pub struct SystemdCredsSealer;

impl Sealer for SystemdCredsSealer {
    fn seal(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>, String> {
        let mut child = Command::new(SYSTEMD_CREDS_BIN)
            .args([
                "encrypt",
                &format!("--with-key={KEY_TYPE}"),
                "--name",
                SEALED_NAME,
                "-",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn credential backend: {e}"))?;

        child
            .stdin
            .as_mut()
            .ok_or_else(|| "stdin pipe missing".to_string())?
            .write_all(key)
            .map_err(|e| format!("write key to backend: {e}"))?;

        let out = child
            .wait_with_output()
            .map_err(|e| format!("backend wait: {e}"))?;
        if !out.status.success() {
            return Err("master-key seal failed".to_string());
        }
        Ok(out.stdout)
    }

    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, String> {
        let mut child = Command::new(SYSTEMD_CREDS_BIN)
            .args(["decrypt", "-", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn credential backend: {e}"))?;

        child
            .stdin
            .as_mut()
            .ok_or_else(|| "stdin pipe missing".to_string())?
            .write_all(blob)
            .map_err(|e| format!("write blob to backend: {e}"))?;

        let out = child
            .wait_with_output()
            .map_err(|e| format!("backend wait: {e}"))?;
        if !out.status.success() {
            return Err("master-key unseal failed".to_string());
        }
        if out.stdout.len() != MASTER_KEY_LEN {
            return Err(format!(
                "unseal returned {} bytes, expected {MASTER_KEY_LEN}",
                out.stdout.len()
            ));
        }
        let mut key = [0u8; MASTER_KEY_LEN];
        key.copy_from_slice(&out.stdout);
        Ok(Zeroizing::new(key))
    }
}

/// User-mode sealer. The master key is already protected by the owner-only
/// data directory and 0600 file permissions; no systemd, root daemon, or
/// external credential helper is required. System-mode deployments should
/// continue using `SystemdCredsSealer`.
pub struct LocalFileSealer;

impl Sealer for LocalFileSealer {
    fn seal(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>, String> {
        let backend = kepr_core::keyring::platform_keyring_backend();
        backend.seal_key(key)
    }

    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, String> {
        let backend = kepr_core::keyring::platform_keyring_backend();
        backend.unseal_key(blob)
    }
}

/// Returns true if `path` exists and contains an un-wrapped local master key.
pub fn is_unwrapped_local_key(path: &Path) -> bool {
    if let Ok(bytes) = fs::read(path) {
        bytes.starts_with(b"kepr-local-v1\n")
    } else {
        false
    }
}

/// Load the master key from `path`, or generate + seal + write it on
/// first run. The file is owned `root:root 0600`; the parent directory
/// is created with `0700` if it does not exist.
///
/// Idempotent across restarts: a present file is unsealed; an absent
/// file triggers generation. This is the only entry point the daemon
/// should call — `random_master_key` and the `Sealer` trait are
/// exposed for testability.
pub fn load_or_generate(
    path: &Path,
    sealer: &dyn Sealer,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, String> {
    if path.exists() {
        let blob = fs::read(path).map_err(|e| format!("read master key: {e}"))?;
        return sealer.unseal(&blob);
    }

    let key = random_master_key()?;
    let blob = sealer.seal(&key)?;

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| format!("create master-key dir: {e}"))?;
            // Parent must be tight too — only root reads the credstore root,
            // and only root reads the master key dir.
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("chmod master-key dir: {e}"))?;
        }
    }

    // Create with mode 0600 at open(2) time so the inode never exists
    // at any mode wider than the bits below — the previous shape
    // (fs::write then chmod) left a window where the master-key blob
    // was group/world readable under default umask. Codex flagged the
    // same pattern in crypto_inproc::write_atomic on a re-review pass.
    //
    // `create_new(true)` is the right shape here (rather than
    // `create(true)`) because mode(0o600) only applies to a NEW
    // inode. The write path is only reached when `path.exists()`
    // returned false above; re-entering it with the file present
    // would be a TOCTOU race we explicitly want to fail on rather
    // than reopen at a stale mode.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("open master key: {e}"))?;
    f.write_all(&blob)
        .map_err(|e| format!("write master key: {e}"))?;
    drop(f);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// In-memory sealer that just reverses the bytes — distinct from
    /// the input but trivially decodable. Good enough for the
    /// orchestrator's "round-trip the key through the file system"
    /// behaviour without requiring systemd-creds at test time.
    struct MockSealer {
        seals: Mutex<u32>,
        unseals: Mutex<u32>,
    }

    impl MockSealer {
        fn new() -> Self {
            Self {
                seals: Mutex::new(0),
                unseals: Mutex::new(0),
            }
        }
    }

    impl Sealer for MockSealer {
        fn seal(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>, String> {
            *self.seals.lock().unwrap() += 1;
            // Tag the blob with a magic prefix so unseal can sanity-check
            // that it was produced by this mock and not a real sealer.
            let mut out = Vec::with_capacity(4 + key.len());
            out.extend_from_slice(b"MOCK");
            out.extend(key.iter().rev());
            Ok(out)
        }

        fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, String> {
            *self.unseals.lock().unwrap() += 1;
            if blob.len() != 4 + MASTER_KEY_LEN || &blob[..4] != b"MOCK" {
                return Err("mock unseal: bad blob".to_string());
            }
            let mut key = [0u8; MASTER_KEY_LEN];
            for (i, b) in blob[4..].iter().rev().enumerate() {
                key[i] = *b;
            }
            Ok(Zeroizing::new(key))
        }
    }

    #[test]
    fn random_master_key_returns_32_bytes() {
        let k = random_master_key().expect("urandom must be readable");
        assert_eq!(k.len(), MASTER_KEY_LEN);
    }

    #[test]
    fn random_master_key_is_distinct_per_call() {
        // Two consecutive 32-byte draws from /dev/urandom must differ
        // with overwhelming probability. Equality would mean the CSPRNG
        // is broken or the test is reading a stub.
        let a = random_master_key().unwrap();
        let b = random_master_key().unwrap();
        assert_ne!(*a, *b, "two CSPRNG draws collided — broken RNG");
    }

    #[test]
    fn load_or_generate_creates_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/master.key");
        assert!(!path.exists());

        let sealer = MockSealer::new();
        let key = load_or_generate(&path, &sealer).expect("first call must succeed");

        assert!(path.exists(), "master key file must exist after generate");
        assert_eq!(*sealer.seals.lock().unwrap(), 1);
        assert_eq!(*sealer.unseals.lock().unwrap(), 0);
        assert_eq!(key.len(), MASTER_KEY_LEN);
    }

    #[test]
    fn load_or_generate_round_trips_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");

        let sealer = MockSealer::new();
        let first = load_or_generate(&path, &sealer).unwrap();
        let second = load_or_generate(&path, &sealer).unwrap();

        // Second call must unseal the same key, not re-generate.
        assert_eq!(*first, *second);
        assert_eq!(*sealer.seals.lock().unwrap(), 1, "seal called only once");
        assert_eq!(
            *sealer.unseals.lock().unwrap(),
            1,
            "unseal called on second load"
        );
    }

    #[test]
    fn load_or_generate_sets_secure_perms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/master.key");
        let sealer = MockSealer::new();
        load_or_generate(&path, &sealer).unwrap();

        // The master-key file must be 0600 even if the dir tree was
        // freshly created. Anyone reading the daemon's process tree
        // would otherwise be able to lift the sealed blob.
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "master key must be 0600, got {mode:o}");
        let parent_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            parent_mode, 0o700,
            "parent dir must be 0700, got {parent_mode:o}"
        );
    }

    #[test]
    fn load_or_generate_propagates_unseal_failure() {
        // Pre-write a bogus file; the mock sealer's unseal rejects it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        fs::write(&path, b"not a real sealed blob").unwrap();

        let sealer = MockSealer::new();
        let err = match load_or_generate(&path, &sealer) {
            Ok(_) => panic!("must reject bad sealed blob"),
            Err(e) => e,
        };
        assert!(err.contains("bad blob"), "got: {err}");
    }

    #[test]
    fn test_is_unwrapped_local_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        assert!(!is_unwrapped_local_key(&path));
        let sealer = LocalFileSealer;
        load_or_generate(&path, &sealer).unwrap();
        assert!(is_unwrapped_local_key(&path));
    }
}
