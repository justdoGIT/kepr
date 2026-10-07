// master_key.rs — load-or-generate the 32-byte AES-256-GCM master key.
//
// System mode seals the random key with systemd-creds. User mode uses a
// local owner-only file by default. `kepr lock` can remove that unwrapped
// file and replace it with the Argon2id + AES-GCM envelope implemented in
// key_unlock.rs; the daemon then starts locked until `kepr unlock`.
//
// The Sealer trait keeps system and local startup protection injectable and
// testable. The other sealers (TPM2 PIN / counter, bring-your-own-key KMS
// and HSM, the macOS Keychain) live in daemon_seal/ and are picked by
// `sealer_from_env`; the default path stays as below. Password protection is deliberately a separate envelope: the
// credential-encryption key remains random 256-bit material and is never
// derived directly from a human password.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

const MASTER_KEY_LEN: usize = 32;
const SYSTEMD_CREDS_BIN: &str = "/usr/bin/systemd-creds";
const KEY_TYPE: &str = "host";
const SEALED_NAME: &str = "kepr-master-key";
/// T4.11: the other sealers `KEPR_MASTER_KEY_SEAL` can name (daemon_seal).
const BYOK_KINDS: &str = "aws-kms:ARN, gcp-kms:NAME, azure-kv:URL";

/// Read 32 random bytes from /dev/urandom. Linux's CSPRNG is the right
/// source for long-term key material; getrandom(2) would be equivalent
/// but adds an extra dependency.
pub fn random_master_key() -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, String> {
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    getrandom::fill(key.as_mut()).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(key)
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

/// Arguments for sealing a new master key (P4.3). `KEPR_MASTER_KEY_SEAL`
/// picks what the key is bound to: `host` (default: the machine's
/// credential secret), `tpm2`, `host+tpm2` or `auto`. `KEPR_TPM2_PCRS`
/// (e.g. `7` or `7+11`) binds TPM2 sealing to those PCRs, so a changed
/// boot chain cannot unseal it. Values are allow-listed; decrypt detects
/// the sealing type itself, so existing keys keep working.
pub fn seal_args(seal: Option<&str>, pcrs: Option<&str>) -> Result<Vec<String>, String> {
    let kind = seal.unwrap_or(KEY_TYPE);
    if !matches!(kind, "host" | "tpm2" | "host+tpm2" | "auto") {
        return Err(format!(
            "KEPR_MASTER_KEY_SEAL={kind}: use host, tpm2, host+tpm2, auto or {BYOK_KINDS}"
        ));
    }
    let mut args = vec!["encrypt".to_string(), format!("--with-key={kind}")];
    if let Some(p) = pcrs.filter(|p| !p.is_empty()) {
        let valid = p.split('+').all(|n| n.parse::<u8>().is_ok_and(|n| n <= 23));
        if !valid || !kind.contains("tpm2") && kind != "auto" {
            return Err(format!(
                "KEPR_TPM2_PCRS={p}: PCR numbers 0-23 joined by '+', with a tpm2 seal"
            ));
        }
        args.push(format!("--tpm2-pcrs={p}"));
    }
    args.extend(["--name", SEALED_NAME, "-", "-"].map(String::from));
    Ok(args)
}

impl Sealer for SystemdCredsSealer {
    fn seal(&self, key: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>, String> {
        let args = seal_args(
            std::env::var("KEPR_MASTER_KEY_SEAL").ok().as_deref(),
            std::env::var("KEPR_TPM2_PCRS").ok().as_deref(),
        )?;
        let mut child = Command::new(SYSTEMD_CREDS_BIN)
            .args(&args)
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
        let stdout = Zeroizing::new(out.stdout);
        if !out.status.success() {
            return Err("master-key unseal failed".to_string());
        }
        if stdout.len() != MASTER_KEY_LEN {
            return Err(format!(
                "unseal returned {} bytes, expected {MASTER_KEY_LEN}",
                stdout.len()
            ));
        }
        let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        key.copy_from_slice(&stdout);
        Ok(key)
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

/// The sealer for a daemon's master key at `path`. `KEPR_MASTER_KEY_SEAL`
/// and the TPM2 PIN / counter options (T4.08) can pick another one
/// (daemon_seal::sealer_for); otherwise user mode keeps the local file
/// and system mode the machine's credential sealer.
pub fn sealer_from_env(user: bool, path: &Path) -> Result<Box<dyn Sealer>, String> {
    let seal = std::env::var("KEPR_MASTER_KEY_SEAL").ok();
    let dir = path.parent().unwrap_or(Path::new("."));
    if let Some(s) = crate::daemon_seal::sealer_for(seal.as_deref(), dir)? {
        return Ok(s);
    }
    Ok(if user {
        Box::new(LocalFileSealer)
    } else {
        Box::new(SystemdCredsSealer)
    })
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
        // The local sealer's blob contains the key itself.
        let blob = Zeroizing::new(fs::read(path).map_err(|e| format!("read master key: {e}"))?);
        return sealer.unseal(&blob);
    }

    let key = random_master_key()?;
    let blob = Zeroizing::new(sealer.seal(&key)?);

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
    // Write to a temp file, fsync, then rename: a crash mid-write must
    // never leave a torn master.key (every credential would become
    // unreadable and the daemon would refuse to start).
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(&blob).and_then(|_| f.sync_all()))
        .and_then(|_| fs::hard_link(&tmp, path));
    let _ = fs::remove_file(&tmp);
    written.map_err(|e| format!("write master key: {e}"))?;
    if let Some(dir) = path.parent().and_then(|d| fs::File::open(d).ok()) {
        let _ = dir.sync_all();
    }
    Ok(key)
}

#[cfg(test)]
mod tests {

    #[test]
    fn seal_args_allow_list() {
        let a = seal_args(None, None).unwrap();
        assert_eq!(a[1], "--with-key=host");
        let a = seal_args(Some("host+tpm2"), Some("7+11")).unwrap();
        assert!(a.contains(&"--tpm2-pcrs=7+11".to_string()));
        assert!(seal_args(Some("evil; rm -rf"), None).is_err());
        assert!(seal_args(Some("tpm2"), Some("7+99")).is_err());
        assert!(seal_args(Some("tpm2"), Some("7;x")).is_err());
        assert!(
            seal_args(Some("host"), Some("7")).is_err(),
            "PCRs need a tpm2 seal"
        );
    }

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
}
