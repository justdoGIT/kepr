//! Cross-platform `KeyringBackend` trait and host keyring implementations.
//!
//! STATUS: only `LinuxKeyringBackend` is a deliberate design choice today
//! (see its doc comment). `MacOSKeyringBackend` and `WindowsKeyringBackend`
//! are trait-conformant placeholders that do **not** yet call the Keychain
//! or DPAPI APIs their names suggest — they currently perform the exact
//! same "prepend a label, store the raw key" no-op as the Linux backend.
//! Do not advertise macOS/Windows master-key protection as
//! OS-keyring-backed until real `Security.framework` / `CryptProtectData`
//! FFI lands here; tracked as a follow-up (no Windows/macOS CI runner
//! exists in this repo to validate real platform crypto FFI).

use zeroize::Zeroizing;

/// Seal/unseal a 32-byte AES master key against a host-specific backend.
pub trait KeyringBackend: Send + Sync {
    /// Human-readable name of the keyring backend.
    fn name(&self) -> &'static str;
    /// Seal a 32-byte AES master key into an envelope byte buffer.
    fn seal_key(&self, key: &[u8; 32]) -> Result<Vec<u8>, String>;
    /// Unseal an envelope byte buffer back into a 32-byte AES master key.
    fn unseal_key(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String>;
}

/// Linux file/envelope keyring backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxKeyringBackend;

impl KeyringBackend for LinuxKeyringBackend {
    fn name(&self) -> &'static str {
        "linux-envelope"
    }

    fn seal_key(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let mut blob = b"kepr-local-v1\n".to_vec();
        blob.extend_from_slice(key);
        Ok(blob)
    }

    fn unseal_key(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        const PREFIX: &[u8] = b"kepr-local-v1\n";
        if blob.len() != PREFIX.len() + 32 || !blob.starts_with(PREFIX) {
            return Err("invalid linux envelope keyring format".to_string());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&blob[PREFIX.len()..]);
        Ok(Zeroizing::new(out))
    }
}

/// PLACEHOLDER — not wired to macOS Keychain yet. Currently performs the
/// same unencrypted label+key envelope as `LinuxKeyringBackend`; real
/// protection relies entirely on the 0600 file permissions of the state
/// directory that stores the sealed blob, same as Linux. See module docs.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacOSKeyringBackend;

impl KeyringBackend for MacOSKeyringBackend {
    fn name(&self) -> &'static str {
        "macos-keychain"
    }

    fn seal_key(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let mut blob = b"kepr-mac-v1\n".to_vec();
        blob.extend_from_slice(key);
        Ok(blob)
    }

    fn unseal_key(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        const PREFIX: &[u8] = b"kepr-mac-v1\n";
        if blob.len() != PREFIX.len() + 32 || !blob.starts_with(PREFIX) {
            return Err("invalid macos keychain keyring format".to_string());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&blob[PREFIX.len()..]);
        Ok(Zeroizing::new(out))
    }
}

/// PLACEHOLDER — not wired to Windows DPAPI (`CryptProtectData`) yet.
/// Currently performs the same unencrypted label+key envelope as
/// `LinuxKeyringBackend`; real protection relies entirely on host
/// filesystem ACLs on the state directory. See module docs.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsKeyringBackend;

impl KeyringBackend for WindowsKeyringBackend {
    fn name(&self) -> &'static str {
        "windows-dpapi"
    }

    fn seal_key(&self, key: &[u8; 32]) -> Result<Vec<u8>, String> {
        let mut blob = b"kepr-dpapi-v1\n".to_vec();
        blob.extend_from_slice(key);
        Ok(blob)
    }

    fn unseal_key(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        const PREFIX: &[u8] = b"kepr-dpapi-v1\n";
        if blob.len() != PREFIX.len() + 32 || !blob.starts_with(PREFIX) {
            return Err("invalid windows dpapi keyring format".to_string());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&blob[PREFIX.len()..]);
        Ok(Zeroizing::new(out))
    }
}

/// Factory returning the default `KeyringBackend` for the current platform.
pub fn platform_keyring_backend() -> Box<dyn KeyringBackend> {
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOSKeyringBackend)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsKeyringBackend)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Box::new(LinuxKeyringBackend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_keyring_backend_round_trip() {
        let backend = platform_keyring_backend();
        let test_key = [0x42u8; 32];
        let sealed = backend.seal_key(&test_key).expect("seal key");
        let unsealed = backend.unseal_key(&sealed).expect("unseal key");
        assert_eq!(*unsealed, test_key);
    }
}
