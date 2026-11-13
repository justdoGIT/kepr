//! Cross-platform `KeyringBackend` trait and host keyring implementations.
//!
//! Linux deliberately uses a permissions-protected local envelope. The
//! macOS/Windows types remain API-compatible unavailable backends and fail
//! closed until verified native implementations exist. They never return
//! raw-key envelopes under an OS-protection label. The daemon's separate
//! macOS Keychain sealer is not implemented by this interface.

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

/// Unavailable macOS backend; native Keychain integration is required.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacOSKeyringBackend;

impl KeyringBackend for MacOSKeyringBackend {
    fn name(&self) -> &'static str {
        "macos-keychain-unavailable"
    }

    fn seal_key(&self, _key: &[u8; 32]) -> Result<Vec<u8>, String> {
        Err("macOS Keychain backend is unavailable; no key material was written".into())
    }

    fn unseal_key(&self, _blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        Err("macOS Keychain backend is unavailable; operator migration of legacy envelopes is required".into())
    }
}

/// Unavailable Windows backend; verified DPAPI integration is required.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsKeyringBackend;

impl KeyringBackend for WindowsKeyringBackend {
    fn name(&self) -> &'static str {
        "windows-dpapi-unavailable"
    }

    fn seal_key(&self, _key: &[u8; 32]) -> Result<Vec<u8>, String> {
        Err("Windows DPAPI backend is unavailable; no key material was written".into())
    }

    fn unseal_key(&self, _blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        Err("Windows DPAPI backend is unavailable; operator migration of legacy envelopes is required".into())
    }
}

/// Unsupported platforms never inherit Linux's local-envelope behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedKeyringBackend;

impl KeyringBackend for UnsupportedKeyringBackend {
    fn name(&self) -> &'static str {
        "unsupported-os"
    }
    fn seal_key(&self, _key: &[u8; 32]) -> Result<Vec<u8>, String> {
        Err("no supported keyring backend for this OS".into())
    }
    fn unseal_key(&self, _blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
        Err("no supported keyring backend for this OS".into())
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
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxKeyringBackend)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Box::new(UnsupportedKeyringBackend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_placeholder_refuses_to_wrap_or_recover_raw_keys() {
        let key = [0x42; 32];
        let mut legacy = b"kepr-mac-v1\n".to_vec();
        legacy.extend_from_slice(&key);
        assert!(MacOSKeyringBackend.seal_key(&key).is_err());
        assert!(MacOSKeyringBackend.unseal_key(&legacy).is_err());
    }

    #[test]
    fn windows_placeholder_refuses_to_wrap_or_recover_raw_keys() {
        let key = [0x42; 32];
        let mut legacy = b"kepr-dpapi-v1\n".to_vec();
        legacy.extend_from_slice(&key);
        assert!(WindowsKeyringBackend.seal_key(&key).is_err());
        assert!(WindowsKeyringBackend.unseal_key(&legacy).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_platform_keyring_backend_round_trip() {
        let backend = platform_keyring_backend();
        let test_key = [0x42u8; 32];
        let sealed = backend.seal_key(&test_key).expect("seal key");
        let unsealed = backend.unseal_key(&sealed).expect("unseal key");
        assert_eq!(*unsealed, test_key);
    }
}
