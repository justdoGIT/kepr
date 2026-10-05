// daemon_vault/keys.rs — the image's key schedule and AEAD helpers.
//
// Every image key comes from the daemon's master key (the KEK) through
// HKDF-SHA256 with the image's random salt, one `info` label per use.
// Nothing here is stored: keys are derived per operation and wiped on
// drop, so a locked store leaves no usable key behind.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const SALT: usize = 32;
pub const NONCE: usize = 12;
pub const TAG: usize = 16;

/// Per-image keys, derived from the daemon's master key (KEK) and the
/// image's salt. Wiped on drop.
pub struct Keys {
    pub header: Zeroizing<[u8; 32]>,
    /// Seals the journal slot (T4.04).
    pub journal: Zeroizing<[u8; 32]>,
}

impl Keys {
    pub fn derive(kek: &[u8; 32], salt: &[u8; SALT]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(salt), kek);
        let k = |info: &[u8]| {
            let mut out = Zeroizing::new([0u8; 32]);
            hk.expand(info, out.as_mut())
                .expect("32 bytes is a valid HKDF length");
            out
        };
        Self {
            header: k(b"kepr-vi1 header"),
            journal: k(b"kepr-vi1 journal"),
        }
    }
}

pub(super) fn noise(buf: &mut [u8]) -> Result<(), String> {
    getrandom::fill(buf).map_err(|e| format!("CSPRNG failure: {e}"))
}

/// AES-256-GCM with a fresh random nonce: nonce ‖ ciphertext ‖ tag.
pub(super) fn gcm_seal(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE];
    noise(&mut nonce)?;
    let ct = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "invalid key")?
        .encrypt(&nonce.into(), Payload { msg, aad })
        .map_err(|_| "encryption failed")?;
    Ok([&nonce[..], &ct].concat())
}

/// Inverse of `gcm_seal`; every failure is the same message.
pub(super) fn gcm_open(
    key: &[u8; 32],
    aad: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    const FAIL: &str = "decryption failed: authentication";
    if blob.len() < NONCE + TAG {
        return Err(FAIL.into());
    }
    let nonce: [u8; NONCE] = blob[..NONCE].try_into().expect("12 bytes");
    let msg = &blob[NONCE..];
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| "invalid key")?
        .decrypt(&nonce.into(), Payload { msg, aad })
        .map(Zeroizing::new)
        .map_err(|_| FAIL.to_string())
}
