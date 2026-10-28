//! Optional password protection for the kepr master key.
//!
//! The credential files remain AES-256-GCM encrypted. This module protects the
//! random credential-encryption key at rest with Argon2id-derived AES-256-GCM.
//! It deliberately does not replace the random master key with a password:
//! password entropy is only used to wrap that key.
//!
//! T4.09: a password that carries a FIDO2 factor (kepr_core::seal_factor)
//! selects the `kepr_pw2` envelope of daemon_seal/fido2_kek.rs, which
//! needs the passphrase and the security key's `hmac-secret` output.

use argon2::{Algorithm, Argon2, Params, Version};
use kepr_core::seal_factor::split_factor;
use zeroize::Zeroizing;

use crate::daemon_eco::cipher;
use crate::daemon_seal::fido2_kek;

const MAGIC: &[u8; 9] = b"kepr_pw1\n";
/// T11.13: what replaces the envelope after an opt-in wipe. Never a valid
/// envelope; a restarted daemon stays locked until a recovery restore.
pub const WIPED: &[u8] = b"kepr_pw_wiped\n";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;

pub(crate) fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, 1, Some(KEY_LEN))
        .map_err(|e| format!("invalid Argon2 parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| format!("password key derivation failed: {e}"))?;
    Ok(key)
}

/// Wrap a random 32-byte master key. The returned envelope contains no
/// plaintext key and is safe to write with mode 0600.
pub fn wrap(master_key: &[u8; KEY_LEN], password: &[u8]) -> Result<Vec<u8>, String> {
    // T4.09: a passphrase that carries a security-key factor makes a
    // `kepr_pw2` envelope that needs both.
    let (factor, password) = split_factor(password)?;
    if let Some(f) = factor {
        return fido2_kek::wrap_with(master_key, password, &f, derive_key);
    }
    if password.is_empty() {
        return Err("password cannot be empty".to_string());
    }
    let mut salt = [0u8; SALT_LEN];
    cipher::fill_random(&mut salt).map_err(|_| "CSPRNG failure".to_string())?;
    let key = derive_key(password, &salt)?;
    let mut nonce = [0u8; NONCE_LEN];
    cipher::fill_random(&mut nonce).map_err(|_| "CSPRNG failure".to_string())?;
    let ciphertext = cipher::seal(key.as_ref(), &nonce, b"", master_key.as_ref())
        .map_err(|_| "master-key wrapping failed".to_string())?;

    let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + KEY_LEN + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unwrap a password-protected master key. Authentication failures are
/// intentionally indistinguishable from malformed envelopes.
pub fn unwrap(envelope: &[u8], password: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let (factor, password) = split_factor(password)?;
    if fido2_kek::is_fido2(envelope) {
        return fido2_kek::unwrap_with(envelope, password, factor.as_ref(), derive_key);
    }
    if password.is_empty() {
        return Err("password cannot be empty".to_string());
    }
    let expected = MAGIC.len() + SALT_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;
    if envelope.len() != expected || &envelope[..MAGIC.len()] != MAGIC {
        return Err("invalid protected master-key envelope".to_string());
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&envelope[MAGIC.len()..MAGIC.len() + SALT_LEN]);
    let nonce_start = MAGIC.len() + SALT_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&envelope[nonce_start..nonce_start + NONCE_LEN]);
    let ciphertext = &envelope[nonce_start + NONCE_LEN..];
    let key = derive_key(password, &salt)?;
    let plaintext = cipher::open(key.as_ref(), &nonce, b"", ciphertext)
        .map_err(|_| "invalid password or protected master-key envelope".to_string())?;
    if plaintext.len() != KEY_LEN {
        return Err("invalid protected master-key plaintext".to_string());
    }
    let mut key_out = Zeroizing::new([0u8; KEY_LEN]);
    key_out.copy_from_slice(&plaintext);
    Ok(key_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_uses_random_salt_and_nonce() {
        let master = [7u8; KEY_LEN];
        let one = wrap(&master, b"correct horse battery staple").unwrap();
        let two = wrap(&master, b"correct horse battery staple").unwrap();
        assert_ne!(one, two);
        assert_eq!(
            *unwrap(&one, b"correct horse battery staple").unwrap(),
            master
        );
    }

    #[test]
    fn rejects_wrong_password_and_tampering() {
        let master = [9u8; KEY_LEN];
        let mut envelope = wrap(&master, b"secret").unwrap();
        assert!(unwrap(&envelope, b"wrong").is_err());
        envelope[SALT_LEN + MAGIC.len() + NONCE_LEN] ^= 1;
        assert!(unwrap(&envelope, b"secret").is_err());
    }

    #[test]
    fn a_fido2_factor_selects_the_two_factor_envelope() {
        use kepr_core::seal_factor::{compose_factor, Fido2Factor};
        let factor = || Fido2Factor {
            credential_id: vec![7; 48],
            salt: [8; 32],
            hmac: Zeroizing::new([9; 32]),
        };
        let master = [3u8; KEY_LEN];
        let secret = compose_factor("secret", &factor());
        let envelope = wrap(&master, secret.as_bytes()).unwrap();
        assert!(fido2_kek::is_fido2(&envelope));
        // The passphrase alone no longer opens it.
        let e = unwrap(&envelope, b"secret").unwrap_err();
        assert!(e.contains("security key"), "{e}");
        assert_eq!(*unwrap(&envelope, secret.as_bytes()).unwrap(), master);
    }
}
