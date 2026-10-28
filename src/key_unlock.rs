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
/// T13.20: like `kepr_pw1`, but the Argon2id cost is in the header and the
/// header is authenticated: `magic | m_kib u32 BE | t u32 BE | p u8 | salt |
/// nonce | ciphertext+tag`.
const MAGIC3: &[u8; 9] = b"kepr_pw3\n";
const HEADER3: usize = 9 + 4 + 4 + 1;
/// What a stored cost may be. A tampered envelope must not make the daemon
/// allocate gigabytes or hash for minutes before the tag is even checked.
const MIN_MEMORY_KIB: u32 = 8 * 1024;
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_ITERATIONS: u32 = 10;
const MAX_LANES: u8 = 8;
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
    derive_with(password, salt, (MEMORY_KIB, ITERATIONS, 1))
}

fn derive_with(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    (memory, iterations, lanes): (u32, u32, u8),
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let params = Params::new(memory, iterations, u32::from(lanes), Some(KEY_LEN))
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
    let mut out = Vec::with_capacity(HEADER3 + SALT_LEN + NONCE_LEN + KEY_LEN + TAG_LEN);
    out.extend_from_slice(MAGIC3);
    out.extend_from_slice(&MEMORY_KIB.to_be_bytes());
    out.extend_from_slice(&ITERATIONS.to_be_bytes());
    out.push(1);
    // The header is the AAD: the stored cost cannot be lowered unseen.
    let ciphertext = cipher::seal(key.as_ref(), &nonce, &out, master_key.as_ref())
        .map_err(|_| "master-key wrapping failed".to_string())?;
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
    if envelope.starts_with(MAGIC3) {
        return unwrap3(envelope, password);
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

fn unwrap3(envelope: &[u8], password: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let bad = || "invalid protected master-key envelope".to_string();
    if envelope.len() != HEADER3 + SALT_LEN + NONCE_LEN + KEY_LEN + TAG_LEN {
        return Err(bad());
    }
    let at = MAGIC3.len();
    let memory = u32::from_be_bytes(envelope[at..at + 4].try_into().expect("4 bytes"));
    let iterations = u32::from_be_bytes(envelope[at + 4..at + 8].try_into().expect("4 bytes"));
    let lanes = envelope[at + 8];
    if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory)
        || !(1..=MAX_ITERATIONS).contains(&iterations)
        || !(1..=MAX_LANES).contains(&lanes)
    {
        return Err(bad());
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&envelope[HEADER3..HEADER3 + SALT_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&envelope[HEADER3 + SALT_LEN..HEADER3 + SALT_LEN + NONCE_LEN]);
    let key = derive_with(password, &salt, (memory, iterations, lanes))?;
    let plaintext = cipher::open(
        key.as_ref(),
        &nonce,
        &envelope[..HEADER3],
        &envelope[HEADER3 + SALT_LEN + NONCE_LEN..],
    )
    .map_err(|_| "invalid password or protected master-key envelope".to_string())?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    if plaintext.len() != KEY_LEN {
        return Err("invalid protected master-key plaintext".to_string());
    }
    out.copy_from_slice(&plaintext);
    Ok(out)
}

/// Is this a `kepr_pw1` envelope that should be rewritten as `kepr_pw3`?
pub fn needs_upgrade(envelope: &[u8]) -> bool {
    envelope.starts_with(MAGIC)
}

/// After a successful unlock with `password`: replace a `kepr_pw1`
/// envelope at `path` with a `kepr_pw3` one for the same key. Best effort:
/// the old envelope stays valid if anything fails.
pub fn upgrade_at(path: &std::path::Path, password: &[u8], key: &[u8; KEY_LEN]) {
    let Ok(old) = std::fs::read(path) else { return };
    if !needs_upgrade(&old) {
        return;
    }
    if let Ok(new) = wrap(key, password) {
        if crate::atomic_file::write(path, &new, 0o600).is_err() {
            eprintln!(
                "[kepr-daemon] could not upgrade the passphrase envelope; it stays as it was"
            );
        }
    }
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
        envelope[SALT_LEN + HEADER3 + NONCE_LEN] ^= 1;
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

    /// Written by the code before kepr_pw3 existed.
    fn pw1_envelope(master: &[u8; KEY_LEN], password: &[u8]) -> Vec<u8> {
        let salt = [4u8; SALT_LEN];
        let nonce = [5u8; NONCE_LEN];
        let key = derive_key(password, &salt).unwrap();
        let ct = cipher::seal(key.as_ref(), &nonce, b"", master).unwrap();
        [&MAGIC[..], &salt, &nonce, &ct].concat()
    }

    #[test]
    fn a_pw1_envelope_from_the_old_code_still_opens_and_is_upgraded() {
        let master = [6u8; KEY_LEN];
        let old = pw1_envelope(&master, b"pw");
        assert_eq!(*unwrap(&old, b"pw").unwrap(), master);
        assert!(needs_upgrade(&old));
        let new = wrap(&master, b"pw").unwrap();
        assert!(new.starts_with(MAGIC3), "wrap writes the new format");
        assert!(!needs_upgrade(&new));
        assert_eq!(*unwrap(&new, b"pw").unwrap(), master);
    }

    #[test]
    fn a_pw3_envelope_carries_and_authenticates_its_cost() {
        let master = [8u8; KEY_LEN];
        let env = wrap(&master, b"pw").unwrap();
        let at = MAGIC3.len();
        assert_eq!(
            u32::from_be_bytes(env[at..at + 4].try_into().unwrap()),
            MEMORY_KIB
        );
        // Lowering the stored cost changes the key, and the header is part
        // of what the tag covers: nothing opens.
        let mut weak = env.clone();
        weak[at..at + 4].copy_from_slice(&(MIN_MEMORY_KIB).to_be_bytes());
        assert!(unwrap(&weak, b"pw").is_err());
    }

    #[test]
    fn costs_outside_the_bounds_are_refused_before_any_hashing() {
        let master = [1u8; KEY_LEN];
        let env = wrap(&master, b"pw").unwrap();
        let at = MAGIC3.len();
        let patch = |m: u32, t: u32, p: u8| {
            let mut e = env.clone();
            e[at..at + 4].copy_from_slice(&m.to_be_bytes());
            e[at + 4..at + 8].copy_from_slice(&t.to_be_bytes());
            e[at + 8] = p;
            e
        };
        let start = std::time::Instant::now();
        for bad in [
            patch(4 * 1024 * 1024, 3, 1), // 4 GiB
            patch(MEMORY_KIB, 0, 1),      // no passes
            patch(MEMORY_KIB, 11, 1),     // too many passes
            patch(MEMORY_KIB, 3, 0),      // no lanes
            patch(MEMORY_KIB, 3, 255),    // too many lanes
            patch(1024, 3, 1),            // under 8 MiB
        ] {
            assert_eq!(
                unwrap(&bad, b"pw").unwrap_err(),
                "invalid protected master-key envelope"
            );
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "no hashing happened"
        );
    }

    #[test]
    fn unlock_rewrites_an_old_envelope_in_place() {
        let master = [2u8; KEY_LEN];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key.argon2id");
        std::fs::write(&path, pw1_envelope(&master, b"pw")).unwrap();
        upgrade_at(&path, b"pw", &master);
        let now = std::fs::read(&path).unwrap();
        assert!(now.starts_with(MAGIC3));
        assert_eq!(*unwrap(&now, b"pw").unwrap(), master);
        // A new-format envelope is left alone, byte for byte.
        upgrade_at(&path, b"pw", &master);
        assert_eq!(std::fs::read(&path).unwrap(), now);
        // A missing file is not an error.
        upgrade_at(&dir.path().join("none"), b"pw", &master);
    }
}
