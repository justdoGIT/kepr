// daemon_vault/keys.rs — the image's key schedule and AEAD helpers.
//
// Every image key comes from the daemon's master key (the KEK) through
// HKDF-SHA256 with the image's random salt, one `info` label per use.
// Nothing here is stored: keys are derived per operation and wiped on
// drop, so a locked store leaves no usable key behind.

use zeroize::Zeroizing;

use crate::daemon_eco::cipher;

pub const SALT: usize = 32;
pub const NONCE: usize = 12;
pub const TAG: usize = 16;

/// Per-image keys, derived from the daemon's master key (KEK) and the
/// image's salt. Wiped on drop.
pub struct Keys {
    pub header: Zeroizing<[u8; 32]>,
    /// Seals the journal slot (T4.04).
    pub journal: Zeroizing<[u8; 32]>,
    /// HMAC key for slot placement (T4.03).
    pub place: Zeroizing<[u8; 32]>,
    /// Vault master key: wraps each record's own key (T4.05).
    pub vmk: Zeroizing<[u8; 32]>,
    /// HKDF(vmk, "index"): seals the index pages (T4.05).
    pub index: Zeroizing<[u8; 32]>,
}

impl Keys {
    pub fn derive(kek: &[u8; 32], salt: &[u8; SALT]) -> Self {
        let expand = |info: &[u8]| cipher::hkdf_sha256(Some(salt), kek, &[info]);
        let vmk = expand(b"kepr-vi1 vmk");
        let index = cipher::hkdf_sha256(None, vmk.as_ref(), &[b"index"]);
        Self {
            header: expand(b"kepr-vi1 header"),
            journal: expand(b"kepr-vi1 journal"),
            place: expand(b"kepr-vi1 place"),
            vmk,
            index,
        }
    }
}

pub(super) fn noise(buf: &mut [u8]) -> Result<(), String> {
    cipher::fill_random(buf).map_err(|_| "CSPRNG failure".to_string())
}

/// AES-256-GCM with a fresh random nonce: nonce ‖ ciphertext ‖ tag.
pub(super) fn gcm_seal(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE];
    noise(&mut nonce)?;
    let ct = cipher::seal(key, &nonce, aad, msg).map_err(|_| "encryption failed")?;
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
    cipher::open(key, &nonce, aad, msg).map_err(|_| FAIL.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::Aes256Gcm;

    #[test]
    fn derive_is_pinned() {
        let k = Keys::derive(&[7; 32], &[9; 32]);
        for (got, want) in [
            (
                &k.header,
                "878e644e29ac7dd267f06c6d1e66072f9a7c1fa8b913a429faac9da5e6887522",
            ),
            (
                &k.journal,
                "af4438e90b9fc2cc766e68313962b93addf16289f1b40390c59edd5dcc6c63d3",
            ),
            (
                &k.place,
                "112f714069d8440bb1032ce5ae1891ea0a587d101db41d83addf65d085dd9ce5",
            ),
            (
                &k.vmk,
                "6108f0076b96821a852f7e71e002f0b6ad8951adbf65afd9ac746b9475398853",
            ),
            (
                &k.index,
                "4dfca3833843ab32c7e8c2118183756aa127bc7832a6e020d07b823af3ca14fc",
            ),
        ] {
            assert_eq!(hex::encode(got.as_ref()), want);
        }
    }

    #[test]
    fn gcm_open_reads_pinned_blob() {
        let (key, aad, nonce) = ([1u8; 32], b"slot", [2u8; NONCE]);
        let ct = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: b"pinned",
                    aad,
                },
            )
            .unwrap();
        let blob = [&nonce[..], &ct].concat();
        assert_eq!(
            hex::encode(&blob),
            "02020202020202020202020277bfa7272f338a38413c154c6b7adfcabf3b1bcb1564"
        );
        assert_eq!(&**gcm_open(&key, aad, &blob).unwrap(), b"pinned");
    }
}
