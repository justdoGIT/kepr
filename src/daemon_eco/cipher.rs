// cipher.rs — the daemon's crypto seam (T7.16).
// batch: eco
//
// AES-256-GCM and SHA-256 for data at rest go through one `CipherSuite`.
// The default build uses the RustCrypto crates; the `fips` cargo feature
// switches `Active` to aws-lc-rs (crypto_fips.rs). Both produce
// byte-identical output (AES-GCM is ciphertext || 16-byte tag), so the
// on-disk formats do not change and either build reads the other's files.
// Callers: crypto_inproc.rs (credential files), key_unlock.rs
// (passphrase-wrapped master key), daemon_recovery.rs (key proof and
// fingerprint), audit_chain.rs (hash chain). HMAC has no daemon caller
// outside the share envelopes' HKDF, which sits on X25519 (not a FIPS
// key agreement) and stays on RustCrypto.

use zeroize::Zeroizing;

pub const NONCE_LEN: usize = 12;

/// Authentication failure or bad key length; deliberately uninformative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError;

pub trait CipherSuite {
    /// Shown by `kepr status`.
    const NAME: &'static str;
    /// AES-256-GCM: ciphertext || tag.
    fn seal(
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    fn open(
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
    /// SHA-256 over the concatenation of `parts`.
    fn sha256(parts: &[&[u8]]) -> [u8; 32];
    /// True only when running inside a validated FIPS module.
    fn fips() -> bool;
}

/// The default suite. A `fips` build keeps it only for the cross-format
/// tests, so no production path can fall back to it.
#[cfg(any(not(feature = "fips"), test))]
pub struct RustCrypto;

#[cfg(any(not(feature = "fips"), test))]
impl CipherSuite for RustCrypto {
    const NAME: &'static str = "RustCrypto (aes-gcm, sha2)";

    fn seal(
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError)?;
        c.encrypt(&(*nonce).into(), Payload { msg, aad })
            .map_err(|_| CryptoError)
    }

    fn open(
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let c = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError)?;
        c.decrypt(&(*nonce).into(), Payload { msg: ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| CryptoError)
    }

    fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    fn fips() -> bool {
        false
    }
}

#[cfg(not(feature = "fips"))]
pub type Active = RustCrypto;
#[cfg(feature = "fips")]
pub type Active = super::crypto_fips::AwsLc;

pub fn seal(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    Active::seal(key, nonce, aad, msg)
}

pub fn open(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    Active::open(key, nonce, aad, ct)
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    Active::sha256(parts)
}

/// (provider name, running in a validated FIPS module).
pub fn describe() -> (&'static str, bool) {
    (Active::NAME, Active::fips())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // McGrew & Viega GCM spec, test case 16 (AES-256, 60-byte message, AAD).
    const K: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    const IV: &str = "cafebabefacedbaddecaf888";
    const P: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                     1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
    const A: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    const CT: &str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                      8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662\
                      76fc6ece0f4e1768cddf8853bb2d551b";

    fn nonce() -> [u8; NONCE_LEN] {
        h(IV).try_into().unwrap()
    }

    /// The same fixed vectors pass in the default and the `fips` build:
    /// ciphertext written by one build opens in the other.
    #[test]
    fn active_suite_matches_known_answers() {
        assert_eq!(seal(&h(K), &nonce(), &h(A), &h(P)).unwrap(), h(CT));
        assert_eq!(*open(&h(K), &nonce(), &h(A), &h(CT)).unwrap(), h(P));
        assert_eq!(
            sha256(&[b"a", b"bc"]).to_vec(),
            h("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn tampering_and_bad_keys_fail_closed() {
        let mut ct = h(CT);
        ct[0] ^= 1;
        assert_eq!(open(&h(K), &nonce(), &h(A), &ct), Err(CryptoError));
        assert_eq!(
            open(&h(K), &nonce(), b"other aad", &h(CT)),
            Err(CryptoError)
        );
        assert_eq!(seal(&[0u8; 16], &nonce(), b"", b"x"), Err(CryptoError));
        assert_eq!(open(&h(K), &nonce(), &h(A), &h(CT)[..10]), Err(CryptoError));
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn default_build_uses_rustcrypto() {
        assert_eq!(describe(), (RustCrypto::NAME, false));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn rustcrypto_and_aws_lc_read_each_others_output() {
        use super::super::crypto_fips::AwsLc;
        let key = [7u8; 32];
        let n = [9u8; NONCE_LEN];
        for len in [0usize, 1, 15, 16, 17, 1000] {
            let msg = vec![0x5a; len];
            let a = RustCrypto::seal(&key, &n, b"uid+name", &msg).unwrap();
            let b = AwsLc::seal(&key, &n, b"uid+name", &msg).unwrap();
            assert_eq!(a, b);
            assert_eq!(*AwsLc::open(&key, &n, b"uid+name", &a).unwrap(), msg);
            assert_eq!(*RustCrypto::open(&key, &n, b"uid+name", &b).unwrap(), msg);
            assert_eq!(RustCrypto::sha256(&[&msg]), AwsLc::sha256(&[&msg]));
        }
        assert_eq!(describe().0, AwsLc::NAME);
    }

    /// CI's FIPS job runs this with the validated module linked.
    #[cfg(feature = "fips")]
    #[test]
    #[ignore = "needs --features fips,aws-lc-rs/fips (Go + CMake)"]
    fn validated_module_reports_fips_mode() {
        assert!(describe().1);
    }
}
