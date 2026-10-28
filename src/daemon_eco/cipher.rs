// cipher.rs — the daemon's crypto seam (T7.16).
// batch: eco
//
// AES-256-GCM and SHA-256 for data at rest go through one `CipherSuite`.
// The default build uses the RustCrypto crates; the `fips` cargo feature
// switches `Active` to aws-lc-rs (crypto_fips.rs). Both produce
// byte-identical output (AES-GCM is ciphertext || 16-byte tag), so the
// on-disk formats do not change and either build reads the other's files.
// HMAC-SHA256, HKDF-SHA256 and key/nonce randomness go through it too
// (T12.39), so a `fips` build runs them in aws-lc-rs as well. Callers:
// crypto_inproc.rs (credential files), key_unlock.rs (passphrase-wrapped
// master key), master_key.rs (key generation), daemon_recovery.rs (key proof
// and fingerprint), audit_chain.rs (hash chain). tests/crypto_seam.rs lists
// the files that still use the RustCrypto crates directly.

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
    // The HMAC and HKDF methods have no production caller until T12.40-T12.42
    // move the files listed in tests/crypto_seam.rs over; drop the allows then.
    /// HMAC-SHA256 over the concatenation of `parts`.
    fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32];
    /// Constant-time check of a full 32-byte tag; any other length is false.
    fn hmac_sha256_verify(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool;
    /// HKDF-SHA256 (RFC 5869) to 32 bytes; `None` salt is the RFC's zero salt.
    /// `info` is the concatenation of its parts.
    fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[&[u8]]) -> Zeroizing<[u8; 32]>;
    /// Fill `buf` from the system CSPRNG; the error carries no detail.
    fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError>;
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

    fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        use hmac::Mac;
        Self::mac(key, parts).finalize().into_bytes().into()
    }

    fn hmac_sha256_verify(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
        use hmac::Mac;
        Self::mac(key, parts).verify_slice(tag).is_ok()
    }

    fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[&[u8]]) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(salt, ikm)
            .expand_multi_info(info, out.as_mut())
            .expect("32 bytes is within HKDF-SHA256's output limit");
        out
    }

    fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::fill(buf).map_err(|_| CryptoError)
    }

    fn fips() -> bool {
        false
    }
}

#[cfg(any(not(feature = "fips"), test))]
impl RustCrypto {
    fn mac(key: &[u8], parts: &[&[u8]]) -> hmac::Hmac<sha2::Sha256> {
        use hmac::{KeyInit, Mac};
        let mut m = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key)
            .expect("HMAC takes any key length");
        for p in parts {
            m.update(p);
        }
        m
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

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    Active::hmac_sha256(key, parts)
}

pub fn hmac_sha256_verify(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    Active::hmac_sha256_verify(key, parts, tag)
}

pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    Active::hkdf_sha256(salt, ikm, info)
}

pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    Active::fill_random(buf)
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

    /// RFC 4231 test case 2.
    #[test]
    fn hmac_rfc4231_case2() {
        let want = h("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        let tag = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(tag.to_vec(), want);
        assert!(hmac_sha256_verify(
            b"Jefe",
            &[b"what do ya want for nothing?"],
            &want
        ));
    }

    #[test]
    fn hmac_verify_rejects_flipped_bit_and_short_tag() {
        let mut tag = hmac_sha256(b"k", &[b"msg"]);
        assert!(hmac_sha256_verify(b"k", &[b"msg"], &tag));
        assert!(!hmac_sha256_verify(b"k", &[b"msg"], &tag[..31]));
        assert!(!hmac_sha256_verify(b"k", &[b"msg"], &[]));
        assert!(!hmac_sha256_verify(b"other", &[b"msg"], &tag));
        tag[5] ^= 0x01;
        assert!(!hmac_sha256_verify(b"k", &[b"msg"], &tag));
    }

    /// RFC 5869 test case 1 (first 32 bytes of OKM), info passed as two parts.
    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let okm = hkdf_sha256(Some(&salt), &ikm, &[&info[..5], &info[5..]]);
        assert_eq!(
            okm.to_vec(),
            h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
        );
    }

    /// RFC 5869 test case 3: no salt (the all-zero salt of the RFC), no info.
    #[test]
    fn hkdf_rfc5869_case3_no_salt() {
        let okm = hkdf_sha256(None, &[0x0bu8; 22], &[]);
        assert_eq!(
            okm.to_vec(),
            h("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")
        );
    }

    #[test]
    fn fill_random_draws_differ() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
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
            let (mac_a, mac_b) = (
                RustCrypto::hmac_sha256(&key, &[&msg, b"x"]),
                AwsLc::hmac_sha256(&key, &[&msg, b"x"]),
            );
            assert_eq!(mac_a, mac_b);
            assert!(RustCrypto::hmac_sha256_verify(&key, &[&msg, b"x"], &mac_b));
            assert!(AwsLc::hmac_sha256_verify(&key, &[&msg, b"x"], &mac_a));
            for salt in [None, Some(&b"salt"[..])] {
                let info: [&[u8]; 2] = [b"kepr", &msg];
                assert_eq!(
                    *RustCrypto::hkdf_sha256(salt, &key, &info),
                    *AwsLc::hkdf_sha256(salt, &key, &info)
                );
            }
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
