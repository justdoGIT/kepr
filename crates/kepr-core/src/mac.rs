//! SHA-256, HMAC-SHA256 and PBKDF2-HMAC-SHA256 (T12.43), shared by SigV4
//! signing, the gate's SCRAM login and its placeholder MACs.
//!
//! The default build uses RustCrypto (`sha2`, `hmac`). With the `fips`
//! feature the same calls run in aws-lc-rs, which is the FIPS 140-3 module
//! when built with `aws-lc-rs/fips`. Outputs are identical either way.

use std::num::NonZeroU32;

use zeroize::Zeroizing;

/// Shortest tag `hmac_sha256_verify` accepts (a left-truncated MAC).
const MIN_TAG: usize = 8;

#[cfg(not(feature = "fips"))]
mod imp {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};

    pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    fn mac(key: &[u8], parts: &[&[u8]]) -> Hmac<Sha256> {
        let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
        for p in parts {
            m.update(p);
        }
        m
    }

    pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(mac(key, parts).finalize().into_bytes().into())
    }

    pub fn verify(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
        mac(key, parts).verify_truncated_left(tag).is_ok()
    }

    /// One 32-byte block (RFC 8018 §5.2).
    pub fn pbkdf2(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> Zeroizing<[u8; 32]> {
        let mut u = hmac_sha256(password, &[salt, &1u32.to_be_bytes()]);
        let mut out = Zeroizing::new(*u);
        for _ in 1..iterations.get() {
            u = hmac_sha256(password, &[u.as_ref()]);
            for (o, b) in out.iter_mut().zip(u.iter()) {
                *o ^= b;
            }
        }
        out
    }
}

#[cfg(feature = "fips")]
mod imp {
    use super::*;
    use aws_lc_rs::{constant_time, digest, hmac, pbkdf2};

    pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        let mut c = digest::Context::new(&digest::SHA256);
        for p in parts {
            c.update(p);
        }
        c.finish().as_ref().try_into().expect("SHA-256 is 32 bytes")
    }

    pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
        let k = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut c = hmac::Context::with_key(&k);
        for p in parts {
            c.update(p);
        }
        Zeroizing::new(
            c.sign()
                .as_ref()
                .try_into()
                .expect("HMAC-SHA256 is 32 bytes"),
        )
    }

    pub fn verify(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
        let want = hmac_sha256(key, parts);
        constant_time::verify_slices_are_equal(&want[..tag.len()], tag).is_ok()
    }

    pub fn pbkdf2(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt,
            password,
            out.as_mut(),
        );
        out
    }
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    imp::sha256(parts)
}

/// HMAC-SHA256 over the concatenation of `parts`.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    imp::hmac_sha256(key, parts)
}

/// Constant-time check of `tag` against the left bytes of the MAC. A tag of
/// 8 to 32 bytes is compared; any other length is false.
pub fn hmac_sha256_verify(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    (MIN_TAG..=32).contains(&tag.len()) && imp::verify(key, parts, tag)
}

/// PBKDF2-HMAC-SHA256 to a single 32-byte block.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> Zeroizing<[u8; 32]> {
    imp::pbkdf2(password, salt, iterations)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASE2: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    #[test]
    fn rfc4231_case2() {
        let tag = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(hex_of(tag.as_ref()), CASE2);
    }

    #[test]
    fn sha256_concatenates_its_parts() {
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hex_of(&sha256(&[b"a", b"bc"])), want);
    }

    #[test]
    fn verify_accepts_8_byte_left_truncation() {
        let tag = hmac_sha256(b"Jefe", &[b"what do ya want for nothing?"]);
        for n in [8, 16, 32] {
            assert!(hmac_sha256_verify(
                b"Jefe",
                &[b"what do ya want for nothing?"],
                &tag[..n]
            ));
        }
    }

    #[test]
    fn verify_rejects_flipped_bit_empty_and_33_byte_tags() {
        let msg: &[&[u8]] = &[b"what do ya want for nothing?"];
        let tag = hmac_sha256(b"Jefe", msg);
        let mut bad = *tag;
        bad[0] ^= 1;
        assert!(!hmac_sha256_verify(b"Jefe", msg, &bad));
        assert!(!hmac_sha256_verify(b"Jefe", msg, &[]));
        assert!(!hmac_sha256_verify(b"Jefe", msg, &tag[..7]));
        let long = [tag.as_ref(), &[0u8]].concat();
        assert!(!hmac_sha256_verify(b"Jefe", msg, &long));
        assert!(!hmac_sha256_verify(b"other", msg, &tag[..]));
    }

    #[test]
    fn pbkdf2_rfc7914() {
        let one = NonZeroU32::new(1).unwrap();
        let dk = pbkdf2_sha256(b"passwd", b"salt", one);
        assert_eq!(
            hex_of(dk.as_ref()),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn pbkdf2_runs_every_iteration() {
        let n = |i| pbkdf2_sha256(b"p", b"s", NonZeroU32::new(i).unwrap());
        assert_ne!(*n(1), *n(2));
        assert_eq!(*n(3), *n(3));
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
