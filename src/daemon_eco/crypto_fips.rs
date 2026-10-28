// crypto_fips.rs — the aws-lc-rs `CipherSuite` (T7.16), compiled only with
// the `fips` cargo feature.
// batch: eco
//
// `--features fips` alone links AWS-LC's ordinary build (what CI's
// `--all-features` lint compiles). The FIPS 140-3 validated module needs
// AWS-LC's FIPS build as well:
//
//     cargo build --release --features fips,aws-lc-rs/fips
//
// (Go and CMake on the build host). `fips()` asks the library at run time,
// so `kepr status` only claims FIPS mode when the validated module is
// actually linked and passed its power-on self tests.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::hkdf::{KeyType, Salt, HKDF_SHA256};
use aws_lc_rs::{constant_time, digest, hmac, rand};
use zeroize::Zeroizing;

use super::cipher::{CipherSuite, CryptoError, NONCE_LEN};

pub struct AwsLc;

/// HKDF output length for `expand`: always 32 bytes here.
struct Len32;

impl KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

fn key_for(key: &[u8]) -> Result<LessSafeKey, CryptoError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| CryptoError)
}

impl CipherSuite for AwsLc {
    const NAME: &'static str = "aws-lc-rs (AWS-LC)";

    fn seal(
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let k = key_for(key)?;
        // Room for the tag up front: no reallocation leaves a stray copy.
        let mut buf = Vec::with_capacity(msg.len() + AES_256_GCM.tag_len());
        buf.extend_from_slice(msg);
        k.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| CryptoError)?;
        Ok(buf)
    }

    fn open(
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let k = key_for(key)?;
        let mut buf = Zeroizing::new(ct.to_vec());
        let n = k
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| CryptoError)?
            .len();
        buf.truncate(n);
        Ok(buf)
    }

    fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        let mut ctx = digest::Context::new(&digest::SHA256);
        for p in parts {
            ctx.update(p);
        }
        ctx.finish()
            .as_ref()
            .try_into()
            .expect("SHA-256 is 32 bytes")
    }

    fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let k = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut ctx = hmac::Context::with_key(&k);
        for p in parts {
            ctx.update(p);
        }
        ctx.sign()
            .as_ref()
            .try_into()
            .expect("HMAC-SHA256 is 32 bytes")
    }

    fn hmac_sha256_verify(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
        let want = Self::hmac_sha256(key, parts);
        // Different lengths are rejected before any comparison.
        tag.len() == want.len() && constant_time::verify_slices_are_equal(&want, tag).is_ok()
    }

    fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[&[u8]]) -> Zeroizing<[u8; 32]> {
        // RFC 5869: no salt means HashLen zero bytes.
        let zero = [0u8; 32];
        let prk = Salt::new(HKDF_SHA256, salt.unwrap_or(&zero)).extract(ikm);
        let mut out = Zeroizing::new([0u8; 32]);
        prk.expand(info, Len32)
            .expect("32 bytes is within HKDF-SHA256's output limit")
            .fill(out.as_mut())
            .expect("output length matches");
        out
    }

    fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
        rand::fill(buf).map_err(|_| CryptoError)
    }

    fn fips() -> bool {
        aws_lc_rs::try_fips_mode().is_ok()
    }
}
