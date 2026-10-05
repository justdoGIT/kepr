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
use aws_lc_rs::digest;
use zeroize::Zeroizing;

use super::cipher::{CipherSuite, CryptoError, NONCE_LEN};

pub struct AwsLc;

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

    fn fips() -> bool {
        aws_lc_rs::try_fips_mode().is_ok()
    }
}
