//! The rustls `CryptoProvider` behind every TLS context in the gate
//! (T7.16): ring by default, aws-lc-rs with the `fips` cargo feature.
//! `--features fips,rustls/fips` links the FIPS 140-3 validated AWS-LC
//! module (Go + CMake on the build host); rustls then also leaves out the
//! suites and groups that are not approved (ChaCha20-Poly1305, plain X25519).
//! The per-session CA's keys and signatures follow the same switch (rcgen).

use rustls::crypto::CryptoProvider;

#[cfg(not(feature = "fips"))]
pub fn provider() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

#[cfg(feature = "fips")]
pub fn provider() -> CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_matches_the_build() {
        let p = provider();
        assert!(!p.cipher_suites.is_empty() && !p.kx_groups.is_empty());
        let backend = format!("{:?}", p.key_provider);
        #[cfg(feature = "fips")]
        assert!(backend.contains("AwsLc"), "{backend}");
        #[cfg(not(feature = "fips"))]
        assert!(backend.contains("Ring"), "{backend}");
    }

    /// CI's FIPS job runs this with the validated module linked.
    #[cfg(feature = "fips")]
    #[test]
    #[ignore = "needs --features fips,rustls/fips (Go + CMake)"]
    fn validated_provider_is_fips() {
        assert!(provider().fips());
    }
}
