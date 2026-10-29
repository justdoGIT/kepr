//! The rustls `CryptoProvider` behind every TLS context in the gate
//! (T7.16): ring by default, aws-lc-rs with the `fips` cargo feature.
//! `--features fips,rustls/fips` links the FIPS 140-3 validated AWS-LC
//! module (Go + CMake on the build host); rustls then also leaves out the
//! suites and groups that are not approved (ChaCha20-Poly1305, plain X25519).
//! The per-session CA's keys and signatures follow the same switch (rcgen).
//!
//! T13.01: `--features pq` selects aws-lc-rs as well (ring has no ML-KEM)
//! and puts the hybrid key exchange X25519MLKEM768 first in every client
//! hello, so a provider that supports it is spoken to post-quantum; one
//! that does not falls back to X25519. The session CA's own keys (local,
//! agent-facing) stay as `fips` alone decides.

use rustls::crypto::CryptoProvider;

#[cfg(not(any(feature = "fips", feature = "pq")))]
pub fn provider() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

#[cfg(any(feature = "fips", feature = "pq"))]
pub fn provider() -> CryptoProvider {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    hybrid_first(&mut p);
    p
}

/// Move X25519MLKEM768 to the front of the offered groups, when the
/// provider has it (the first group is the one whose key share is sent).
#[cfg(any(feature = "fips", feature = "pq"))]
fn hybrid_first(p: &mut CryptoProvider) {
    use rustls::NamedGroup;
    let hybrid = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS
        .iter()
        .copied()
        .find(|g| g.name() == NamedGroup::X25519MLKEM768);
    if let Some(h) = hybrid {
        p.kx_groups.retain(|g| g.name() != h.name());
        p.kx_groups.insert(0, h);
    }
}

/// The key-exchange group a build offers first, for `kepr-gate --tls-info`.
pub fn first_group() -> String {
    format!("{:?}", provider().kx_groups[0].name())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_matches_the_build() {
        let p = provider();
        assert!(!p.cipher_suites.is_empty() && !p.kx_groups.is_empty());
        let backend = format!("{:?}", p.key_provider);
        #[cfg(any(feature = "fips", feature = "pq"))]
        assert!(backend.contains("AwsLc"), "{backend}");
        #[cfg(not(any(feature = "fips", feature = "pq")))]
        assert!(backend.contains("Ring"), "{backend}");
    }

    #[cfg(not(any(feature = "fips", feature = "pq")))]
    #[test]
    fn the_default_build_has_no_hybrid_group() {
        assert!(provider()
            .kx_groups
            .iter()
            .all(|g| g.name() != rustls::NamedGroup::X25519MLKEM768));
        assert_eq!(first_group(), "X25519");
    }

    #[cfg(any(feature = "fips", feature = "pq"))]
    #[test]
    fn the_hybrid_group_is_offered_first() {
        assert_eq!(first_group(), "X25519MLKEM768");
        // Others are still offered, for providers without the hybrid.
        assert!(provider().kx_groups.len() > 1);
    }

    /// A server that accepts only the hybrid group: the `pq` gate connects,
    /// and says so; the default build cannot.
    #[cfg(feature = "pq")]
    #[test]
    fn a_hybrid_only_server_is_reachable() {
        use std::io::{Read, Write};
        use std::sync::Arc;
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut sp = provider();
        sp.kx_groups
            .retain(|g| g.name() == rustls::NamedGroup::X25519MLKEM768);
        assert_eq!(sp.kx_groups.len(), 1);
        let key = rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap();
        let server = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(sp))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key)
                .unwrap(),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut c = rustls::ServerConnection::new(server).unwrap();
            let mut tls = rustls::Stream::new(&mut c, &mut s);
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).unwrap();
            tls.write_all(b"pong").unwrap();
            tls.flush().unwrap();
            c.negotiated_key_exchange_group().unwrap().name()
        });
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        let mut c = rustls::ClientConnection::new(client, "localhost".try_into().unwrap()).unwrap();
        let mut tls = rustls::Stream::new(&mut c, &mut s);
        tls.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        assert_eq!(
            c.negotiated_key_exchange_group().unwrap().name(),
            rustls::NamedGroup::X25519MLKEM768
        );
        assert_eq!(t.join().unwrap(), rustls::NamedGroup::X25519MLKEM768);
    }

    /// CI's FIPS job runs this with the validated module linked.
    #[cfg(feature = "fips")]
    #[test]
    #[ignore = "needs --features fips,rustls/fips (Go + CMake)"]
    fn validated_provider_is_fips() {
        assert!(provider().fips());
    }
}
