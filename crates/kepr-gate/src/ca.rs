//! Per-session certificate authority for the egress proxy (P2.1).
//!
//! The gate terminates TLS only for the hosts this session's sealed keys
//! are bound to, so tools that can't be pointed at a base URL (`gh`,
//! `curl`, SDKs) still never hold the real key. The CA:
//!   - is created in the gate's memory at session start and dies with it
//!     (the gate is non-dumpable); only its certificate leaves, so the
//!     harness can trust it;
//!   - is name-constrained to the session's bound hosts, so even a leaked
//!     CA key could not sign a certificate for any other site;
//!   - is valid for 24 h; leaf certificates are made on first use per host.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

pub struct SessionCa {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    pem: String,
    hosts: Vec<String>,
    /// T2.02: domains whose sub-hosts the CA may sign (`amazonaws.com` for
    /// AWS routes); the egress proxy asks the daemon first whether the
    /// session's key is bound to the exact host.
    suffixes: Vec<String>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn err(e: impl std::fmt::Display) -> String {
    format!("session CA: {e}")
}

fn validity(p: &mut CertificateParams) {
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::hours(1);
    p.not_after = now + Duration::hours(24);
}

impl SessionCa {
    /// A CA that can sign only `hosts` (lower-case DNS names).
    #[cfg(test)]
    pub fn new(hosts: &[String]) -> Result<Self, String> {
        Self::with_suffixes(hosts, &[])
    }

    /// Also sub-hosts of `suffixes` (e.g. `amazonaws.com`).
    pub fn with_suffixes(hosts: &[String], suffixes: &[&str]) -> Result<Self, String> {
        if hosts.is_empty() && suffixes.is_empty() {
            return Err("session CA: no bound hosts".into());
        }
        let key = KeyPair::generate().map_err(err)?;
        let mut p = CertificateParams::new(Vec::<String>::new()).map_err(err)?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "kepr agent session CA");
        p.distinguished_name = dn;
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.name_constraints = Some(NameConstraints {
            permitted_subtrees: hosts
                .iter()
                .map(String::as_str)
                .chain(suffixes.iter().copied())
                .map(|h| GeneralSubtree::DnsName(h.to_string()))
                .collect(),
            excluded_subtrees: Vec::new(),
        });
        validity(&mut p);
        let cert = p.self_signed(&key).map_err(err)?;
        Ok(Self {
            ca_der: cert.der().clone(),
            pem: cert.pem(),
            issuer: Issuer::new(p, key),
            hosts: hosts.to_vec(),
            suffixes: suffixes.iter().map(|s| format!(".{s}")).collect(),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub fn pem(&self) -> &str {
        &self.pem
    }

    #[cfg(test)]
    pub(crate) fn ca_der(&self) -> CertificateDer<'static> {
        self.ca_der.clone()
    }

    pub fn covers(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| h == host) || self.suffixes.iter().any(|s| host.ends_with(s))
    }

    /// TLS server config presenting a leaf for `host` (bound hosts only).
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        if !self.covers(host) {
            return Err(format!("{host} is not bound in this session"));
        }
        let mut cache = self.leaves.lock().map_err(|_| "leaf cache poisoned")?;
        if let Some(c) = cache.get(host) {
            return Ok(c.clone());
        }
        let key = KeyPair::generate().map_err(err)?;
        let mut p = CertificateParams::new(vec![host.to_string()]).map_err(err)?;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        validity(&mut p);
        let leaf = p.signed_by(&key, &self.issuer).map_err(err)?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut cfg =
            ServerConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
                .with_safe_default_protocol_versions()
                .map_err(err)?
                .with_no_client_auth()
                .with_single_cert(vec![leaf.der().clone(), self.ca_der.clone()], key_der)
                .map_err(err)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        cache.insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }

    #[cfg(test)]
    fn leaf_for_any(&self, host: &str) -> (CertificateDer<'static>, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![host.to_string()]).unwrap();
        validity(&mut p);
        (p.signed_by(&key, &self.issuer).unwrap().der().clone(), key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn client(ca: &SessionCa) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(ca.ca_der.clone()).unwrap();
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    async fn handshake(server: Arc<ServerConfig>, client: Arc<ClientConfig>, host: &str) -> bool {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(server);
        let srv = tokio::spawn(async move {
            if let Ok(mut s) = acceptor.accept(a).await {
                let mut buf = [0u8; 2];
                let _ = s.read_exact(&mut buf).await;
                let _ = s.write_all(&buf).await;
            }
        });
        let name = ServerName::try_from(host.to_string()).unwrap();
        let ok = match tokio_rustls::TlsConnector::from(client)
            .connect(name, b)
            .await
        {
            Ok(mut c) => {
                c.write_all(b"hi").await.unwrap();
                let mut buf = [0u8; 2];
                c.read_exact(&mut buf).await.is_ok() && &buf == b"hi"
            }
            Err(_) => false,
        };
        srv.abort();
        ok
    }

    #[tokio::test]
    async fn signs_bound_hosts_and_clients_trust_it() {
        let ca = SessionCa::new(&["api.github.com".into()]).unwrap();
        assert!(ca.pem().starts_with("-----BEGIN CERTIFICATE-----"));
        let cfg = ca.server_config("api.github.com").unwrap();
        assert!(Arc::ptr_eq(
            &cfg,
            &ca.server_config("api.github.com").unwrap()
        ));
        assert!(handshake(cfg, client(&ca), "api.github.com").await);
        assert!(ca.server_config("example.com").is_err());
    }

    #[tokio::test]
    async fn aws_suffix_covers_only_its_sub_hosts() {
        let ca = SessionCa::with_suffixes(&[], &["amazonaws.com"]).unwrap();
        assert!(ca.covers("s3.eu-west-1.amazonaws.com"));
        for h in [
            "amazonaws.com",
            "evilamazonaws.com",
            "amazonaws.com.evil.io",
        ] {
            assert!(!ca.covers(h), "{h}");
        }
        let cfg = ca.server_config("sts.amazonaws.com").unwrap();
        assert!(handshake(cfg, client(&ca), "sts.amazonaws.com").await);
        let (leaf, key) = ca.leaf_for_any("evil.example");
        let cfg = ServerConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf, ca.ca_der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        assert!(!handshake(Arc::new(cfg), client(&ca), "evil.example").await);
        assert!(SessionCa::with_suffixes(&[], &[]).is_err());
    }

    #[tokio::test]
    async fn name_constraints_stop_any_other_host() {
        let ca = SessionCa::new(&["api.github.com".into()]).unwrap();
        // Forge a leaf for another host with the CA key itself: clients
        // must still reject it, because the CA is constrained.
        let (leaf, key) = ca.leaf_for_any("evil.example");
        let cfg = ServerConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf, ca.ca_der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        assert!(!handshake(Arc::new(cfg), client(&ca), "evil.example").await);
    }
}
