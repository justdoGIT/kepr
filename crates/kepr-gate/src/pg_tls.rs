//! Connections from the gate to database servers (P7.1): plain TCP only
//! when the record says `sslmode=disable`; otherwise TLS (for PostgreSQL
//! after an SSLRequest), verified against the compiled-in roots plus the
//! record's optional `ca_pem` (managed databases often use their own CA).

use std::sync::Arc;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use kepr_core::gate_protocol::DbTarget;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub async fn connect(t: &DbTarget) -> Result<TcpStream, String> {
    TcpStream::connect((t.host.as_str(), t.port))
        .await
        .map_err(|e| format!("cannot reach the database: {e}"))
}

pub async fn upstream(t: &DbTarget, sslmode: &str, ca_pem: &str) -> Result<Box<dyn Io>, String> {
    let mut tcp = connect(t).await?;
    if sslmode == "disable" {
        return Ok(Box::new(tcp));
    }
    let mut req = 8u32.to_be_bytes().to_vec();
    req.extend_from_slice(&crate::pg::SSL_REQUEST.to_be_bytes());
    tcp.write_all(&req).await.map_err(|e| e.to_string())?;
    if tcp.read_u8().await.map_err(|e| e.to_string())? != b'S' {
        return Err(
            "the database does not offer TLS (set sslmode=disable to allow plaintext)".into(),
        );
    }
    tls_client(tcp, &t.host, ca_pem).await
}

/// TLS over an open connection, verifying `host` against the compiled-in
/// roots plus `ca_pem`.
pub async fn tls_client(tcp: TcpStream, host: &str, ca_pem: &str) -> Result<Box<dyn Io>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for der in pem_certs(ca_pem) {
        roots
            .add(der)
            .map_err(|_| "ca_pem holds an invalid certificate")?;
    }
    let cfg =
        rustls::ClientConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid database host name")?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .map_err(|e| format!("database TLS: {e}"))?;
    Ok(Box::new(tls))
}

/// DER certificates in a PEM string (no extra dependency: base64 between
/// BEGIN/END CERTIFICATE lines).
fn pem_certs(pem: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start + 27..];
        let Some(end) = after.find("-----END CERTIFICATE-----") else {
            break;
        };
        let b64: String = after[..end].split_whitespace().collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64) {
            out.push(der.into());
        }
        rest = &after[end..];
    }
    out
}
