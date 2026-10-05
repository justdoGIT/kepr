//! MySQL authentication for the gate's proxy (T7.02).
//!
//! Agent side: the placeholder never crosses the socket in clear. The
//! gate knows which placeholder the route expects, so it recomputes the
//! scramble a client must have sent for it (`caching_sha2_password` or
//! `mysql_native_password`) and compares in constant time.
//!
//! Server side: the record's user, database and password, TLS (verified)
//! unless `sslmode=disable`. Fast auth for both plugins and auth switches
//! between them; `caching_sha2_password` *full* authentication sends the
//! password, so the gate does it only inside TLS (the RSA key exchange a
//! plaintext connection would need is not implemented).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::db::Login;
use crate::pg_tls::Io;
use kepr_core::mysql_wire::{
    self as wire, caps, Greeting, HandshakeResponse, CACHING_SHA2, NATIVE,
};

/// Handshake packets are small; a larger one is refused.
const MAX_AUTH_PACKET: usize = 64 * 1024;

pub(crate) async fn read_packet(
    r: &mut (impl AsyncRead + Unpin),
) -> std::io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 4];
    r.read_exact(&mut h).await?;
    let (len, seq) = wire::header(h);
    if len > MAX_AUTH_PACKET {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut p = vec![0u8; len];
    r.read_exact(&mut p).await?;
    Ok((seq, p))
}

pub(crate) async fn write_packet(
    w: &mut (impl AsyncWrite + Unpin),
    seq: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    w.write_all(&Zeroizing::new(wire::packet(seq, payload)))
        .await
}

/// 20 printable random bytes (no NUL: part of it is NUL-terminated).
pub(crate) fn nonce() -> Result<Vec<u8>, String> {
    let mut n = [0u8; 20];
    getrandom::fill(&mut n).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(n.iter().map(|b| 0x21 + b % 94).collect())
}

/// Did the client answer `nonce` with the scramble of `placeholder`?
pub(crate) fn client_ok(plugin: &str, auth: &[u8], placeholder: &str, nonce: &[u8]) -> bool {
    wire::scramble_for(plugin, placeholder.as_bytes(), nonce)
        .is_some_and(|want| wire::ct_eq(&want, auth))
}

/// Why the upstream login failed.
pub(crate) enum Refused {
    /// The server's ERR packet, for the client.
    Server(Vec<u8>),
    /// A problem on kepr's side, as a message.
    Failed(String),
}

/// Capabilities toward the server: what the client and server share
/// (so the command phase is what the client expects), minus TLS,
/// compression and attributes, which the gate handles itself.
pub(crate) fn upstream_caps(client: u32, server: u32, tls: bool, with_db: bool) -> u32 {
    let strip = caps::SSL
        | caps::COMPRESS
        | caps::ZSTD
        | caps::CONNECT_ATTRS
        | caps::MULTI_FACTOR
        | caps::CONNECT_WITH_DB;
    let mut c = (client & server & !strip)
        | caps::PROTOCOL_41
        | caps::SECURE_CONNECTION
        | caps::PLUGIN_AUTH;
    if tls {
        c |= caps::SSL;
    }
    if with_db {
        c |= caps::CONNECT_WITH_DB;
    }
    c
}

/// Log in to the server whose greeting was `server` on `tcp`, for the
/// client whose response was `client`. Returns the connection and the
/// server's OK payload.
pub(crate) async fn login(
    mut tcp: TcpStream,
    (server, client): (&Greeting, &HandshakeResponse),
    host: &str,
    l: &Login,
) -> Result<(Box<dyn Io>, Vec<u8>), Refused> {
    let fail = |m: &str| Refused::Failed(m.to_string());
    let io = |e: std::io::Error| Refused::Failed(e.to_string());
    let tls = l.sslmode != "disable";
    if tls && server.caps & caps::SSL == 0 {
        return Err(fail(
            "the database does not offer TLS (set sslmode=disable to allow plaintext)",
        ));
    }
    let plugin = if server.plugin == NATIVE {
        NATIVE
    } else {
        CACHING_SHA2
    };
    let pw = l.password.as_bytes();
    let resp = HandshakeResponse {
        caps: upstream_caps(client.caps, server.caps, tls, !l.database.is_empty()),
        user: l.user.clone(),
        auth: wire::scramble_for(plugin, pw, &server.scramble).unwrap_or_default(),
        database: Some(l.database.clone()),
        plugin: Some(plugin.into()),
        ..client.clone()
    };
    let mut seq = 1u8;
    let mut up: Box<dyn Io> = if tls {
        write_packet(&mut tcp, seq, &resp.ssl_request())
            .await
            .map_err(io)?;
        seq += 1;
        crate::pg_tls::tls_client(tcp, host, &l.ca_pem)
            .await
            .map_err(Refused::Failed)?
    } else {
        Box::new(tcp)
    };
    write_packet(&mut up, seq, &resp.encode())
        .await
        .map_err(io)?;
    drop(resp);
    loop {
        let (s, p) = read_packet(&mut up).await.map_err(io)?;
        seq = s.wrapping_add(1);
        let reply: Zeroizing<Vec<u8>> = match (p.first(), p.get(1)) {
            (Some(0x00), _) => return Ok((up, p)),
            (Some(0xff), _) => return Err(Refused::Server(p)),
            // AuthSwitchRequest: plugin name, then its nonce.
            (Some(0xfe), _) => {
                let mut b = &p[1..];
                let name = String::from_utf8_lossy(wire::take_nul(&mut b)).into_owned();
                let nonce = b.strip_suffix(&[0]).unwrap_or(b);
                Zeroizing::new(
                    wire::scramble_for(&name, pw, nonce)
                        .ok_or_else(|| fail(&format!("unsupported auth plugin {name}")))?,
                )
            }
            // caching_sha2_password: fast auth worked, the OK follows.
            (Some(0x01), Some(3)) => continue,
            // Full authentication: the password itself, so TLS only.
            (Some(0x01), Some(4)) if tls => {
                let mut v = Zeroizing::new(Vec::with_capacity(pw.len() + 1));
                v.extend_from_slice(pw);
                v.push(0);
                v
            }
            (Some(0x01), Some(4)) => return Err(fail(
                "the server asked for full caching_sha2_password authentication, which kepr does only over TLS; use sslmode=verify-full",
            )),
            _ => return Err(fail("unexpected packet during the database login")),
        };
        write_packet(&mut up, seq, &reply).await.map_err(io)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_scrambles_are_checked_against_the_placeholder() {
        let n = nonce().unwrap();
        assert_eq!(n.len(), 20);
        assert!(n.iter().all(|b| (0x21..0x7f).contains(b)));
        let good = wire::sha2_scramble(b"kepr-ph-x", &n);
        assert!(client_ok(CACHING_SHA2, &good, "kepr-ph-x", &n));
        assert!(!client_ok(CACHING_SHA2, &good, "kepr-ph-y", &n));
        assert!(!client_ok(NATIVE, &good, "kepr-ph-x", &n));
        let native = wire::native_scramble(b"kepr-ph-x", &n);
        assert!(client_ok(NATIVE, &native, "kepr-ph-x", &n));
        assert!(!client_ok(
            "mysql_clear_password",
            b"kepr-ph-x",
            "kepr-ph-x",
            &n
        ));
        assert!(!client_ok(CACHING_SHA2, b"", "kepr-ph-x", &n));
    }

    #[test]
    fn upstream_capabilities() {
        let all = u32::MAX;
        let c = upstream_caps(all, all, false, false);
        for off in [
            caps::SSL,
            caps::COMPRESS,
            caps::ZSTD,
            caps::CONNECT_ATTRS,
            caps::CONNECT_WITH_DB,
        ] {
            assert_eq!(c & off, 0, "{off:#x}");
        }
        assert_ne!(upstream_caps(all, all, true, true) & caps::SSL, 0);
        // Only what both sides have, so the client parses the server.
        let c = upstream_caps(caps::DEPRECATE_EOF, 0, false, true);
        assert_eq!(c & caps::DEPRECATE_EOF, 0);
        assert_ne!(c & caps::CONNECT_WITH_DB, 0);
    }
}
