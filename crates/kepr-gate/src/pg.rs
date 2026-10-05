//! PostgreSQL proxy (P7.1). The agent connects to a local port with the
//! session placeholder as its password; the gate logs in to the real
//! server with the sealed `database` record and then relays the session.
//!
//! Client side (loopback): SSL/GSS requests are declined, the client is
//! asked for a cleartext password (it never leaves this host), and that
//! password must be this route's placeholder. Server side: the record's
//! user, database and password; TLS with certificate verification
//! (`sslmode` verify-full, the default: compiled-in roots plus an optional
//! `ca_pem` field) or plaintext only when the record says `disable`;
//! SCRAM-SHA-256 or cleartext auth (MD5 is refused). From the server's
//! AuthenticationOk on, bytes flow unchanged both ways.

use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::db::{self, Fail};
use crate::proxy::State;
use crate::scram::Scram;

pub(crate) const SSL_REQUEST: u32 = 80_877_103;
const GSS_REQUEST: u32 = 80_877_104;
const PROTOCOL_3: u32 = 196_608;
const MAX_MSG: usize = 1 << 20;

pub(crate) use crate::db::{DbRoute, Login};
pub(crate) use crate::pg_tls::Io;

pub(crate) fn error_response(code: &str, msg: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (k, v) in [(b'S', "FATAL"), (b'V', "FATAL"), (b'C', code), (b'M', msg)] {
        body.push(k);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut out = vec![b'E'];
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

pub(crate) fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

async fn read_startup(c: &mut (impl AsyncRead + Unpin)) -> std::io::Result<(u32, Vec<u8>)> {
    let len = c.read_u32().await? as usize;
    if !(8..=10_000).contains(&len) {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let code = c.read_u32().await?;
    let mut body = vec![0u8; len - 8];
    c.read_exact(&mut body).await?;
    Ok((code, body))
}

pub(crate) async fn read_msg(c: &mut (impl AsyncRead + Unpin)) -> std::io::Result<(u8, Vec<u8>)> {
    let kind = c.read_u8().await?;
    let len = c.read_u32().await? as usize;
    if !(4..=MAX_MSG).contains(&len) {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut body = vec![0u8; len - 4];
    c.read_exact(&mut body).await?;
    Ok((kind, body))
}

/// `key\0value\0…\0` → pairs.
pub fn parse_params(body: &[u8]) -> Vec<(String, String)> {
    let parts: Vec<&[u8]> = body.split(|b| *b == 0).collect();
    parts
        .chunks(2)
        .filter(|kv| kv.len() == 2 && !kv[0].is_empty())
        .map(|kv| {
            (
                String::from_utf8_lossy(kv[0]).into(),
                String::from_utf8_lossy(kv[1]).into(),
            )
        })
        .collect()
}

/// Startup for the server: the client's parameters, with user and
/// database taken from the record.
fn startup(params: &[(String, String)], login: &Login) -> Vec<u8> {
    let mut body = PROTOCOL_3.to_be_bytes().to_vec();
    let mut put = |k: &str, v: &str| {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    };
    put("user", &login.user);
    put("database", &login.database);
    for (k, v) in params {
        if !matches!(k.as_str(), "user" | "database" | "replication") && !k.starts_with("kepr_") {
            put(k, v);
        }
    }
    body.push(0);
    let mut out = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

/// Log in to the server; on success the AuthenticationOk message is
/// returned so it can be passed on to the client.
pub(crate) async fn login(
    up: &mut Box<dyn Io>,
    params: &[(String, String)],
    l: &Login,
) -> Result<Vec<u8>, Vec<u8>> {
    let fail = |m: &str| error_response("08001", &format!("kepr: {m}"));
    up.write_all(&startup(params, l))
        .await
        .map_err(|e| fail(&e.to_string()))?;
    let mut scram: Option<Scram> = None;
    let mut server_proved = false;
    loop {
        let (kind, body) = read_msg(up).await.map_err(|e| fail(&e.to_string()))?;
        if kind == b'E' {
            return Err(message(b'E', &body));
        }
        if kind != b'R' || body.len() < 4 {
            return Err(fail("unexpected message during login"));
        }
        let code = u32::from_be_bytes(body[..4].try_into().expect("4 bytes"));
        let data = &body[4..];
        let reply = match code {
            // A SCRAM login must end with the server's signature: a
            // server that skips it never proved it knows the password.
            0 if scram.is_some() && !server_proved => {
                return Err(fail("the server skipped SCRAM's final proof"))
            }
            0 => return Ok(message(b'R', &body)),
            // Cleartext only inside TLS: on a plaintext connection the
            // password would cross the network as is.
            3 if l.sslmode == "disable" => {
                return Err(fail(
                    "the server asked for a cleartext password on an unencrypted connection; use TLS or scram-sha-256",
                ))
            }
            3 => {
                let mut p = l.password.as_bytes().to_vec();
                p.push(0);
                message(b'p', &p)
            }
            10 => {
                if !data.split(|b| *b == 0).any(|m| m == b"SCRAM-SHA-256") {
                    return Err(fail("the server offers no SCRAM-SHA-256"));
                }
                let mut n = [0u8; 18];
                getrandom::fill(&mut n).map_err(|_| fail("CSPRNG failure"))?;
                let s = Scram::new(
                    &l.password,
                    &base64::engine::general_purpose::STANDARD.encode(n),
                );
                let first = s.client_first();
                scram = Some(s);
                let mut b = b"SCRAM-SHA-256\0".to_vec();
                b.extend_from_slice(&(first.len() as u32).to_be_bytes());
                b.extend_from_slice(first.as_bytes());
                message(b'p', &b)
            }
            11 => {
                let s = scram.as_mut().ok_or_else(|| fail("SCRAM out of order"))?;
                let fin = s
                    .client_final(&String::from_utf8_lossy(data))
                    .map_err(|e| fail(&e))?;
                message(b'p', fin.as_bytes())
            }
            12 => {
                let s = scram.as_ref().ok_or_else(|| fail("SCRAM out of order"))?;
                s.verify_server(&String::from_utf8_lossy(data))
                    .map_err(|e| fail(&e))?;
                server_proved = true;
                continue;
            }
            5 => {
                return Err(fail(
                    "MD5 password auth is not supported; use scram-sha-256",
                ))
            }
            _ => return Err(fail("unsupported authentication method")),
        };
        up.write_all(&reply)
            .await
            .map_err(|e| fail(&e.to_string()))?;
    }
}

/// Serve one client connection on a database route's port.
pub async fn serve_conn(state: Arc<State>, route: Arc<DbRoute>, mut client: TcpStream) {
    let start = Instant::now();
    let result = session(&state, &route, &mut client).await;
    db::log(&state, &route, "LOGIN", &result, start);
}

async fn session(state: &Arc<State>, route: &DbRoute, client: &mut TcpStream) -> Result<(), Fail> {
    let io = |_| (400, None);
    let mut startup_msg = read_startup(client).await.map_err(io)?;
    while matches!(startup_msg.0, SSL_REQUEST | GSS_REQUEST) {
        client.write_all(b"N").await.map_err(io)?;
        startup_msg = read_startup(client).await.map_err(io)?;
    }
    if startup_msg.0 != PROTOCOL_3 {
        return Err((400, None));
    }
    let params = parse_params(&startup_msg.1);
    // Ask for the (placeholder) password in cleartext: it stays on loopback.
    client
        .write_all(&message(b'R', &3u32.to_be_bytes()))
        .await
        .map_err(io)?;
    let (kind, body) = read_msg(client).await.map_err(io)?;
    let given = Zeroizing::new(
        String::from_utf8_lossy(body.strip_suffix(&[0]).unwrap_or(&body)).to_string(),
    );
    if kind != b'p' || !state.valid_placeholder(&given, route.slot) {
        let _ = client
            .write_all(&error_response(
                "28P01",
                "kepr: invalid or missing kepr placeholder",
            ))
            .await;
        return Err((401, None));
    }
    if let Err(msg) = db::admit(state) {
        let _ = client.write_all(&error_response("53400", &msg)).await;
        return Err((403, Some("limit")));
    }
    let Ok(login_rec) = db::resolve_login(state, route).await else {
        let _ = client
            .write_all(&error_response(
                "28000",
                "kepr could not obtain the database login",
            ))
            .await;
        return Err((502, None));
    };
    let mut up =
        match crate::pg_tls::upstream(&route.target, &login_rec.sslmode, &login_rec.ca_pem).await {
            Ok(u) => u,
            Err(e) => {
                let _ = client
                    .write_all(&error_response("08001", &format!("kepr: {e}")))
                    .await;
                return Err((502, None));
            }
        };
    if params.iter().any(|(k, v)| k == "kepr_rotate" && v == "1") {
        if !route.target.rotate {
            let _ = client
                .write_all(&error_response(
                    "42501",
                    "kepr: password rotation is only available to `kepr agent rotate-db`",
                ))
                .await;
            return Err((403, None));
        }
        let reply = crate::pg_rotate::session(up, route, &params, &login_rec).await;
        let _ = client.write_all(&reply).await;
        return Ok(());
    }
    // T7.18: the route's role is granted before its first login.
    if let Err(e) = crate::pg_jit::ensure(state, route, &login_rec.user).await {
        let msg = format!("kepr: role elevation failed: {e}");
        let _ = client.write_all(&error_response("42501", &msg)).await;
        return Err((502, Some("grant")));
    }
    match login(&mut up, &params, &login_rec).await {
        Ok(ok) => client.write_all(&ok).await.map_err(io)?,
        Err(err) => {
            let _ = client.write_all(&err).await;
            return Err((502, None));
        }
    }
    drop(login_rec);
    let _ = tokio::io::copy_bidirectional(client, &mut up).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(sslmode: &str) -> Login {
        serde_json::from_str(&format!(
            r#"{{"user":"u","password":"pw","database":"d","sslmode":"{sslmode}"}}"#
        ))
        .unwrap()
    }

    /// Run `login` against a fake server that sends `replies` (after
    /// reading the startup) and return the verdict.
    async fn login_against(replies: Vec<Vec<u8>>, l: Login) -> Result<Vec<u8>, Vec<u8>> {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let srv = tokio::spawn(async move {
            let _ = read_startup(&mut server).await;
            for r in replies {
                let _ = server.write_all(&r).await;
                let _ = read_msg(&mut server).await;
            }
        });
        let mut up: Box<dyn Io> = Box::new(client);
        let r = login(&mut up, &[], &l).await;
        srv.abort();
        r
    }

    #[tokio::test]
    async fn no_cleartext_password_without_tls() {
        let ask = message(b'R', &3u32.to_be_bytes());
        assert!(login_against(vec![ask.clone()], rec("disable"))
            .await
            .is_err());
        // Inside TLS (verify-full) the cleartext request is answered.
        let ok = message(b'R', &0u32.to_be_bytes());
        assert!(login_against(vec![ask, ok], rec("verify-full"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn scram_without_the_server_proof_is_refused() {
        let mut sasl = 10u32.to_be_bytes().to_vec();
        sasl.extend_from_slice(b"SCRAM-SHA-256\0\0");
        let replies = vec![message(b'R', &sasl), message(b'R', &0u32.to_be_bytes())];
        assert!(login_against(replies, rec("disable")).await.is_err());
    }

    #[test]
    fn startup_replaces_user_and_database() {
        let params = parse_params(b"user\0kepr\0database\0x\0client_encoding\0UTF8\0\0");
        assert_eq!(params.len(), 3);
        let l = Login {
            user: "app".into(),
            password: kepr_core::generate::ZeroString::from_string("p".into()),
            database: "prod".into(),
            sslmode: String::new(),
            ca_pem: String::new(),
            pending_password: None,
        };
        let m = startup(&params, &l);
        let body = &m[8..];
        let p = parse_params(body);
        assert_eq!(
            p,
            vec![
                ("user".into(), "app".into()),
                ("database".into(), "prod".into()),
                ("client_encoding".into(), "UTF8".into())
            ]
        );
        assert_eq!(
            u32::from_be_bytes(m[..4].try_into().unwrap()) as usize,
            m.len()
        );
    }

    #[test]
    fn error_response_is_well_formed() {
        let e = error_response("28P01", "nope");
        assert_eq!(e[0], b'E');
        assert_eq!(
            u32::from_be_bytes(e[1..5].try_into().unwrap()) as usize,
            e.len() - 1
        );
        assert!(e.ends_with(b"nope\0\0"));
    }
}
