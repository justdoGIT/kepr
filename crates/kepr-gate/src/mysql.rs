//! MySQL proxy (T7.02). The agent connects to a local port with the
//! session placeholder as its password; the gate completes the server's
//! handshake itself with the sealed `database` record (`kind: mysql`) and
//! then relays packets unchanged both ways.
//!
//! Order: connect to the server and read its greeting; greet the client
//! with the server's version and capabilities (no TLS or compression on
//! loopback) but the gate's own nonce and `caching_sha2_password`; check
//! the client's scramble against the route's placeholder (an auth switch
//! first, for a client that answered with another plugin); only then
//! resolve the login, log in upstream (mysql_auth.rs) and hand the
//! server's OK to the client.

use std::sync::Arc;
use std::time::Instant;

use tokio::net::TcpStream;

use crate::db::{self, DbRoute, Fail};
use crate::mysql_auth::{self, read_packet, write_packet, Refused};
use crate::proxy::State;
use kepr_core::mysql_wire::{
    self as wire, caps, Greeting, HandshakeResponse, CACHING_SHA2, NATIVE,
};

/// Not offered to the agent: the loopback leg has no TLS or compression.
const CLIENT_STRIP: u32 = caps::SSL | caps::COMPRESS | caps::ZSTD | caps::MULTI_FACTOR;

/// Serve one client connection on a MySQL route's port.
pub async fn serve_conn(state: Arc<State>, route: Arc<DbRoute>, mut client: TcpStream) {
    let start = Instant::now();
    let result = session(&state, &route, &mut client).await;
    db::log(&state, &route, "LOGIN", &result, start);
}

async fn refuse(client: &mut TcpStream, seq: u8, code: u16, msg: &str, fail: Fail) -> Fail {
    let state = if code == wire::ACCESS_DENIED {
        "28000"
    } else {
        "HY000"
    };
    let _ = write_packet(client, seq, &wire::err_packet(code, state, msg)).await;
    fail
}

/// The client's handshake response, after an auth switch if it answered
/// with a plugin the gate can't check. `seq` is the client's last seq.
async fn client_login(
    client: &mut TcpStream,
    nonce: &[u8],
) -> Result<(HandshakeResponse, String, u8), Fail> {
    let io = |_| (400, None);
    let (mut seq, raw) = read_packet(client).await.map_err(io)?;
    let Some(mut resp) = HandshakeResponse::parse(&raw) else {
        let msg = "kepr: unsupported client handshake (TLS is not offered on the loopback port; use ssl-mode=DISABLED)";
        return Err(refuse(client, seq.wrapping_add(1), 1043, msg, (400, None)).await);
    };
    let mut plugin = resp.plugin.clone().unwrap_or_else(|| NATIVE.into());
    if plugin != NATIVE && plugin != CACHING_SHA2 {
        let switch = wire::auth_switch(CACHING_SHA2, nonce);
        write_packet(client, seq.wrapping_add(1), &switch)
            .await
            .map_err(io)?;
        let (s, auth) = read_packet(client).await.map_err(io)?;
        (seq, resp.auth, plugin) = (s, auth, CACHING_SHA2.into());
    }
    Ok((resp, plugin, seq))
}

async fn session(state: &State, route: &DbRoute, client: &mut TcpStream) -> Result<(), Fail> {
    let mut tcp = match crate::pg_tls::connect(&route.target).await {
        Ok(t) => t,
        Err(e) => return Err(refuse(client, 0, 2003, &format!("kepr: {e}"), (502, None)).await),
    };
    let greeting = read_packet(&mut tcp).await.map(|p| p.1).unwrap_or_default();
    if greeting.first() == Some(&0xff) {
        let _ = write_packet(client, 0, &greeting).await;
        return Err((502, None));
    }
    let Some(server) = Greeting::parse(&greeting) else {
        let msg = "kepr: the database sent an unsupported handshake";
        return Err(refuse(client, 0, 2027, msg, (502, None)).await);
    };
    let nonce = mysql_auth::nonce().map_err(|_| (500, None))?;
    let mine = Greeting {
        scramble: nonce.clone(),
        caps: server.caps & !CLIENT_STRIP,
        plugin: CACHING_SHA2.into(),
        ..server.clone()
    };
    write_packet(client, 0, &mine.encode())
        .await
        .map_err(|_| (400, None))?;
    let (resp, plugin, seq) = client_login(client, &nonce).await?;
    let mut seq = seq.wrapping_add(1);
    let placeholder = db::expected_placeholder(state, route.slot);
    if !mysql_auth::client_ok(&plugin, &resp.auth, &placeholder, &nonce) {
        let msg = format!(
            "Access denied for user '{}' (kepr: invalid or missing kepr placeholder)",
            resp.user
        );
        return Err(refuse(client, seq, wire::ACCESS_DENIED, &msg, (401, None)).await);
    }
    drop(placeholder);
    if let Err(msg) = db::admit(state) {
        return Err(refuse(client, seq, 1226, &msg, (403, Some("limit"))).await);
    }
    let Ok(l) = db::resolve_login(state, route).await else {
        let msg = "kepr could not obtain the database login";
        return Err(refuse(client, seq, wire::ACCESS_DENIED, msg, (502, None)).await);
    };
    let logged_in = mysql_auth::login(tcp, (&server, &resp), &route.target.host, &l).await;
    drop(l);
    let (mut up, ok) = match logged_in {
        Ok(v) => v,
        Err(Refused::Server(err)) => {
            let _ = write_packet(client, seq, &err).await;
            return Err((502, None));
        }
        Err(Refused::Failed(m)) => {
            let msg = format!("kepr: {m}");
            return Err(refuse(client, seq, wire::ACCESS_DENIED, &msg, (502, None)).await);
        }
    };
    // A caching_sha2 client expects "fast auth succeeded" before the OK.
    if plugin == CACHING_SHA2 {
        write_packet(client, seq, &[0x01, 0x03])
            .await
            .map_err(|_| (400, None))?;
        seq = seq.wrapping_add(1);
    }
    write_packet(client, seq, &ok)
        .await
        .map_err(|_| (400, None))?;
    let _ = tokio::io::copy_bidirectional(client, &mut up).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::testkit;
    use crate::pg_tls::Io;
    use kepr_core::binding::Inject;
    use kepr_core::gate_protocol::TargetKind;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    const REAL: &str = "real-mysql-pw";

    /// What the fake server saw: the login, the full-auth password if
    /// asked for one, then the command bytes.
    #[derive(Debug)]
    enum Seen {
        Login(HandshakeResponse, Vec<u8>),
        Password(Vec<u8>),
        Command(Vec<u8>),
    }

    /// A MySQL server on loopback announcing `plugin`; with `full`, it
    /// asks for caching_sha2 full authentication. Answers COM_PING.
    async fn fake_mysql(
        plugin: &'static str,
        tls: Option<Arc<rustls::ServerConfig>>,
        full: bool,
    ) -> (u16, mpsc::UnboundedReceiver<Seen>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let (tx, tls) = (tx.clone(), tls.clone());
                tokio::spawn(async move {
                    let nonce = b"abcdefghijklmnopqrst".to_vec();
                    let ssl = if tls.is_some() { caps::SSL } else { 0 };
                    let g = Greeting {
                        version: "8.0.36".into(),
                        conn_id: 7,
                        scramble: nonce.clone(),
                        caps: ssl | !(caps::SSL | caps::COMPRESS),
                        charset: 255,
                        status: 2,
                        reserved: [0; 10],
                        plugin: plugin.into(),
                    };
                    write_packet(&mut s, 0, &g.encode()).await.unwrap();
                    let (_, mut p) = read_packet(&mut s).await.unwrap();
                    let mut s: Box<dyn Io> = match tls {
                        Some(cfg) => {
                            assert_eq!(p.len(), 32, "SSLRequest first");
                            let t = tokio_rustls::TlsAcceptor::from(cfg)
                                .accept(s)
                                .await
                                .unwrap();
                            let mut t: Box<dyn Io> = Box::new(t);
                            p = read_packet(&mut t).await.unwrap().1;
                            t
                        }
                        None => Box::new(s),
                    };
                    let resp = HandshakeResponse::parse(&p).unwrap();
                    let _ = tx.send(Seen::Login(resp, nonce));
                    let mut seq = if full {
                        write_packet(&mut s, 2, &[0x01, 0x04]).await.unwrap();
                        let Ok((q, pw)) = read_packet(&mut s).await else {
                            return; // the gate refused to send it
                        };
                        let _ = tx.send(Seen::Password(pw));
                        q + 1
                    } else if plugin == CACHING_SHA2 {
                        write_packet(&mut s, 2, &[0x01, 0x03]).await.unwrap();
                        3
                    } else {
                        2
                    };
                    write_packet(&mut s, seq, &wire::ok_packet(2))
                        .await
                        .unwrap();
                    while let Ok((_, cmd)) = read_packet(&mut s).await {
                        let _ = tx.send(Seen::Command(cmd));
                        seq = 1;
                        write_packet(&mut s, seq, &wire::ok_packet(2))
                            .await
                            .unwrap();
                    }
                });
            }
        });
        (port, rx)
    }

    fn record(sslmode: &str, ca_pem: &str) -> String {
        serde_json::json!({
            "kind": "mysql", "user": "app", "password": REAL, "database": "prod",
            "sslmode": sslmode, "ca_pem": ca_pem,
        })
        .to_string()
    }

    async fn gate_for(rec: String, host: &str, port: u16) -> u16 {
        let state = testkit::state(&rec, Inject::Mysql);
        testkit::listen(state, testkit::route(TargetKind::Mysql, host, port)).await
    }

    /// Log in through the gate as a client using `plugin`; returns every
    /// packet after the response, up to and including OK or ERR.
    async fn client(gate: u16, plugin: &str, password: &str) -> (TcpStream, Vec<Vec<u8>>) {
        let mut c = TcpStream::connect(("127.0.0.1", gate)).await.unwrap();
        let (_, g) = read_packet(&mut c).await.unwrap();
        let g = Greeting::parse(&g).unwrap();
        assert_eq!(g.caps & caps::SSL, 0, "no TLS offered on loopback");
        assert_eq!(g.plugin, CACHING_SHA2);
        let auth = wire::scramble_for(plugin, password.as_bytes(), &g.scramble).unwrap();
        let r = HandshakeResponse::new(caps::DEPRECATE_EOF, "agent", auth, plugin);
        write_packet(&mut c, 1, &r.encode()).await.unwrap();
        let mut got = Vec::new();
        loop {
            let (_, p) = read_packet(&mut c).await.unwrap();
            let last = matches!(p.first(), Some(0x00 | 0xff));
            got.push(p);
            if last {
                return (c, got);
            }
        }
    }

    fn login_seen(s: Seen) -> (HandshakeResponse, Vec<u8>) {
        match s {
            Seen::Login(r, n) => (r, n),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn placeholder_login_reaches_the_server_with_the_real_password() {
        let (up, mut seen) = fake_mysql(CACHING_SHA2, None, false).await;
        let gate = gate_for(record("disable", ""), "127.0.0.1", up).await;
        let (mut c, got) = client(gate, CACHING_SHA2, &testkit::placeholder(0)).await;
        assert_eq!(got, vec![vec![0x01, 0x03], wire::ok_packet(2)]);
        let (resp, nonce) = login_seen(seen.recv().await.unwrap());
        assert_eq!(
            (resp.user.as_str(), resp.database.as_deref()),
            ("app", Some("prod"))
        );
        assert_eq!(resp.auth, wire::sha2_scramble(REAL.as_bytes(), &nonce));
        assert_ne!(
            resp.caps & caps::DEPRECATE_EOF,
            0,
            "client capabilities kept"
        );
        // Then packets pass through unchanged.
        write_packet(&mut c, 0, &[0x0e]).await.unwrap();
        assert_eq!(read_packet(&mut c).await.unwrap().1, wire::ok_packet(2));
        assert!(matches!(seen.recv().await, Some(Seen::Command(p)) if p == [0x0e]));
    }

    #[tokio::test]
    async fn native_password_clients_and_servers() {
        let (up, mut seen) = fake_mysql(NATIVE, None, false).await;
        let gate = gate_for(record("disable", ""), "127.0.0.1", up).await;
        let (_c, got) = client(gate, NATIVE, &testkit::placeholder(0)).await;
        assert_eq!(got, vec![wire::ok_packet(2)]);
        let (resp, nonce) = login_seen(seen.recv().await.unwrap());
        assert_eq!(resp.plugin.as_deref(), Some(NATIVE));
        assert_eq!(resp.auth, wire::native_scramble(REAL.as_bytes(), &nonce));
    }

    #[tokio::test]
    async fn wrong_placeholder_gets_access_denied() {
        let (up, mut seen) = fake_mysql(CACHING_SHA2, None, false).await;
        let gate = gate_for(record("disable", ""), "127.0.0.1", up).await;
        for pw in [testkit::placeholder(1), "kepr-ph-nope".into(), REAL.into()] {
            let (mut c, got) = client(gate, CACHING_SHA2, &pw).await;
            let (code, msg) = wire::parse_err(&got[0]).unwrap();
            assert_eq!(code, wire::ACCESS_DENIED, "{msg}");
            let mut rest = Vec::new();
            c.read_to_end(&mut rest).await.unwrap();
        }
        let quiet = tokio::time::timeout(std::time::Duration::from_millis(200), seen.recv());
        assert!(quiet.await.is_err(), "the server never saw a login");
    }

    #[tokio::test]
    async fn full_authentication_only_inside_tls() {
        let ca = crate::ca::SessionCa::new(&["localhost".into()]).unwrap();
        let cfg = ca.server_config("localhost").unwrap();
        let (up, mut seen) = fake_mysql(CACHING_SHA2, Some(cfg), true).await;
        let gate = gate_for(record("verify-full", ca.pem()), "localhost", up).await;
        let (_c, got) = client(gate, CACHING_SHA2, &testkit::placeholder(0)).await;
        assert_eq!(got.last().unwrap(), &wire::ok_packet(2));
        login_seen(seen.recv().await.unwrap());
        assert!(
            matches!(seen.recv().await, Some(Seen::Password(p)) if p == [REAL.as_bytes(), b"\0"].concat())
        );

        let (up, mut seen) = fake_mysql(CACHING_SHA2, None, true).await;
        let gate = gate_for(record("disable", ""), "127.0.0.1", up).await;
        let (_c, got) = client(gate, CACHING_SHA2, &testkit::placeholder(0)).await;
        let (_, msg) = wire::parse_err(got.last().unwrap()).unwrap();
        assert!(msg.contains("TLS"), "{msg}");
        login_seen(seen.recv().await.unwrap());
        let quiet = tokio::time::timeout(std::time::Duration::from_millis(200), seen.recv());
        assert!(quiet.await.is_err(), "the password was not sent in clear");
    }
}
