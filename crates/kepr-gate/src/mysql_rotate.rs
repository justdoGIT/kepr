//! MySQL password rotation through the gate (T7.04), the counterpart of
//! pg_rotate.rs. `kepr agent rotate-db` has the daemon put a random
//! `pending_password` into the sealed record, then logs in through the
//! gate as user `kepr_rotate` (with the route's placeholder, on a route
//! only rotate-db starts). The gate logs in with the current password and
//! runs `ALTER USER CURRENT_USER() IDENTIFIED BY '<pending>'`.
//!
//! Unlike PostgreSQL there is no verifier form every auth plugin accepts,
//! so the statement carries the password itself: it only crosses the
//! gate's upstream leg (TLS unless the record says `sslmode=disable`), and
//! the server masks it in its general, slow and binary logs.
//!
//! Re-runnable: if a previous run changed the server but never committed,
//! the current password fails and the pending one logs in. The gate then
//! reports success without another ALTER, and the CLI commits.

use tokio::net::TcpStream;

use crate::db::Login;
use crate::mysql_auth::{self, read_packet, write_packet, Refused};
use crate::pg_tls::Io;
use kepr_core::gate_protocol::DbTarget;
use kepr_core::generate::ZeroString;
use kepr_core::mysql_wire::{self as wire, Greeting, HandshakeResponse};

/// Set `pending` as the logged-in account's password.
async fn alter(up: &mut Box<dyn Io>, pending: &str) -> Result<(), String> {
    if !(16..=128).contains(&pending.len()) {
        return Err("pending password must be 16-128 characters".into());
    }
    let q = wire::alter_password(pending).ok_or("pending password cannot be quoted")?;
    write_packet(up, 0, &q).await.map_err(|e| e.to_string())?;
    drop(q);
    let (_, p) = read_packet(up).await.map_err(|e| e.to_string())?;
    match p.first() {
        Some(0x00) => Ok(()),
        _ => Err(wire::parse_err(&p)
            .map(|(_, m)| m)
            .unwrap_or_else(|| "unexpected reply to ALTER USER".into())),
    }
}

/// One `kepr_rotate` login on `tcp`, which has delivered `server`'s
/// greeting. Returns the OK for the client once the server has the
/// pending password.
pub(crate) async fn session(
    tcp: TcpStream,
    (server, client): (&Greeting, &HandshakeResponse),
    target: &DbTarget,
    l: &Login,
) -> Result<Vec<u8>, Refused> {
    let fail = |m: String| Refused::Failed(format!("rotate: {m}"));
    let Some(pending) = l.pending_password.as_ref() else {
        return Err(fail(
            "no rotation pending (run kepr agent rotate-db)".into(),
        ));
    };
    let first = match mysql_auth::login(tcp, (server, client), &target.host, l).await {
        Ok((mut up, ok)) => {
            return alter(&mut up, pending.as_str())
                .await
                .map(|()| ok)
                .map_err(fail)
        }
        Err(first) => first,
    };
    // An earlier run may have set the pending password already.
    let retry = Login {
        user: l.user.clone(),
        password: ZeroString::from_string(pending.0.clone()),
        database: l.database.clone(),
        sslmode: l.sslmode.clone(),
        ca_pem: l.ca_pem.clone(),
        pending_password: None,
    };
    let Ok(mut tcp) = crate::pg_tls::connect(target).await else {
        return Err(first);
    };
    let greeting = read_packet(&mut tcp).await.ok();
    let Some(g) = greeting.and_then(|(_, p)| Greeting::parse(&p)) else {
        return Err(first);
    };
    match mysql_auth::login(tcp, (&g, client), &target.host, &retry).await {
        Ok((_, ok)) => Ok(ok),
        Err(_) => Err(first),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{testkit, DbRoute};
    use kepr_core::binding::Inject;
    use kepr_core::gate_protocol::TargetKind;
    use kepr_core::mysql_wire::{caps, CACHING_SHA2, NATIVE, ROTATE_USER};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    const REAL: &str = "real-mysql-pw";
    const PENDING: &str = "Pending0123456789abcdef";

    /// A mysql_native_password server whose one account's password is
    /// `pw`; ALTER USER … IDENTIFIED BY '<x>' changes it. Every query
    /// text is sent on the channel.
    async fn fake_server(pw: &str) -> (u16, Arc<Mutex<String>>, mpsc::UnboundedReceiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let pw = Arc::new(Mutex::new(pw.to_string()));
        let (tx, rx) = mpsc::unbounded_channel();
        let shared = pw.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let (pw, tx) = (shared.clone(), tx.clone());
                tokio::spawn(async move {
                    let nonce = b"abcdefghijklmnopqrst".to_vec();
                    let g = Greeting {
                        version: "8.0.36".into(),
                        conn_id: 1,
                        scramble: nonce.clone(),
                        caps: !(caps::SSL | caps::COMPRESS),
                        charset: 255,
                        status: 2,
                        reserved: [0; 10],
                        plugin: NATIVE.into(),
                    };
                    write_packet(&mut s, 0, &g.encode()).await.unwrap();
                    let (_, p) = read_packet(&mut s).await.unwrap();
                    let r = HandshakeResponse::parse(&p).unwrap();
                    let want = wire::native_scramble(pw.lock().unwrap().as_bytes(), &nonce);
                    if r.user != "app" || r.auth != want {
                        let e = wire::err_packet(wire::ACCESS_DENIED, "28000", "Access denied");
                        let _ = write_packet(&mut s, 2, &e).await;
                        return;
                    }
                    write_packet(&mut s, 2, &wire::ok_packet(2)).await.unwrap();
                    while let Ok((_, cmd)) = read_packet(&mut s).await {
                        let q = String::from_utf8(cmd[1..].to_vec()).unwrap();
                        let _ = tx.send(q.clone());
                        let lit = q.strip_prefix("ALTER USER CURRENT_USER() IDENTIFIED BY '");
                        let reply = match lit.and_then(|l| l.strip_suffix('\'')) {
                            Some(new) => {
                                *pw.lock().unwrap() = new.replace("''", "'");
                                wire::ok_packet(2)
                            }
                            None => wire::err_packet(1064, "42000", "syntax"),
                        };
                        write_packet(&mut s, 1, &reply).await.unwrap();
                    }
                });
            }
        });
        (port, pw, rx)
    }

    fn record(pending: Option<&str>) -> String {
        let mut r = serde_json::json!({
            "kind": "mysql", "user": "app", "password": REAL, "database": "prod",
            "sslmode": "disable",
        });
        if let Some(p) = pending {
            r["pending_password"] = p.into();
        }
        r.to_string()
    }

    async fn gate(rec: String, port: u16, rotate: bool) -> u16 {
        let state = testkit::state(&rec, Inject::Mysql);
        let base = testkit::route(TargetKind::Mysql, "127.0.0.1", port);
        let mut target = base.target.clone();
        target.rotate = rotate;
        let route = Arc::new(DbRoute {
            key: base.key.clone(),
            cred: base.cred.clone(),
            slot: base.slot,
            target,
        });
        testkit::listen(state, route).await
    }

    /// Log in through the gate as `user`; the final OK or ERR payload.
    async fn login_as(gate: u16, user: &str) -> Vec<u8> {
        let mut c = TcpStream::connect(("127.0.0.1", gate)).await.unwrap();
        let (_, g) = read_packet(&mut c).await.unwrap();
        let g = Greeting::parse(&g).unwrap();
        let auth = wire::sha2_scramble(testkit::placeholder(0).as_bytes(), &g.scramble);
        let r = HandshakeResponse::new(0, user, auth, CACHING_SHA2);
        write_packet(&mut c, 1, &r.encode()).await.unwrap();
        loop {
            let (_, p) = read_packet(&mut c).await.unwrap();
            if matches!(p.first(), Some(0x00 | 0xff)) {
                return p;
            }
        }
    }

    #[tokio::test]
    async fn rotates_the_password_with_an_alter_user() {
        let (up, pw, mut queries) = fake_server(REAL).await;
        let gate = gate(record(Some(PENDING)), up, true).await;
        assert_eq!(login_as(gate, ROTATE_USER).await, wire::ok_packet(2));
        assert_eq!(
            queries.recv().await.unwrap(),
            format!("ALTER USER CURRENT_USER() IDENTIFIED BY '{PENDING}'")
        );
        assert_eq!(*pw.lock().unwrap(), PENDING);
    }

    #[tokio::test]
    async fn resumes_when_the_server_already_has_the_pending_password() {
        let (up, pw, mut queries) = fake_server(PENDING).await;
        let gate = gate(record(Some(PENDING)), up, true).await;
        assert_eq!(login_as(gate, ROTATE_USER).await, wire::ok_packet(2));
        assert_eq!(*pw.lock().unwrap(), PENDING);
        assert!(queries.try_recv().is_err(), "no second ALTER");
    }

    #[tokio::test]
    async fn fails_when_neither_password_logs_in() {
        let (up, pw, _q) = fake_server("someone-else-changed-it").await;
        let gate = gate(record(Some(PENDING)), up, true).await;
        let (code, _) = wire::parse_err(&login_as(gate, ROTATE_USER).await).unwrap();
        assert_eq!(code, wire::ACCESS_DENIED);
        assert_eq!(*pw.lock().unwrap(), "someone-else-changed-it");
    }

    #[tokio::test]
    async fn needs_a_pending_password_and_a_rotate_route() {
        let (up, pw, _q) = fake_server(REAL).await;
        let gate1 = gate(record(None), up, true).await;
        let (_, msg) = wire::parse_err(&login_as(gate1, ROTATE_USER).await).unwrap();
        assert!(msg.contains("no rotation pending"), "{msg}");
        // An agent's session never has `rotate`: refused before any login.
        let gate2 = gate(record(Some(PENDING)), up, false).await;
        let (code, msg) = wire::parse_err(&login_as(gate2, ROTATE_USER).await).unwrap();
        assert_eq!(code, 1227, "{msg}");
        assert_eq!(*pw.lock().unwrap(), REAL);
        // An ordinary login on a rotate route is just a login.
        let gate3 = gate(record(Some(PENDING)), up, true).await;
        assert_eq!(login_as(gate3, "agent").await, wire::ok_packet(2));
        assert_eq!(*pw.lock().unwrap(), REAL);
    }
}
