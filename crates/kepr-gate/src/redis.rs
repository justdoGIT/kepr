//! Redis proxy (T7.01). The agent connects to a local port and
//! authenticates with the session placeholder (`AUTH`, or `HELLO … AUTH`);
//! the gate logs in to the real server with the sealed `database` record
//! (`kind: redis`) and then relays bytes unchanged both ways.
//!
//! Only the client's first command is parsed (a RESP2 array of bulk
//! strings, or an inline command). Upstream the gate always logs in with
//! `AUTH` (the one-argument form for the `default` user, so servers
//! without ACLs work) and `SELECT`s the record's database when it is not
//! 0; then it answers the client's `AUTH` with `+OK`, or forwards the
//! client's `HELLO` without its credentials. TLS upstream unless the
//! record says `sslmode=disable` (`redis://` rather than `rediss://`).

use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::db::{self, DbRoute, Fail, Login};
use crate::pg_tls::Io;
use crate::proxy::State;

const MAX_ARGS: usize = 16;
const MAX_ARG: usize = 4096;
const NOAUTH: &str = "NOAUTH kepr: authenticate with the session placeholder first";

pub(crate) type Arg = Zeroizing<Vec<u8>>;

fn bad() -> std::io::Error {
    std::io::ErrorKind::InvalidData.into()
}

/// One CRLF-terminated line, without the terminator. Read byte by byte so
/// nothing after the first command is consumed: a client may pipeline its
/// next commands, and those must reach the server.
pub(crate) async fn read_line(c: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Arg> {
    let mut line = Zeroizing::new(Vec::with_capacity(64));
    loop {
        match c.read_u8().await? {
            b'\n' => {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            _ if line.len() >= MAX_ARG + 16 => return Err(bad()),
            b => line.push(b),
        }
    }
}

fn num(s: &[u8]) -> Option<usize> {
    std::str::from_utf8(s).ok()?.parse().ok()
}

/// The client's first command: a RESP2 array of bulk strings or an
/// inline command line.
pub(crate) async fn read_command(c: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<Arg>> {
    let first = read_line(c).await?;
    let Some(count) = first.strip_prefix(b"*") else {
        return Ok(first
            .split(|b| b.is_ascii_whitespace())
            .filter(|a| !a.is_empty())
            .map(|a| Zeroizing::new(a.to_vec()))
            .collect());
    };
    let n = num(count)
        .filter(|n| (1..=MAX_ARGS).contains(n))
        .ok_or_else(bad)?;
    let mut args = Vec::with_capacity(n);
    for _ in 0..n {
        let head = read_line(c).await?;
        let len = head
            .strip_prefix(b"$")
            .and_then(num)
            .filter(|l| *l <= MAX_ARG)
            .ok_or_else(bad)?;
        let mut a = Zeroizing::new(vec![0u8; len + 2]);
        c.read_exact(&mut a).await?;
        if !a.ends_with(b"\r\n") {
            return Err(bad());
        }
        a.truncate(len);
        args.push(a);
    }
    Ok(args)
}

/// A command as a RESP2 array (sized up front: it may hold a password).
pub(crate) fn encode(args: &[&[u8]]) -> Arg {
    let len = 16 + args.iter().map(|a| a.len() + 16).sum::<usize>();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// What the client's first command asks for.
#[derive(Debug, PartialEq)]
pub(crate) struct Opening {
    /// The password it gave: must be this route's placeholder.
    pub(crate) placeholder: String,
    /// For `HELLO`: the command to forward once logged in (no `AUTH`).
    pub(crate) hello: Option<Vec<Vec<u8>>>,
}

pub(crate) fn opening(args: &[Arg]) -> Result<Opening, &'static str> {
    let upper = |a: &Arg| a.to_ascii_uppercase();
    let text = |a: &Arg| String::from_utf8_lossy(a).into_owned();
    match args.first().map(upper).as_deref() {
        Some(b"AUTH") if (2..=3).contains(&args.len()) => Ok(Opening {
            placeholder: text(&args[args.len() - 1]),
            hello: None,
        }),
        Some(b"HELLO") => {
            let mut keep = vec![b"HELLO".to_vec()];
            let mut i = 1;
            if let Some(v) = args.get(1).filter(|v| num(v).is_some()) {
                keep.push(v.to_vec());
                i = 2;
            }
            let mut placeholder = None;
            while i < args.len() {
                match upper(&args[i]).as_slice() {
                    b"AUTH" if i + 2 < args.len() => {
                        placeholder = Some(text(&args[i + 2]));
                        i += 3;
                    }
                    b"SETNAME" if i + 1 < args.len() => {
                        keep.extend([b"SETNAME".to_vec(), args[i + 1].to_vec()]);
                        i += 2;
                    }
                    _ => return Err("ERR kepr: unsupported HELLO argument"),
                }
            }
            Ok(Opening {
                placeholder: placeholder.ok_or(NOAUTH)?,
                hello: Some(keep),
            })
        }
        _ => Err(NOAUTH),
    }
}

/// An error reply (`-…\r\n`) with any line breaks flattened.
fn error_line(msg: &str) -> Vec<u8> {
    format!("-{}\r\n", msg.replace(['\r', '\n'], " ")).into_bytes()
}

async fn expect_ok(up: &mut Box<dyn Io>) -> Result<(), String> {
    let line = read_line(up).await.map_err(|e| e.to_string())?;
    match line.first() {
        Some(b'+') => Ok(()),
        Some(b'-') => Err(String::from_utf8_lossy(&line[1..]).into_owned()),
        _ => Err("unexpected reply from the server".into()),
    }
}

/// Log in upstream: `AUTH`, then `SELECT` unless the database is 0.
pub(crate) async fn login(up: &mut Box<dyn Io>, l: &Login) -> Result<(), String> {
    let pw = l.password.as_bytes();
    let auth = if l.user.is_empty() || l.user == "default" {
        encode(&[b"AUTH", pw])
    } else {
        encode(&[b"AUTH", l.user.as_bytes(), pw])
    };
    up.write_all(&auth).await.map_err(|e| e.to_string())?;
    expect_ok(up).await?;
    if !matches!(l.database.as_str(), "" | "0") {
        let select = encode(&[b"SELECT", l.database.as_bytes()]);
        up.write_all(&select).await.map_err(|e| e.to_string())?;
        expect_ok(up).await?;
    }
    Ok(())
}

async fn upstream(route: &DbRoute, l: &Login) -> Result<Box<dyn Io>, String> {
    let tcp = crate::pg_tls::connect(&route.target).await?;
    if l.sslmode == "disable" {
        return Ok(Box::new(tcp));
    }
    crate::pg_tls::tls_client(tcp, &route.target.host, &l.ca_pem).await
}

/// Serve one client connection on a Redis route's port.
pub async fn serve_conn(state: Arc<State>, route: Arc<DbRoute>, mut client: TcpStream) {
    let start = Instant::now();
    let mut method = "AUTH";
    let result = session(&state, &route, &mut client, &mut method).await;
    db::log(&state, &route, method, &result, start);
}

async fn session(
    state: &State,
    route: &DbRoute,
    client: &mut TcpStream,
    method: &mut &'static str,
) -> Result<(), Fail> {
    let args = read_command(client).await.map_err(|_| (400, None))?;
    let open = opening(&args);
    drop(args);
    let refuse = |msg: &str, fail: Fail| (error_line(msg), fail);
    let refused = match open {
        Err(e) => Some(refuse(e, (401, None))),
        Ok(ref o) if !state.valid_placeholder(&o.placeholder, route.slot) => Some(refuse(
            "ERR kepr: invalid or missing kepr placeholder",
            (401, None),
        )),
        Ok(_) => db::admit(state)
            .err()
            .map(|m| refuse(&format!("ERR {m}"), (403, Some("limit")))),
    };
    if let Some((line, fail)) = refused {
        let _ = client.write_all(&line).await;
        return Err(fail);
    }
    let open = open.map_err(|_| (401, None))?;
    if open.hello.is_some() {
        *method = "HELLO";
    }
    let Ok(l) = db::resolve_login(state, route).await else {
        let msg = "ERR kepr could not obtain the database login";
        let _ = client.write_all(&error_line(msg)).await;
        return Err((502, None));
    };
    let up = match upstream(route, &l).await {
        Ok(mut up) => login(&mut up, &l).await.map(|()| up),
        Err(e) => Err(e),
    };
    drop(l);
    let mut up = match up {
        Ok(up) => up,
        Err(e) => {
            let msg = format!("ERR kepr: database login failed: {e}");
            let _ = client.write_all(&error_line(&msg)).await;
            return Err((502, None));
        }
    };
    let sent = match &open.hello {
        None => client.write_all(b"+OK\r\n").await,
        Some(cmd) => {
            let refs: Vec<&[u8]> = cmd.iter().map(Vec::as_slice).collect();
            up.write_all(&encode(&refs)).await
        }
    };
    sent.map_err(|_| (502, None))?;
    let _ = tokio::io::copy_bidirectional(client, &mut up).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::testkit;
    use kepr_core::binding::Inject;
    use kepr_core::gate_protocol::TargetKind;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    fn args(v: &[&str]) -> Vec<Arg> {
        v.iter()
            .map(|a| Zeroizing::new(a.as_bytes().to_vec()))
            .collect()
    }

    #[tokio::test]
    async fn parses_resp_arrays_and_inline_commands() {
        let raw = encode(&[b"AUTH", b"u", b"p w"]);
        let mut r: &[u8] = &raw;
        let got = read_command(&mut r).await.unwrap();
        assert_eq!(got, args(&["AUTH", "u", "p w"]));
        let mut inline: &[u8] = b"auth  secret\r\nPING\r\n";
        assert_eq!(
            read_command(&mut inline).await.unwrap(),
            args(&["auth", "secret"])
        );
        assert_eq!(inline, b"PING\r\n", "the next command stays unread");
        for bad in [&b"*0\r\n"[..], b"*1\r\n$99999\r\n", b"*1\r\n$3\r\nabcd\r\n"] {
            let mut r = bad;
            assert!(read_command(&mut r).await.is_err());
        }
    }

    #[test]
    fn opening_commands() {
        let auth = opening(&args(&["AUTH", "ph"])).unwrap();
        assert_eq!((auth.placeholder.as_str(), auth.hello), ("ph", None));
        assert_eq!(
            opening(&args(&["auth", "user", "ph"])).unwrap().placeholder,
            "ph"
        );
        let hello = opening(&args(&["hello", "3", "AUTH", "u", "ph", "SETNAME", "x"])).unwrap();
        assert_eq!(hello.placeholder, "ph");
        let want: Vec<Vec<u8>> = ["HELLO", "3", "SETNAME", "x"]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        assert_eq!(hello.hello, Some(want));
        assert_eq!(opening(&args(&["HELLO", "3"])), Err(NOAUTH));
        assert_eq!(opening(&args(&["PING"])), Err(NOAUTH));
        assert!(opening(&args(&["HELLO", "3", "AUTH", "u", "p", "BOGUS"])).is_err());
    }

    /// A Redis server on loopback: reports every command it gets, answers
    /// AUTH/SELECT with +OK, PING with +PONG and HELLO with a small map.
    async fn fake_redis(
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> (u16, mpsc::UnboundedReceiver<Vec<String>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let tx = tx.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    let mut s: Box<dyn Io> = match tls {
                        Some(cfg) => match tokio_rustls::TlsAcceptor::from(cfg).accept(s).await {
                            Ok(t) => Box::new(t),
                            Err(_) => return,
                        },
                        None => Box::new(s),
                    };
                    while let Ok(cmd) = read_command(&mut s).await {
                        let words: Vec<String> = cmd
                            .iter()
                            .map(|a| String::from_utf8_lossy(a).into_owned())
                            .collect();
                        let reply: &[u8] = match words[0].as_str() {
                            "PING" => b"+PONG\r\n",
                            "HELLO" => b"%1\r\n+server\r\n+redis\r\n",
                            _ => b"+OK\r\n",
                        };
                        let _ = tx.send(words);
                        if s.write_all(reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, rx)
    }

    fn record(extra: serde_json::Value) -> String {
        let mut r = serde_json::json!({
            "kind": "redis", "user": "default", "password": "real-redis-pw",
            "database": "0", "sslmode": "disable",
        });
        for (k, v) in extra.as_object().unwrap() {
            r[k] = v.clone();
        }
        r.to_string()
    }

    async fn gate_for(rec: String, host: &str, port: u16) -> u16 {
        let state = testkit::state(&rec, Inject::Redis);
        let route = testkit::route(TargetKind::Redis, host, port);
        testkit::listen(state, route).await
    }

    async fn reply_line(c: &mut TcpStream) -> String {
        String::from_utf8_lossy(&read_line(c).await.unwrap()).into_owned()
    }

    #[tokio::test]
    async fn auth_placeholder_is_replaced() {
        let (up, mut seen) = fake_redis(None).await;
        let rec = record(serde_json::json!({"user": "app", "database": "2"}));
        let gate = gate_for(rec, "127.0.0.1", up).await;
        let mut c = TcpStream::connect(("127.0.0.1", gate)).await.unwrap();
        let ph = testkit::placeholder(0);
        c.write_all(&encode(&[b"AUTH", ph.as_bytes()]))
            .await
            .unwrap();
        assert_eq!(reply_line(&mut c).await, "+OK");
        assert_eq!(
            seen.recv().await.unwrap(),
            vec!["AUTH", "app", "real-redis-pw"]
        );
        assert_eq!(seen.recv().await.unwrap(), vec!["SELECT", "2"]);
        c.write_all(&encode(&[b"PING"])).await.unwrap();
        assert_eq!(reply_line(&mut c).await, "+PONG");
        assert_eq!(seen.recv().await.unwrap(), vec!["PING"]);
    }

    #[tokio::test]
    async fn wrong_placeholder_gets_an_error_and_never_reaches_the_server() {
        let (up, mut seen) = fake_redis(None).await;
        let gate = gate_for(record(serde_json::json!({})), "127.0.0.1", up).await;
        for first in [
            encode(&[b"AUTH", b"kepr-ph-0123456789abcdef-0000-0000000000000000"]),
            encode(&[b"AUTH", testkit::placeholder(1).as_bytes()]),
            encode(&[b"GET", b"k"]),
        ] {
            let mut c = TcpStream::connect(("127.0.0.1", gate)).await.unwrap();
            c.write_all(&first).await.unwrap();
            assert!(reply_line(&mut c).await.starts_with('-'));
            let mut rest = Vec::new();
            c.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty(), "the gate closes the connection");
        }
        let quiet = tokio::time::timeout(std::time::Duration::from_millis(200), seen.recv());
        assert!(quiet.await.is_err());
    }

    #[tokio::test]
    async fn hello_with_auth_logs_in_then_forwards_hello() {
        let (up, mut seen) = fake_redis(None).await;
        let gate = gate_for(record(serde_json::json!({})), "127.0.0.1", up).await;
        let mut c = TcpStream::connect(("127.0.0.1", gate)).await.unwrap();
        let ph = testkit::placeholder(0);
        let hello = encode(&[
            b"HELLO",
            b"3",
            b"AUTH",
            b"x",
            ph.as_bytes(),
            b"SETNAME",
            b"a",
        ]);
        c.write_all(&hello).await.unwrap();
        assert_eq!(reply_line(&mut c).await, "%1");
        assert_eq!(seen.recv().await.unwrap(), vec!["AUTH", "real-redis-pw"]);
        assert_eq!(
            seen.recv().await.unwrap(),
            vec!["HELLO", "3", "SETNAME", "a"]
        );
    }

    #[tokio::test]
    async fn tls_upstream_unless_disabled() {
        let ca = crate::ca::SessionCa::new(&["localhost".into()]).unwrap();
        let (up, mut seen) = fake_redis(Some(ca.server_config("localhost").unwrap())).await;
        let rec = record(serde_json::json!({"sslmode": "verify-full", "ca_pem": ca.pem()}));
        let gate = gate_for(rec, "localhost", up).await;
        let mut c = TcpStream::connect(("127.0.0.1", gate)).await.unwrap();
        let ph = testkit::placeholder(0);
        c.write_all(&encode(&[b"AUTH", ph.as_bytes()]))
            .await
            .unwrap();
        assert_eq!(reply_line(&mut c).await, "+OK");
        assert_eq!(seen.recv().await.unwrap(), vec!["AUTH", "real-redis-pw"]);
        // Without the CA the server's certificate is refused.
        let rec = record(serde_json::json!({"sslmode": "verify-full"}));
        let gate = gate_for(rec, "localhost", up).await;
        let mut c = TcpStream::connect(("127.0.0.1", gate)).await.unwrap();
        c.write_all(&encode(&[b"AUTH", ph.as_bytes()]))
            .await
            .unwrap();
        assert!(reply_line(&mut c).await.contains("TLS"));
    }
}
