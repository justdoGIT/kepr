//! Raw TCP tunnels (T7.03). `kepr agent run --tunnel NAME=host:port`
//! gives the session a loopback port that the gate pipes to that one
//! host:port, byte for byte and without any credential, so an agent can
//! reach an internal service it has no other route to. The egress proxy
//! also lets `CONNECT` through to exactly these targets, which is how a
//! sandbox under `--isolate-net` (whose only way out is the gate's port)
//! reaches them; every other host stays refused there.

use std::sync::Arc;
use std::time::Instant;

use tokio::net::TcpStream;

use crate::db::{self, DbRoute};
use crate::proxy::State;
use kepr_core::gate_protocol::GateRoute;

impl State {
    /// Remember the session's tunnel targets for the egress proxy.
    pub fn with_tunnels(mut self, routes: &[GateRoute]) -> Self {
        self.tunnels = routes
            .iter()
            .filter(|r| r.is_tunnel())
            .filter_map(|r| r.target.as_ref())
            .map(|t| (t.host.to_ascii_lowercase(), t.port))
            .collect();
        self
    }
}

/// Is `host:port` one of the session's tunnel targets?
pub fn allowed(state: &State, host: &str, port: u16) -> bool {
    state
        .tunnels
        .iter()
        .any(|(h, p)| *p == port && h.eq_ignore_ascii_case(host))
}

/// Serve one connection on a tunnel's loopback port.
pub async fn serve_conn(state: Arc<State>, route: Arc<DbRoute>, mut client: TcpStream) {
    let start = Instant::now();
    let result = match crate::pg_tls::connect(&route.target).await {
        Ok(mut up) => {
            crate::recording::relay(&state, &route, &mut client, &mut up).await;
            Ok(())
        }
        Err(_) => Err((502, None)),
    };
    db::log(&state, &route, "CONNECT", &result, start);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::testkit;
    use kepr_core::binding::Inject;
    use kepr_core::gate_protocol::{tunnel_route_key, DbTarget, TargetKind};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn echo_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    fn tunnel_route(port: u16) -> GateRoute {
        GateRoute {
            provider: tunnel_route_key("WIKI"),
            cred: "WIKI".into(),
            slot: 0,
            target: Some(DbTarget {
                host: "127.0.0.1".into(),
                port,
                kind: TargetKind::Tcp,
                ..Default::default()
            }),
        }
    }

    async fn round_trip(s: &mut TcpStream) -> Vec<u8> {
        s.write_all(b"hello tunnel").await.unwrap();
        let mut buf = vec![0u8; 12];
        s.read_exact(&mut buf).await.unwrap();
        buf
    }

    #[tokio::test]
    async fn bytes_round_trip_through_the_tunnel_port() {
        let echo = echo_server().await;
        let state = testkit::state("{}", Inject::Bearer);
        let port = testkit::listen(state, testkit::route(TargetKind::Tcp, "127.0.0.1", echo)).await;
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(round_trip(&mut c).await, b"hello tunnel");
    }

    /// CONNECT through the gate's proxy port; returns the status line.
    async fn connect(gate: u16, target: &str) -> (TcpStream, String) {
        let mut s = TcpStream::connect(("127.0.0.1", gate)).await.unwrap();
        let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut r = tokio::io::BufReader::new(&mut s);
        let mut status = String::new();
        r.read_line(&mut status).await.unwrap();
        loop {
            let mut l = String::new();
            r.read_line(&mut l).await.unwrap();
            if l == "\r\n" || l.is_empty() {
                break;
            }
        }
        (s, status)
    }

    #[tokio::test]
    async fn isolated_sessions_reach_only_their_tunnel_targets() {
        let echo = echo_server().await;
        let other = echo_server().await;
        let state = testkit::state("{}", Inject::Bearer);
        let state = Arc::try_unwrap(state)
            .ok()
            .unwrap()
            .with_egress(None, false)
            .with_tunnels(&[tunnel_route(echo)]);
        assert!(allowed(&state, "127.0.0.1", echo));
        assert!(!allowed(&state, "127.0.0.1", other));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate = l.local_addr().unwrap().port();
        tokio::spawn(crate::proxy::serve(l, Arc::new(state)));
        let (mut s, status) = connect(gate, &format!("127.0.0.1:{echo}")).await;
        assert!(status.contains("200"), "{status}");
        assert_eq!(round_trip(&mut s).await, b"hello tunnel");
        let (_s, status) = connect(gate, &format!("127.0.0.1:{other}")).await;
        assert!(status.contains("403"), "{status}");
    }
}
