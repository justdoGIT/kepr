//! Egress proxy (P2.1): `CONNECT host:443` from tools the agent runs.
//!
//! For a host a sealed key of this session is bound to, the gate accepts
//! the TLS itself (session CA, ca.rs) and serves the decrypted requests
//! through the same `proxy_request` path as base-URL traffic: the
//! placeholder must be valid, limits and DLP apply, and the real key is
//! added toward the real host over TLS with the gate's compiled-in roots.
//! Other hosts are tunnelled byte-for-byte when the session allows it,
//! and refused under `--isolate-net` unless they are one of the
//! session's `--tunnel` targets (T7.03).

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

use crate::journal;
use crate::proxy::{kepr_error, proxy_request, proxy_request_to, Body, State};

fn ok() -> Response<Body> {
    Response::new(Empty::<Bytes>::new().map_err(|n| match n {}).boxed())
}

fn log(state: &State, target: &str, status: StatusCode, blocked: Option<&str>, start: Instant) {
    let entry = journal::Entry {
        provider: "egress",
        host: target,
        method: "CONNECT",
        path: "",
        status: status.as_u16(),
        bytes_out: 0,
        ms: start.elapsed().as_millis(),
        blocked,
    };
    journal::emit(state, &entry);
}

/// The provider name if `host:port` is bound in this session.
fn bound_provider(state: &State, host: &str, port: u16) -> Option<&'static str> {
    let ca = state.ca.as_ref()?;
    let p = kepr_core::providers::by_host(host)?;
    (port == 443 && ca.covers(host) && state.routes.contains_key(p.name)).then_some(p.name)
}

/// T2.04: the provider whose domain `host` is under (gcloud:
/// `*.googleapis.com`), when the daemon releases this session's key for
/// that exact host.
async fn domain_bound(state: &Arc<State>, host: &str, port: u16) -> Option<&'static str> {
    let pname = kepr_core::providers::under_domain(host)?;
    let route = state.routes.get(pname)?;
    if port != 443 || !state.ca.as_ref().is_some_and(|c| c.covers(host)) {
        return None;
    }
    let (cache, cred, h) = (state.cache.clone(), route.cred.clone(), host.to_string());
    match tokio::task::spawn_blocking(move || cache.get(&cred, &h, 443)).await {
        Ok(Ok(_)) => Some(pname),
        _ => None,
    }
}

/// Who serves an intercepted connection's requests.
#[derive(Clone)]
enum To {
    Provider(&'static str),
    Aws(String),
    Domain(&'static str, String),
    /// T12.07: github.com, smart-HTTP only (git_http.rs).
    Git,
}

/// Accept the agent's TLS with a session-CA leaf for `host` and serve the
/// requests inside it.
fn intercept(
    state: Arc<State>,
    req: Request<Incoming>,
    (host, target): (&str, &str),
    start: Instant,
    to: To,
) -> Response<Body> {
    let Some(cfg) = state.ca.as_ref().and_then(|ca| ca.server_config(host).ok()) else {
        return kepr_error(StatusCode::BAD_GATEWAY, "kepr", "no certificate for host");
    };
    log(&state, target, StatusCode::OK, Some("intercepted"), start);
    tokio::spawn(async move {
        let Ok(up) = hyper::upgrade::on(req).await else {
            return;
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
        let Ok(tls) = acceptor.accept(TokioIo::new(up)).await else {
            return;
        };
        let svc = hyper::service::service_fn(move |r: Request<Incoming>| {
            let (st, to, path) = (state.clone(), to.clone(), r.uri().path().to_string());
            async move {
                match to {
                    To::Provider(pname) => proxy_request(st, pname, &path, r).await,
                    To::Aws(h) => crate::aws_egress::handle(st, h, r).await,
                    To::Domain(p, h) => proxy_request_to(st, p, Some(h), &path, r).await,
                    To::Git => crate::git_http::handle(st, &path, r).await,
                }
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(tls), svc)
            .await;
    });
    ok()
}

pub async fn connect(state: Arc<State>, req: Request<Incoming>) -> Response<Body> {
    let start = Instant::now();
    let Some(auth) = req.uri().authority().cloned() else {
        return kepr_error(StatusCode::BAD_REQUEST, "kepr", "CONNECT needs host:port");
    };
    let host = auth.host().to_ascii_lowercase();
    let port = auth.port_u16().unwrap_or(443);
    let target = format!("{host}:{port}");

    if let Some(pname) = bound_provider(&state, &host, port) {
        let to = match pname {
            "git" => To::Git,
            p => To::Provider(p),
        };
        return intercept(state, req, (&host, &target), start, to);
    }
    if let Some(pname) = domain_bound(&state, &host, port).await {
        let to = To::Domain(pname, host.clone());
        return intercept(state, req, (&host, &target), start, to);
    }
    // T2.02: an AWS host one of the session's AWS keys is bound to.
    if crate::aws_egress::bound(&state, &host, port).await {
        let to = To::Aws(host.clone());
        return intercept(state, req, (&host, &target), start, to);
    }

    if !state.tunnel && !crate::tunnel::allowed(&state, &host, port) {
        log(
            &state,
            &target,
            StatusCode::FORBIDDEN,
            Some("egress"),
            start,
        );
        return kepr_error(
            StatusCode::FORBIDDEN,
            "kepr_blocked",
            &format!(
                "kepr: this session can only reach the hosts its keys are bound to, not {host}"
            ),
        );
    }
    let upstream = match tokio::net::TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(_) => {
            log(&state, &target, StatusCode::BAD_GATEWAY, None, start);
            return kepr_error(StatusCode::BAD_GATEWAY, "kepr", "cannot reach host");
        }
    };
    log(&state, &target, StatusCode::OK, None, start);
    tokio::spawn(async move {
        if let Ok(up) = hyper::upgrade::on(req).await {
            let mut client = TokioIo::new(up);
            let mut upstream = upstream;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
    });
    ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{build_client, Route};
    use crate::vault::{Cache, Resolve, DEFAULT_TTL};
    use http_body_util::Full;
    use kepr_core::binding::Inject;
    use kepr_core::generate::ZeroString;
    use kepr_core::secmem::SplitKey;
    use std::sync::Mutex;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const SID: &str = "0123456789abcdef";
    const KEY: [u8; 32] = [3u8; 32];

    /// The daemon's view: the gcloud key is bound to storage.googleapis.com
    /// only. Records every host it is asked about.
    struct Bound(Arc<Mutex<Vec<String>>>);
    impl Resolve for Bound {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, host: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            self.0.lock().unwrap().push(host.to_string());
            match host {
                "storage.googleapis.com" => Ok((ZeroString::from("REAL-TOKEN"), Inject::Bearer)),
                _ => Err("credential unavailable".into()),
            }
        }
    }

    async fn upstream() -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await;
            }
        });
        (base, rx)
    }

    async fn gate(base: String) -> (String, Arc<crate::ca::SessionCa>, Arc<Mutex<Vec<String>>>) {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let cache = Arc::new(Cache::new(Box::new(Bound(asked.clone())), DEFAULT_TTL));
        let ca = Arc::new(crate::ca::SessionCa::with_suffixes(&[], &["googleapis.com"]).unwrap());
        let routes = [(
            "gcloud".to_string(),
            Route {
                cred: "GCP_TOKEN".into(),
                slot: 0,
            },
        )]
        .into();
        let mut st = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache)
            .with_egress(Some(ca.clone()), false);
        st.client = build_client(true);
        st.base_override = Some(base);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(crate::proxy::serve(l, Arc::new(st)));
        (addr, ca, asked)
    }

    async fn connect(gate: &str, target: &str) -> (TcpStream, String) {
        let mut s = TcpStream::connect(gate).await.unwrap();
        let line = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        s.write_all(line.as_bytes()).await.unwrap();
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

    struct GitHub;
    impl Resolve for GitHub {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, host: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            assert_eq!(host, "github.com");
            Ok((ZeroString::from("REAL-GH-TOKEN"), Inject::BasicPassword))
        }
    }

    /// TLS through the gate to `host` with the session CA, as a tool would.
    async fn tls_to(
        gate: &str,
        ca: &crate::ca::SessionCa,
        host: &'static str,
    ) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
        let (stream, status) = connect(gate, &format!("{host}:443")).await;
        assert!(status.contains("200"), "{status}");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_der()).unwrap();
        let cfg =
            rustls::ClientConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(host.try_into().unwrap(), stream)
            .await
            .expect("TLS with the session CA");
        let (tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn);
        tx
    }

    #[tokio::test]
    async fn github_com_is_served_by_the_git_route() {
        use base64::Engine;
        let (base, mut rx) = upstream().await;
        let cache = Arc::new(Cache::new(Box::new(GitHub), DEFAULT_TTL));
        let ca =
            Arc::new(crate::ca::SessionCa::with_suffixes(&["github.com".into()], &[]).unwrap());
        let route = Route {
            cred: "GH".into(),
            slot: 0,
        };
        let routes = [("git".to_string(), route)].into();
        let mut st = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache)
            .with_egress(Some(ca.clone()), false);
        st.client = build_client(true);
        st.base_override = Some(base);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate = l.local_addr().unwrap().to_string();
        tokio::spawn(crate::proxy::serve(l, Arc::new(st)));

        let mut tx = tls_to(&gate, &ca, "github.com").await;
        let b64 = |s: String| base64::engine::general_purpose::STANDARD.encode(s);
        let ph = crate::placeholder::make(&KEY, SID, 0);
        let auth = format!("Basic {}", b64(format!("x-access-token:{ph}")));
        let get = |path: &str| {
            Request::get(path)
                .header("host", "github.com")
                .header("authorization", auth.as_str())
                .body(Full::new(Bytes::new()))
                .unwrap()
        };
        let r = tx.send_request(get("/settings/tokens")).await.unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let r = (tx.send_request(get("/o/r.git/info/refs?service=git-upload-pack")))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let seen = rx.recv().await.unwrap();
        assert!(
            seen.starts_with("GET /o/r.git/info/refs?service=git-upload-pack "),
            "{seen}"
        );
        let want = b64("x-access-token:REAL-GH-TOKEN".into());
        assert!(
            seen.contains(&format!("authorization: Basic {want}")),
            "{seen}"
        );
        assert!(rx.try_recv().is_err(), "/settings/tokens reached upstream");
    }

    #[tokio::test]
    async fn gcloud_bound_hosts_under_googleapis_are_intercepted() {
        let (base, mut rx) = upstream().await;
        let (gate, ca, asked) = gate(base).await;
        // Not bound for this host: the daemon refuses, nothing is intercepted.
        let (_s, status) = connect(&gate, "evil.googleapis.com:443").await;
        assert!(status.contains("403"), "{status}");
        let (_s, status) = connect(&gate, "evilgoogleapis.com:443").await;
        assert!(status.contains("403"), "{status}");
        let (_s, status) = connect(&gate, "storage.googleapis.com:8443").await;
        assert!(status.contains("403"), "{status}");
        let (stream, status) = connect(&gate, "storage.googleapis.com:443").await;
        assert!(status.contains("200"), "{status}");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_der()).unwrap();
        let cfg =
            rustls::ClientConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect("storage.googleapis.com".try_into().unwrap(), stream)
            .await
            .expect("TLS with the session CA");
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn);
        let ph = crate::placeholder::make(&KEY, SID, 0);
        let req = Request::get("/storage/v1/b?project=p")
            .header("host", "storage.googleapis.com")
            .header("authorization", format!("Bearer {ph}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(tx.send_request(req).await.unwrap().status(), StatusCode::OK);
        let seen = rx.recv().await.unwrap();
        assert!(seen.starts_with("GET /storage/v1/b?project=p "), "{seen}");
        assert!(seen.contains("authorization: Bearer REAL-TOKEN"), "{seen}");
        assert!(!seen.contains("kepr-ph-"));
        let asked = asked.lock().unwrap().clone();
        assert!(asked.iter().all(|h| h.ends_with(".googleapis.com")));
        assert!(asked.contains(&"evil.googleapis.com".to_string()));
        assert!(!asked.contains(&"evilgoogleapis.com".to_string()));
    }
}
