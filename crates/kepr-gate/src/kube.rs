//! Kubernetes API servers through the egress proxy (T13.04).
//!
//! `kepr agent add-kube` seals a `kube` record (server, bearer token, the
//! cluster's CA) bound to the API server's DNS name and port. In a session
//! the harness gets a `KUBECONFIG` whose server is that URL, whose token is
//! the session placeholder and whose CA is the session CA; `kubectl` reaches
//! the gate as a proxy (`CONNECT host:port`), which accepts TLS with a
//! session-CA leaf for the host. Per request: the placeholder must be
//! valid, limits and DLP apply, and the real token goes upstream as
//! `Authorization: Bearer`, over TLS verified against the cluster's own CA
//! (or the public roots when the record has none). Nothing but a request to
//! this exact host and port ever carries the token.
//!
//! Not served: `Upgrade` requests (`kubectl exec`, `attach`, `port-forward`
//! speak SPDY or WebSocket); they get a plain 501 saying so.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use kepr_core::binding::Inject;
use kepr_core::gate_protocol::{GateRoute, TargetKind};

use crate::forward;
use crate::journal::Log;
use crate::proxy::{kepr_error, Body, State, MAX_BODY};

pub type KubeClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Upstream clients by route key, with a digest of the CA they trust.
pub type Clients = Mutex<HashMap<String, (u64, KubeClient)>>;

/// One API server of the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeTarget {
    pub host: String,
    pub port: u16,
    /// The route key (`kube:<CRED>`).
    pub key: String,
}

impl State {
    /// Remember the session's Kubernetes API servers for the egress proxy.
    pub fn with_kube(mut self, routes: &[GateRoute]) -> Self {
        self.kube = routes
            .iter()
            .filter_map(|r| Some((r, r.target.as_ref().filter(|t| t.kind == TargetKind::Kube)?)))
            .map(|(r, t)| KubeTarget {
                host: t.host.to_ascii_lowercase(),
                port: t.port,
                key: r.provider.clone(),
            })
            .collect();
        self
    }
}

/// Is this route a Kubernetes API server (rather than a database)?
pub fn is_kube(r: &GateRoute) -> bool {
    r.target
        .as_ref()
        .is_some_and(|t| t.kind == TargetKind::Kube)
}

/// The API server hosts of a session's routes (for the session CA).
pub fn hosts(routes: &[GateRoute]) -> Vec<String> {
    routes
        .iter()
        .filter_map(|r| r.target.as_ref().filter(|t| t.kind == TargetKind::Kube))
        .map(|t| t.host.to_ascii_lowercase())
        .collect()
}

/// The route key of the API server at `host:port`, when this session has
/// one and the session CA may sign for the name.
pub fn bound(state: &State, host: &str, port: u16) -> Option<String> {
    let covered = state.ca.as_ref().is_some_and(|c| c.covers(host));
    state
        .kube
        .iter()
        .find(|t| covered && t.port == port && t.host.eq_ignore_ascii_case(host))
        .map(|t| t.key.clone())
}

/// What the sealed `kube` record holds that the gate needs.
#[derive(serde::Deserialize)]
struct Record {
    token: kepr_core::generate::ZeroString,
    #[serde(default)]
    ca_pem: String,
}

/// DER certificates in a PEM string.
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

/// A client trusting `ca_pem` alone, or the public roots when it is empty.
/// Never the environment's CA files: the agent may control those.
pub(crate) fn build_client(ca_pem: &str) -> Result<KubeClient, String> {
    let mut roots = rustls::RootCertStore::empty();
    let certs = pem_certs(ca_pem);
    if certs.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    for der in certs {
        roots
            .add(der)
            .map_err(|_| "the cluster CA is not a valid certificate")?;
    }
    let cfg =
        rustls::ClientConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let conn = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(cfg)
        .https_only()
        .enable_http1()
        .build();
    Ok(Client::builder(hyper_util::rt::TokioExecutor::new()).build(conn))
}

fn digest(s: &str) -> u64 {
    // Only to notice that the record's CA changed; not a security value.
    s.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

fn client_for(state: &State, key: &str, ca_pem: &str) -> Result<KubeClient, String> {
    let want = digest(ca_pem);
    let mut map = state.kube_clients.lock().map_err(|_| "kube client lock")?;
    if let Some((d, c)) = map.get(key).filter(|(d, _)| *d == want) {
        let _ = d;
        return Ok(c.clone());
    }
    let c = build_client(ca_pem)?;
    map.insert(key.to_string(), (want, c.clone()));
    Ok(c)
}

fn is_upgrade(req: &Request<Incoming>) -> bool {
    req.headers().contains_key(hyper::header::UPGRADE)
        || req
            .headers()
            .get_all(hyper::header::CONNECTION)
            .iter()
            .any(|v| {
                v.to_str()
                    .is_ok_and(|s| s.to_ascii_lowercase().contains("upgrade"))
            })
}

/// Serve one decrypted request to the API server `(host, port)`.
pub async fn handle(
    state: Arc<State>,
    (key, host, port): (String, String, u16),
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let Some(route) = state.routes.get(&key) else {
        return Ok(kepr_error(
            StatusCode::NOT_FOUND,
            "kepr",
            "unknown kepr route",
        ));
    };
    let (method, path) = (req.method().to_string(), req.uri().path().to_string());
    let target = format!("{host}:{port}");
    let log = Log {
        state: &state,
        provider: &key,
        host: &target,
        method: &method,
        path: &path,
        start: Instant::now(),
    };
    if is_upgrade(&req) {
        let msg = "kubectl exec, attach and port-forward are not supported through kepr yet";
        let r = kepr_error(StatusCode::NOT_IMPLEMENTED, "kepr", msg);
        return Ok(log.reply(r, 0, Some("upgrade")));
    }
    let (value, inject) =
        match forward::admit_at(&log, route, req.headers(), req.uri().query(), (&host, port)).await
        {
            Ok(v) => v,
            Err(r) => return Ok(*r),
        };
    let rec: Result<Record, _> = match inject {
        Inject::KubeToken => serde_json::from_str(value.as_str()),
        _ => Err(serde::de::Error::custom("not a kube record")),
    };
    drop(value);
    let Ok(rec) = rec else {
        let msg = "kepr could not read the cluster login";
        return Ok(log.reply(kepr_error(StatusCode::BAD_GATEWAY, "kepr", msg), 0, None));
    };

    let (parts, body) = req.into_parts();
    let bytes = match Limited::new(body, MAX_BODY).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            let r = kepr_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "kepr",
                "request body too large for kepr",
            );
            return Ok(log.reply(r, 0, None));
        }
    };
    if let Some((r, why)) =
        crate::canary::screen(&state.cache, &parts.headers, None, Some(&bytes)).await
    {
        return Ok(log.reply(r, bytes.len(), Some(why)));
    }
    if let Some(msg) = crate::dlp::check(&parts, &bytes, &state.cache.values()) {
        let r = kepr_error(StatusCode::FORBIDDEN, "kepr_blocked", &msg);
        return Ok(log.reply(r, bytes.len(), Some("dlp")));
    }
    let client = match client_for(&state, &key, &rec.ca_pem) {
        Ok(c) => c,
        Err(_) => {
            let msg = "kepr could not trust the cluster CA";
            return Ok(log.reply(kepr_error(StatusCode::BAD_GATEWAY, "kepr", msg), 0, None));
        }
    };
    let own = crate::mask::forms(rec.token.as_str());
    let built = forward::upstream_request(
        &log,
        &parts,
        &Inject::Bearer,
        rec.token.as_str(),
        Full::new(bytes.clone()),
    );
    drop(rec);
    let Some(up) = built else {
        return Ok(log.reply(forward::cannot_build(), bytes.len(), None));
    };
    match client.request(up).await {
        Ok(resp) => {
            let (p, b) = forward::for_agent(&state, resp, &Inject::Bearer, own);
            log.emit(p.status, bytes.len(), None);
            Ok(Response::from_parts(p, b))
        }
        Err(_) => Ok(log.reply(forward::upstream_failed(), bytes.len(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{Route, State};
    use crate::vault::{Cache, Resolve, DEFAULT_TTL};
    use hyper_util::rt::TokioIo;
    use kepr_core::generate::ZeroString;
    use kepr_core::secmem::SplitKey;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const SID: &str = "0123456789abcdef";
    const KEY: [u8; 32] = [5u8; 32];
    const TOKEN: &str = "real-cluster-token";

    /// The daemon's view: the kube record for the one bound host:port.
    struct Daemon {
        port: u16,
        record: String,
    }
    impl Resolve for Daemon {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(
            &self,
            name: &str,
            host: &str,
            port: u16,
        ) -> Result<(ZeroString, Inject), String> {
            if name == "K8S" && host == "localhost" && port == self.port {
                Ok((ZeroString::from(self.record.as_str()), Inject::KubeToken))
            } else {
                Err("credential unavailable".into())
            }
        }
    }

    /// A TLS API server on loopback whose certificate only `ca_pem` trusts.
    /// Records `(method path, authorization)` of each request.
    async fn api_server() -> (
        u16,
        String,
        tokio::sync::mpsc::UnboundedReceiver<(String, String)>,
    ) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap();
        let cfg =
            rustls::ServerConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key)
                .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(s).await else {
                        return;
                    };
                    let svc = hyper::service::service_fn(move |r: Request<Incoming>| {
                        let auth = r
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let _ = tx.send((format!("{} {}", r.method(), r.uri().path()), auth));
                        // The server echoes the token it was given in its body.
                        let body = format!("{{\"kind\":\"PodList\",\"seen\":\"{TOKEN}\"}}");
                        async move { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body)))) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        (port, cert.pem(), rx)
    }

    struct Gate {
        addr: String,
        ca: Arc<crate::ca::SessionCa>,
    }

    async fn gate(api_port: u16, ca_pem: &str) -> Gate {
        let record = serde_json::json!({"server": format!("https://localhost:{api_port}"), "token": TOKEN, "ca_pem": ca_pem}).to_string();
        let cache = Arc::new(Cache::new(
            Box::new(Daemon {
                port: api_port,
                record,
            }),
            DEFAULT_TTL,
        ));
        let ca = Arc::new(crate::ca::SessionCa::new(&["localhost".into()]).unwrap());
        let routes: HashMap<String, Route> = [(
            "kube:K8S".to_string(),
            Route {
                cred: "K8S".into(),
                slot: 0,
            },
        )]
        .into();
        let gate_route = GateRoute {
            provider: "kube:K8S".into(),
            cred: "K8S".into(),
            slot: 0,
            target: Some(kepr_core::gate_protocol::DbTarget {
                host: "localhost".into(),
                port: api_port,
                kind: TargetKind::Kube,
                ..Default::default()
            }),
        };
        let st = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache)
            .with_egress(Some(ca.clone()), false)
            .with_kube(&[gate_route]);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(crate::proxy::serve(l, Arc::new(st)));
        Gate { addr, ca }
    }

    async fn connect(gate: &str, target: &str) -> (TcpStream, String) {
        let mut s = TcpStream::connect(gate).await.unwrap();
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
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

    /// kubectl's view: TLS to `localhost:port` through the gate, trusting the session CA.
    async fn kubectl(g: &Gate, port: u16) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
        let (stream, status) = connect(&g.addr, &format!("localhost:{port}")).await;
        assert!(status.contains("200"), "{status}");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(g.ca.ca_der()).unwrap();
        let cfg =
            rustls::ClientConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect("localhost".try_into().unwrap(), stream)
            .await
            .expect("TLS with the session CA");
        let (tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn);
        tx
    }

    fn get(path: &str, token: &str) -> Request<Full<Bytes>> {
        Request::get(path)
            .header("host", "localhost")
            .header("authorization", format!("Bearer {token}"))
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    async fn body(r: Response<Incoming>) -> String {
        String::from_utf8_lossy(&r.into_body().collect().await.unwrap().to_bytes()).into_owned()
    }

    #[tokio::test]
    async fn kubectl_requests_carry_the_real_token_and_never_the_placeholder() {
        let (port, ca_pem, mut seen) = api_server().await;
        let g = gate(port, &ca_pem).await;
        let mut tx = kubectl(&g, port).await;
        let ph = crate::placeholder::make(&KEY, SID, 0);
        let r = tx
            .send_request(get("/api/v1/namespaces/default/pods", &ph))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        // The server echoed the token in its reply; the agent sees it masked.
        let text = body(r).await;
        assert!(text.contains("PodList"), "{text}");
        assert!(!text.contains(TOKEN), "the token reached the agent: {text}");
        let (line, auth) = seen.recv().await.unwrap();
        assert_eq!(line, "GET /api/v1/namespaces/default/pods");
        assert_eq!(auth, format!("Bearer {TOKEN}"));
        assert!(!auth.contains("kepr-ph-"));
    }

    #[tokio::test]
    async fn a_wrong_or_missing_placeholder_never_reaches_the_cluster() {
        let (port, ca_pem, mut seen) = api_server().await;
        let g = gate(port, &ca_pem).await;
        let mut tx = kubectl(&g, port).await;
        let r = tx
            .send_request(get("/api/v1/pods", "not-a-placeholder"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let bare = Request::get("/api/v1/pods")
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(
            tx.send_request(bare).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        // Another session's placeholder (other slot) is no better.
        let other = crate::placeholder::make(&KEY, SID, 3);
        assert_eq!(
            tx.send_request(get("/api/v1/pods", &other))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(seen.try_recv().is_err(), "nothing reached the cluster");
    }

    #[tokio::test]
    async fn only_the_bound_host_and_port_are_intercepted() {
        let (port, ca_pem, _seen) = api_server().await;
        let g = gate(port, &ca_pem).await;
        // Same name, another port; another name: refused (no tunnelling here).
        let (_s, status) = connect(&g.addr, &format!("localhost:{}", port.wrapping_add(1))).await;
        assert!(status.contains("403"), "{status}");
        let (_s, status) = connect(&g.addr, &format!("evil.example.com:{port}")).await;
        assert!(status.contains("403"), "{status}");
    }

    #[tokio::test]
    async fn the_cluster_must_present_a_certificate_its_own_ca_vouches_for() {
        let (port, _right_ca, mut seen) = api_server().await;
        // The record carries a CA that did not sign the server's certificate.
        let rcgen::CertifiedKey { cert: other, .. } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let g = gate(port, &other.pem()).await;
        let mut tx = kubectl(&g, port).await;
        let ph = crate::placeholder::make(&KEY, SID, 0);
        let r = tx.send_request(get("/api/v1/pods", &ph)).await.unwrap();
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
        assert!(
            seen.try_recv().is_err(),
            "the token was not sent to an unverified server"
        );
    }

    #[tokio::test]
    async fn exec_and_port_forward_are_refused_plainly() {
        let (port, ca_pem, mut seen) = api_server().await;
        let g = gate(port, &ca_pem).await;
        let mut tx = kubectl(&g, port).await;
        let ph = crate::placeholder::make(&KEY, SID, 0);
        let req = Request::post("/api/v1/namespaces/d/pods/p/exec?command=sh")
            .header("host", "localhost")
            .header("authorization", format!("Bearer {ph}"))
            .header("connection", "Upgrade")
            .header("upgrade", "SPDY/3.1")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let r = tx.send_request(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_IMPLEMENTED);
        assert!(body(r).await.contains("not supported"));
        assert!(seen.try_recv().is_err());
    }

    #[test]
    fn targets_come_from_the_routes() {
        let r = |kind, host: &str| GateRoute {
            provider: "kube:K".into(),
            cred: "K".into(),
            slot: 0,
            target: Some(kepr_core::gate_protocol::DbTarget {
                host: host.into(),
                port: 6443,
                kind,
                ..Default::default()
            }),
        };
        let routes = [
            r(TargetKind::Kube, "API.Cluster.Example.com"),
            r(TargetKind::Postgres, "db.example.com"),
        ];
        assert_eq!(hosts(&routes), ["api.cluster.example.com"]);
    }
}
