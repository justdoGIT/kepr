//! The forwarding proxy (T1.10): verify the placeholder, swap in the
//! real key, run the DLP check, forward over TLS, stream the answer.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use kepr_core::secmem::SplitKey;

use crate::dlp::{self, Verdict};
use crate::journal;
use crate::limits::{Limiter, Refusal, UsageMeter};
use crate::placeholder;
use crate::rewrite::{placeholders_in, strip_hop_by_hop, upstream_headers, upstream_query};
use crate::routes;
use crate::vault::Cache;

pub type Body = BoxBody<Bytes, hyper::Error>;
pub const MAX_BODY: usize = 8 * 1024 * 1024;

pub struct Route {
    pub cred: String,
    pub slot: u16,
}

pub struct State {
    pub session_id: String,
    pub session_key: SplitKey<32>,
    pub routes: HashMap<String, Route>,
    pub cache: Arc<Cache>,
    pub limiter: Arc<Limiter>,
    /// P2.1 egress proxy: the session CA and whether unbound hosts tunnel.
    pub ca: Option<Arc<crate::ca::SessionCa>>,
    pub tunnel: bool,
    pub(crate) client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    pub(crate) base_override: Option<String>,
}

pub(crate) fn build_client(
    allow_plain_http: bool,
) -> Client<HttpsConnector<HttpConnector>, Full<Bytes>> {
    // Compiled-in roots only: never trust CA files or proxies from the
    // environment, which the agent may control.
    let b = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(rustls::crypto::ring::default_provider())
        .expect("ring provider supports the default protocol versions");
    let b = if allow_plain_http {
        b.https_or_http()
    } else {
        b.https_only()
    };
    let conn = b.enable_http1().enable_http2().build();
    Client::builder(hyper_util::rt::TokioExecutor::new()).build(conn)
}

impl State {
    pub fn new(
        session_id: String,
        session_key: SplitKey<32>,
        routes: HashMap<String, Route>,
        cache: Arc<Cache>,
    ) -> Self {
        Self {
            session_id,
            session_key,
            routes,
            cache,
            limiter: Arc::new(Limiter::new(Default::default())),
            client: build_client(false),
            base_override: None,
            ca: None,
            tunnel: false,
        }
    }

    pub fn with_egress(mut self, ca: Arc<crate::ca::SessionCa>, tunnel: bool) -> Self {
        (self.ca, self.tunnel) = (Some(ca), tunnel);
        self
    }

    pub fn with_limits(mut self, limits: kepr_core::gate_protocol::GateLimits) -> Self {
        self.limiter = Arc::new(Limiter::new(limits));
        self
    }

    /// The gate re-checks what the daemon already validated.
    pub fn validated(self) -> Result<Self, String> {
        self.limiter.config().validate()?;
        Ok(self)
    }

    fn valid_placeholder(&self, s: &str, slot: u16) -> bool {
        match placeholder::parse(s) {
            Some(p) => {
                p.session_id == self.session_id
                    && p.slot == slot
                    && self.session_key.with_key(|k| placeholder::verify(k, &p))
            }
            None => false,
        }
    }
}

fn json(status: StatusCode, body: String) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from(body)).map_err(|n| match n {}).boxed());
    *r.status_mut() = status;
    r.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    r
}

pub fn kepr_error(status: StatusCode, kind: &str, message: &str) -> Response<Body> {
    let body = serde_json::json!({"type": "error", "error": {"type": kind, "message": message}});
    json(status, body.to_string())
}

/// A session cap is final (403, so harnesses don't retry); the rate
/// limit is a 429 with `Retry-After`.
fn limit_response(refusal: Refusal) -> Response<Body> {
    match refusal {
        Refusal::Cap(why) => kepr_error(
            StatusCode::FORBIDDEN,
            "kepr_limit",
            &format!("kepr stopped this request: {why}."),
        ),
        Refusal::Rate(secs) => {
            let mut r = kepr_error(
                StatusCode::TOO_MANY_REQUESTS,
                "kepr_limit",
                &format!("kepr rate limit for this session; retry in {secs}s."),
            );
            r.headers_mut()
                .insert("retry-after", HeaderValue::from(secs));
            r
        }
    }
}

struct Log<'a> {
    state: &'a State,
    provider: &'a str,
    method: &'a str,
    path: &'a str,
    start: Instant,
}

impl Log<'_> {
    fn emit(&self, status: StatusCode, bytes_out: usize, blocked: Option<&str>) {
        journal::emit(&journal::Entry {
            session: &self.state.session_id,
            provider: self.provider,
            method: self.method,
            path: self.path,
            status: status.as_u16(),
            bytes_out,
            ms: self.start.elapsed().as_millis(),
            blocked,
        });
    }

    fn reply(&self, r: Response<Body>, bytes_out: usize, blocked: Option<&str>) -> Response<Body> {
        self.emit(r.status(), bytes_out, blocked);
        r
    }
}

pub async fn handle(
    state: Arc<State>,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    if req.method() == hyper::Method::CONNECT {
        return Ok(crate::egress::connect(state, req).await);
    }
    let path = req.uri().path().to_string();
    if path == "/__kepr/health" {
        return Ok(json(StatusCode::OK, "\"ok\"".into()));
    }
    let Some((pname, rest)) = routes::split_path(&path) else {
        return Ok(kepr_error(
            StatusCode::NOT_FOUND,
            "kepr",
            "unknown kepr route",
        ));
    };
    let (pname, rest) = (pname.to_string(), rest.to_string());
    proxy_request(state, &pname, &rest, req).await
}

/// Everything after routing, shared by base-URL requests and requests
/// arriving through the egress proxy: placeholder check, limits, key
/// resolve, DLP, forward over TLS, stream back (metering tokens).
pub async fn proxy_request(
    state: Arc<State>,
    pname: &str,
    rest: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let not_found = || kepr_error(StatusCode::NOT_FOUND, "kepr", "unknown kepr route");
    let (Some(provider), Some(route)) = (routes::lookup(pname), state.routes.get(pname)) else {
        return Ok(not_found());
    };
    let method = req.method().to_string();
    let log = Log {
        state: &state,
        provider: pname,
        method: &method,
        path: rest,
        start: Instant::now(),
    };
    let query = req.uri().query().map(str::to_string);

    let phs = placeholders_in(req.headers(), query.as_deref());
    if phs.is_empty() || !phs.iter().all(|p| state.valid_placeholder(p, route.slot)) {
        let r = kepr_error(
            StatusCode::UNAUTHORIZED,
            "kepr",
            "invalid or missing kepr placeholder",
        );
        return Ok(log.reply(r, 0, None));
    }

    if let Err(refusal) = state.limiter.admit(Instant::now()) {
        return Ok(log.reply(limit_response(refusal), 0, Some("limit")));
    }

    let (cache, cred, host) = (state.cache.clone(), route.cred.clone(), provider.host);
    let (value, inject) =
        match tokio::task::spawn_blocking(move || cache.get(&cred, host, 443)).await {
            Ok(Ok(v)) => v,
            _ => {
                let r = kepr_error(
                    StatusCode::BAD_GATEWAY,
                    "kepr",
                    "kepr could not obtain the credential",
                );
                return Ok(log.reply(r, 0, None));
            }
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

    let blocked_msg = match dlp::scan(&bytes, &state.cache.values()) {
        Verdict::Clean => None,
        Verdict::StoredSecret(n) => Some(format!(
            "kepr blocked this request: it contains the stored secret {n}. Remove it and retry."
        )),
        Verdict::LooksLikeKey => Some(
            "kepr blocked this request: it contains what looks like an API key. Remove it and retry."
                .to_string(),
        ),
    };
    if let Some(msg) = blocked_msg {
        let r = kepr_error(StatusCode::FORBIDDEN, "kepr_blocked", &msg);
        return Ok(log.reply(r, bytes.len(), Some("dlp")));
    }

    let base = state
        .base_override
        .clone()
        .unwrap_or_else(|| format!("https://{host}"));
    let q = upstream_query(query.as_deref(), &inject, value.as_str())
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let built = format!("{base}{rest}{q}")
        .parse::<Uri>()
        .map_err(|_| ())
        .and_then(|uri| {
            let headers =
                upstream_headers(&parts.headers, &inject, value.as_str()).map_err(|_| ())?;
            let mut up = Request::builder()
                .method(parts.method.clone())
                .uri(uri)
                .body(Full::new(bytes.clone()))
                .map_err(|_| ())?;
            *up.headers_mut() = headers;
            Ok(up)
        });
    drop(value);
    let Ok(up) = built else {
        let r = kepr_error(
            StatusCode::BAD_REQUEST,
            "kepr",
            "kepr could not build the upstream request",
        );
        return Ok(log.reply(r, bytes.len(), None));
    };

    match state.client.request(up).await {
        Ok(resp) => {
            let (mut p, b) = resp.into_parts();
            strip_hop_by_hop(&mut p.headers);
            log.emit(p.status, bytes.len(), None);
            if !state.limiter.meters_tokens() {
                return Ok(Response::from_parts(p, b.boxed()));
            }
            let mut meter = UsageMeter::new(state.limiter.clone());
            let b = b.map_frame(move |f| {
                if let Some(d) = f.data_ref() {
                    meter.observe(d);
                }
                f
            });
            Ok(Response::from_parts(p, b.boxed()))
        }
        Err(_) => {
            let r = kepr_error(StatusCode::BAD_GATEWAY, "kepr", "upstream request failed");
            Ok(log.reply(r, bytes.len(), None))
        }
    }
}

/// Accept loop shared by `main` and the tests.
pub async fn serve(listener: tokio::net::TcpListener, state: Arc<State>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let st = state.clone();
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            let svc = hyper::service::service_fn(move |req| handle(st.clone(), req));
            // with_upgrades: CONNECT (egress proxy) takes over the socket.
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderMap, AUTHORIZATION};
    use kepr_core::binding::Inject;

    impl State {
        /// Send upstream traffic to a plain-HTTP base URL.
        fn with_test_upstream(mut self, base: String) -> Self {
            self.client = build_client(true);
            self.base_override = Some(base);
            self
        }
    }
    use crate::vault::{Resolve, DEFAULT_TTL};
    use hyper_util::client::legacy::Client as PlainClient;
    use kepr_core::generate::ZeroString;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    const SID: &str = "0123456789abcdef";
    const KEY: [u8; 32] = [9u8; 32];
    const REAL: &str = "real-key-1234567890";

    struct Fixed;
    impl Resolve for Fixed {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            Ok((
                ZeroString::from_string(REAL.into()),
                Inject::Header {
                    name: "x-api-key".into(),
                },
            ))
        }
    }

    /// Raw HTTP/1.1 upstream: reports each request it receives and
    /// answers with two chunks 500 ms apart.
    async fn fake_upstream() -> (String, mpsc::UnboundedReceiver<String>) {
        fake_upstream_with(None).await
    }

    /// `reply`: a fixed full response instead of the slow chunked one.
    async fn fake_upstream_with(
        reply: Option<&'static [u8]>,
    ) -> (String, mpsc::UnboundedReceiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = s.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).to_string();
                        if let Some(h) = text.find("\r\n\r\n") {
                            let len = text[..h]
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            if buf.len() >= h + 4 + len {
                                break;
                            }
                        }
                    }
                    let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
                    if let Some(r) = reply {
                        let _ = s.write_all(r).await;
                        return;
                    }
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nkeep-alive: timeout=5\r\n\r\n5\r\nfirst\r\n").await;
                    let _ = s.flush().await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let _ = s.write_all(b"6\r\nsecond\r\n0\r\n\r\n").await;
                });
            }
        });
        (base, rx)
    }

    async fn start_gate(upstream: String) -> String {
        start_gate_with(upstream, Default::default()).await
    }

    async fn start_gate_with(
        upstream: String,
        limits: kepr_core::gate_protocol::GateLimits,
    ) -> String {
        let cache = Arc::new(Cache::new(Box::new(Fixed), DEFAULT_TTL));
        let mut routes = HashMap::new();
        routes.insert(
            "anthropic".to_string(),
            Route {
                cred: "ANTHROPIC_API_KEY".into(),
                slot: 0,
            },
        );
        let state = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache)
            .with_test_upstream(upstream)
            .with_limits(limits);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(serve(l, Arc::new(state)));
        addr
    }

    async fn send(gate: &str, ph: &str, body: &str) -> Response<Incoming> {
        let client: PlainClient<HttpConnector, Full<Bytes>> =
            PlainClient::builder(hyper_util::rt::TokioExecutor::new()).build_http();
        let req = Request::post(format!("{gate}/anthropic/v1/messages?beta=true"))
            .header("x-api-key", ph)
            .header("proxy-authorization", "Basic abc")
            .header("anthropic-version", "2023-06-01")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        client.request(req).await.unwrap()
    }

    #[tokio::test]
    async fn swaps_placeholder_and_streams() {
        let (up, mut rx) = fake_upstream().await;
        let gate = start_gate(up).await;
        let ph = placeholder::make(&KEY, SID, 0);
        let resp = send(&gate, &ph, r#"{"model":"x"}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("keep-alive").is_none());
        let seen = rx.recv().await.unwrap().to_ascii_lowercase();
        assert!(seen.contains(&format!("x-api-key: {REAL}")), "{seen}");
        assert!(!seen.contains("kepr-ph-"));
        assert!(!seen.contains("proxy-authorization"));
        assert!(seen.contains("anthropic-version: 2023-06-01"));
        assert!(seen.starts_with("post /v1/messages?beta=true "), "{seen}");

        let start = Instant::now();
        let mut body = resp.into_body();
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(&first[..], b"first");
        assert!(
            start.elapsed() < Duration::from_millis(400),
            "first chunk was buffered"
        );
        let rest = body.collect().await.unwrap().to_bytes();
        assert_eq!(&rest[..], b"second");
    }

    #[tokio::test]
    async fn request_cap_stops_the_session_without_contacting_upstream() {
        let (up, mut rx) =
            fake_upstream_with(Some(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")).await;
        let limits = kepr_core::gate_protocol::GateLimits {
            max_requests: Some(1),
            ..Default::default()
        };
        let gate = start_gate_with(up, limits).await;
        let ph = placeholder::make(&KEY, SID, 0);
        assert_eq!(send(&gate, &ph, "{}").await.status(), StatusCode::OK);
        rx.recv().await.unwrap();
        let r = send(&gate, &ph, "{}").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let body =
            String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(
            body.contains("kepr_limit") && body.contains("limit of 1 requests"),
            "{body}"
        );
        assert!(tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn token_cap_counts_usage_from_responses() {
        let (up, _rx) = fake_upstream_with(Some(
            b"HTTP/1.1 200 OK\r\ncontent-length: 48\r\n\r\n{\"usage\":{\"input_tokens\":30,\"output_tokens\":20}}",
        ))
        .await;
        let limits = kepr_core::gate_protocol::GateLimits {
            max_tokens: Some(50),
            ..Default::default()
        };
        let gate = start_gate_with(up, limits).await;
        let ph = placeholder::make(&KEY, SID, 0);
        let r = send(&gate, &ph, "{}").await;
        assert_eq!(r.status(), StatusCode::OK);
        r.into_body().collect().await.unwrap(); // the meter sees the body
        assert_eq!(send(&gate, &ph, "{}").await.status(), StatusCode::FORBIDDEN);
    }

    async fn start_egress_gate(
        upstream: String,
        tunnel: bool,
    ) -> (String, Arc<crate::ca::SessionCa>) {
        let ca = Arc::new(crate::ca::SessionCa::new(&["api.anthropic.com".into()]).unwrap());
        let cache = Arc::new(Cache::new(Box::new(Fixed), DEFAULT_TTL));
        let mut routes = HashMap::new();
        routes.insert(
            "anthropic".to_string(),
            Route {
                cred: "ANTHROPIC_API_KEY".into(),
                slot: 0,
            },
        );
        let state = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache)
            .with_test_upstream(upstream)
            .with_egress(ca.clone(), tunnel);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(serve(l, Arc::new(state)));
        (addr, ca)
    }

    /// Send CONNECT and return the stream plus the status line.
    async fn connect_to(gate: &str, target: &str) -> (tokio::net::TcpStream, String) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(gate).await.unwrap();
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

    #[tokio::test]
    async fn egress_intercepts_bound_host_and_swaps_the_placeholder() {
        let (up, mut rx) =
            fake_upstream_with(Some(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")).await;
        let (gate, ca) = start_egress_gate(up, false).await;
        let (stream, status) = connect_to(&gate, "api.anthropic.com:443").await;
        assert!(status.contains("200"), "{status}");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_der()).unwrap();
        let tls_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg))
            .connect("api.anthropic.com".try_into().unwrap(), stream)
            .await
            .expect("TLS with the session CA");
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(conn);
        let ph = placeholder::make(&KEY, SID, 0);
        let req = Request::post("/v1/messages")
            .header("host", "api.anthropic.com")
            .header("x-api-key", ph.as_str())
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let seen = rx.recv().await.unwrap();
        assert!(seen.contains(REAL), "upstream got the real key");
        assert!(
            !seen.contains("kepr-ph-"),
            "placeholder must not reach upstream"
        );
    }

    #[tokio::test]
    async fn egress_refuses_unbound_hosts_without_tunnel() {
        let (up, _rx) = fake_upstream().await;
        let (gate, _) = start_egress_gate(up, false).await;
        let (_s, status) = connect_to(&gate, "example.com:443").await;
        assert!(status.contains("403"), "{status}");
        // A bound name on another port is not intercepted either.
        let (_s, status) = connect_to(&gate, "api.anthropic.com:8443").await;
        assert!(status.contains("403"), "{status}");
    }

    #[tokio::test]
    async fn rejects_bad_placeholders_without_contacting_upstream() {
        let (up, mut rx) = fake_upstream().await;
        let gate = start_gate(up).await;
        let other_key = placeholder::make(&[1u8; 32], SID, 0);
        let wrong_slot = placeholder::make(&KEY, SID, 1);
        for ph in [other_key.as_str(), wrong_slot.as_str(), "sk-ant-real"] {
            assert_eq!(
                send(&gate, ph, "{}").await.status(),
                StatusCode::UNAUTHORIZED,
                "{ph}"
            );
        }
        assert!(tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn dlp_blocks_stored_secret_and_names_it() {
        let (up, mut rx) = fake_upstream().await;
        let gate = start_gate(up).await;
        let ph = placeholder::make(&KEY, SID, 0);
        let resp = send(&gate, &ph, &format!(r#"{{"content":"{REAL}"}}"#)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("ANTHROPIC_API_KEY") && text.contains("kepr_blocked"),
            "{text}"
        );
        assert!(!text.contains(REAL));
        assert!(tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .is_err());
        let resp = send(&gate, &ph, r#"{"c":"AKIAABCDEFGHIJKLMNOP"}"#).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn query_and_placeholder_helpers() {
        let ph = placeholder::make(&KEY, SID, 0);
        let q = format!("a=1&key={ph}");
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {ph}")).unwrap(),
        );
        assert_eq!(placeholders_in(&h, Some(&q)).len(), 2);
        let mut lower = HeaderMap::new();
        lower.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("bearer {ph}")).unwrap(),
        );
        assert_eq!(placeholders_in(&lower, None), vec![ph.clone()]);
        let inject = Inject::Query {
            param: "key".into(),
        };
        assert_eq!(
            upstream_query(Some(&q), &inject, "a b").as_deref(),
            Some("a=1&key=a%20b")
        );
        assert_eq!(
            upstream_query(Some(&format!("key={ph}")), &Inject::Bearer, "v"),
            None
        );
        let out = upstream_headers(&h, &Inject::Bearer, "v").unwrap();
        assert_eq!(out.get(AUTHORIZATION).unwrap(), "Bearer v");
    }
}
