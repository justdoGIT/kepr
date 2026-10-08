//! The forwarding proxy (T1.10): verify the placeholder, swap in the
//! real key, run the DLP check, forward over TLS, stream the answer.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use kepr_core::secmem::SplitKey;

use crate::dlp;
use crate::journal::Log;
use crate::limits::{reports_usage, Limiter, UsageMeter};
use crate::placeholder;
use crate::rewrite::{placeholders_in, upstream_headers, upstream_query};
use crate::routes;
use crate::vault::Cache;

pub(crate) use crate::reply::{json, kepr_error, limit_response};

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
    /// T7.03: host:port of the session's raw tunnels (tunnel.rs).
    pub tunnels: Vec<(String, u16)>,
    /// T7.09: what the agent sends and receives (`--record`).
    pub recorder: Arc<crate::recording::Recorder>,
    /// T11.22: request journal entries on their way to the daemon.
    pub journal: Arc<crate::journal::Queue>,
    pub(crate) client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    pub(crate) base_override: Option<String>,
}

pub(crate) fn build_client(
    allow_plain_http: bool,
) -> Client<HttpsConnector<HttpConnector>, Full<Bytes>> {
    // Compiled-in roots only: never trust CA files or proxies from the
    // environment, which the agent may control.
    let b = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(crate::tls_provider::provider())
        .expect("the TLS provider supports the default protocol versions");
    let b = if allow_plain_http {
        b.https_or_http()
    } else {
        b.https_only()
    };
    // HTTP/1.1 only: every provider serves it, and h2 would add ~400 KB.
    let conn = b.enable_http1().build();
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
            tunnels: Vec::new(),
            recorder: Arc::new(crate::recording::Recorder::new(false)),
            journal: Arc::default(),
        }
    }

    pub fn with_egress(mut self, ca: Option<Arc<crate::ca::SessionCa>>, tunnel: bool) -> Self {
        (self.ca, self.tunnel) = (ca, tunnel);
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

    pub(crate) fn valid_placeholder(&self, s: &str, slot: u16) -> bool {
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
    proxy_request_to(state, pname, None, rest, req).await
}

/// `proxy_request` toward `host` instead of the provider's own host
/// (T2.04: a bound host under a provider domain, e.g. gcloud's).
pub async fn proxy_request_to(
    state: Arc<State>,
    pname: &str,
    host: Option<String>,
    rest: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let not_found = || kepr_error(StatusCode::NOT_FOUND, "kepr", "unknown kepr route");
    let (Some(provider), Some(route)) = (routes::lookup(pname), state.routes.get(pname)) else {
        return Ok(not_found());
    };
    let host = host.unwrap_or_else(|| provider.host.to_string());
    let method = req.method().to_string();
    let log = Log {
        state: &state,
        provider: pname,
        host: &host,
        method: &method,
        path: rest,
        start: Instant::now(),
    };
    let query = req.uri().query().map(str::to_string);
    let head = crate::canary::screen(&state.cache, req.headers(), query.as_deref(), None);
    if let Some(r) = head.await {
        return Ok(log.reply(r, 0, Some("canary"))); // T9.08
    }

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
    let today = state
        .limiter
        .admit_today(state.cache.clone(), route.cred.clone());
    if let Err(refusal) = today.await {
        return Ok(log.reply(limit_response(refusal), 0, Some("limit"))); // T9.06
    }

    let (cache, cred, h) = (state.cache.clone(), route.cred.clone(), host.clone());
    let (value, inject) = match tokio::task::spawn_blocking(move || cache.get(&cred, &h, 443)).await
    {
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
    // T7.08: a GitHub App key becomes an installation token here.
    let Ok((value, inject)) = crate::github_app::swap(&state, value, inject).await else {
        let r = kepr_error(
            StatusCode::BAD_GATEWAY,
            "kepr",
            "kepr could not obtain a token",
        );
        return Ok(log.reply(r, 0, None));
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

    let body = crate::canary::screen(&state.cache, &parts.headers, None, Some(&bytes));
    if let Some(r) = body.await {
        return Ok(log.reply(r, bytes.len(), Some("canary")));
    }
    if let Some(msg) = dlp::check(&parts, &bytes, &state.cache.values()) {
        let r = kepr_error(StatusCode::FORBIDDEN, "kepr_blocked", &msg);
        return Ok(log.reply(r, bytes.len(), Some("dlp")));
    }

    let conn = state.recorder.http_request(pname, &method, rest, &bytes);
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
            crate::rewrite::clean_response(&mut p.headers, &inject);
            let line = log.line(p.status, bytes.len(), None);
            let status = p.status.as_u16();
            let b = (state.recorder).http_response(conn, pname, status, b.boxed(), &state.cache);
            if !state.limiter.meters_tokens() && !reports_usage(&p.headers) {
                crate::journal::push(&state.journal, line);
                return Ok(Response::from_parts(p, b));
            }
            let mut meter = UsageMeter::new(state.limiter.clone())
                .daily(&state.cache, &route.cred)
                .journal(state.journal.clone(), line); // T9.07
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
    use hyper::header::{HeaderMap, HeaderValue, AUTHORIZATION};
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
        start_gate_full(
            upstream,
            limits,
            Arc::new(crate::recording::Recorder::new(false)),
        )
        .await
    }

    async fn start_gate_full(
        upstream: String,
        limits: kepr_core::gate_protocol::GateLimits,
        recorder: Arc<crate::recording::Recorder>,
    ) -> String {
        start_gate_journal(upstream, limits, recorder, Arc::default()).await
    }

    async fn start_gate_journal(
        upstream: String,
        limits: kepr_core::gate_protocol::GateLimits,
        recorder: Arc<crate::recording::Recorder>,
        journal: Arc<crate::journal::Queue>,
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
        let mut state = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache)
            .with_test_upstream(upstream)
            .with_limits(limits)
            .with_recorder(recorder);
        state.journal = journal;
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
    async fn recording_keeps_what_the_agent_sent_and_received_never_the_key() {
        let (up, mut rx) = fake_upstream().await;
        let rec = Arc::new(crate::recording::Recorder::new(true));
        let gate = start_gate_full(up, Default::default(), rec.clone()).await;
        let ph = placeholder::make(&KEY, SID, 0);
        let body = format!(r#"{{"model":"x","note":"{ph}"}}"#);
        let resp = send(&gate, &ph, &body).await;
        let got = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&got[..], b"firstsecond");
        assert!(
            rx.recv().await.unwrap().contains(REAL),
            "upstream got the key"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let chunks: Vec<_> = rec.take().into_iter().flat_map(|b| b.chunks).collect();
        let side = |dir: &str| {
            let b: Vec<u8> = chunks
                .iter()
                .filter(|c| c.dir == dir)
                .flat_map(|c| c.bytes())
                .collect();
            String::from_utf8(b).unwrap()
        };
        assert_eq!(side("i"), format!("POST /v1/messages\n\n{body}"));
        assert_eq!(side("o"), "HTTP 200\n\nfirstsecond");
        assert!(!side("i").contains(REAL) && !side("o").contains(REAL));
        assert!(chunks.iter().all(|c| c.conn == chunks[0].conn));
    }

    #[tokio::test]
    async fn the_journal_keeps_the_agents_request_line_never_the_key() {
        let (up, mut rx) =
            fake_upstream_with(Some(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")).await;
        let journal = Arc::new(crate::journal::Queue::default());
        let rec = Arc::new(crate::recording::Recorder::new(false));
        let gate = start_gate_journal(up, Default::default(), rec, journal.clone()).await;
        let ph = placeholder::make(&KEY, SID, 0);
        assert_eq!(send(&gate, &ph, "{}").await.status(), StatusCode::OK);
        assert!(
            rx.recv().await.unwrap().contains(REAL),
            "upstream got the key"
        );
        let bad = send(
            &gate,
            "kepr-ph-0123456789abcdef-0000-0000000000000000",
            "{}",
        )
        .await;
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let got = journal.take();
        assert_eq!(got.len(), 2, "{got:?}");
        let (ok, refused) = (&got[0], &got[1]);
        assert_eq!(
            (ok.provider.as_str(), ok.host.as_str(), ok.method.as_str()),
            ("anthropic", "api.anthropic.com", "POST")
        );
        assert_eq!(
            (ok.path.as_str(), ok.status, ok.session.as_str()),
            ("/v1/messages", 200, SID)
        );
        assert_eq!(refused.status, 401);
        for e in &got {
            let line = crate::journal::format(e);
            assert!(
                !line.contains(REAL) && !line.contains("beta") && !line.contains("kepr-ph-"),
                "{line}"
            );
        }
    }

    #[tokio::test]
    async fn a_metered_response_journals_its_tokens() {
        const USAGE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 48\r\n\r\n{\"usage\":{\"input_tokens\":30,\"output_tokens\":12}}";
        let (up, _rx) = fake_upstream_with(Some(USAGE)).await;
        let journal = Arc::new(crate::journal::Queue::default());
        let rec = Arc::new(crate::recording::Recorder::new(false));
        let gate = start_gate_journal(up, Default::default(), rec, journal.clone()).await;
        let ph = placeholder::make(&KEY, SID, 0);
        let r = send(&gate, &ph, "{}").await;
        assert_eq!(r.status(), StatusCode::OK);
        r.into_body().collect().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let got = journal.take();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!((got[0].status, got[0].tokens), (200, Some(42)));
    }

    #[tokio::test]
    async fn an_upstream_echoing_the_key_does_not_put_it_in_the_recording() {
        const ECHO: &[u8] = b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 39\r\n\r\n{\"error\":\"bad key real-key-1234567890\"}";
        let (up, _rx) = fake_upstream_with(Some(ECHO)).await;
        let rec = Arc::new(crate::recording::Recorder::new(true));
        let gate = start_gate_full(up, Default::default(), rec.clone()).await;
        let ph = placeholder::make(&KEY, SID, 0);
        let resp = send(&gate, &ph, "{}").await;
        let got = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&got).contains(REAL), "agent view");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let recorded: Vec<u8> = rec
            .take()
            .into_iter()
            .flat_map(|b| b.chunks)
            .flat_map(|c| c.bytes())
            .collect();
        let text = String::from_utf8(recorded).unwrap();
        assert!(!text.contains(REAL), "{text}");
        assert!(text.contains("bad key *******************"), "{text}");
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

    /// T9.06: the daemon's per-day counters, shared by every session.
    #[derive(Clone, Default)]
    struct Daily(Arc<std::sync::Mutex<HashMap<String, (u64, u64)>>>);
    impl Resolve for Daily {
        fn generation(&self) -> Result<u64, String> {
            Fixed.generation()
        }
        fn resolve(&self, n: &str, h: &str, p: u16) -> Result<(ZeroString, Inject), String> {
            Fixed.resolve(n, h, p)
        }
        fn day_usage(&self, name: &str, r: u64, t: u64) -> Result<(u64, u64), String> {
            let mut m = self.0.lock().unwrap();
            let e = m.entry(name.to_string()).or_default();
            *e = (e.0 + r, e.1 + t);
            Ok(*e)
        }
    }

    async fn start_daily_gate(upstream: String, day: Daily) -> String {
        let limits = kepr_core::gate_protocol::GateLimits {
            max_requests_day: Some(2),
            ..Default::default()
        };
        start_gate_resolver(upstream, Box::new(day), limits).await
    }

    async fn start_gate_resolver(
        upstream: String,
        resolver: Box<dyn Resolve>,
        limits: kepr_core::gate_protocol::GateLimits,
    ) -> String {
        let cache = Arc::new(Cache::new(resolver, DEFAULT_TTL));
        let mut routes = HashMap::new();
        let cred = "ANTHROPIC_API_KEY".to_string();
        routes.insert("anthropic".to_string(), Route { cred, slot: 0 });
        let state = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache)
            .with_test_upstream(upstream)
            .with_limits(limits);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(serve(l, Arc::new(state)));
        addr
    }

    #[tokio::test]
    async fn daily_cap_holds_across_sessions() {
        let (up, _rx) =
            fake_upstream_with(Some(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")).await;
        let day = Daily::default();
        let a = start_daily_gate(up.clone(), day.clone()).await;
        let b = start_daily_gate(up, day.clone()).await;
        let ph = placeholder::make(&KEY, SID, 0);
        assert_eq!(send(&a, &ph, "{}").await.status(), StatusCode::OK);
        assert_eq!(send(&b, &ph, "{}").await.status(), StatusCode::OK);
        let r = send(&a, &ph, "{}").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let body =
            String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(
            body.contains("kepr_limit") && body.contains("daily limit of 2"),
            "{body}"
        );
        assert_eq!(day.0.lock().unwrap()["ANTHROPIC_API_KEY"].0, 3);
    }

    /// T9.08: the daemon's side of the canary check, one decoy planted.
    #[derive(Clone)]
    struct Planted(String, Arc<std::sync::Mutex<u32>>);
    impl Resolve for Planted {
        fn generation(&self) -> Result<u64, String> {
            Fixed.generation()
        }
        fn resolve(&self, n: &str, h: &str, p: u16) -> Result<(ZeroString, Inject), String> {
            Fixed.resolve(n, h, p)
        }
        fn canary(&self, fps: Vec<String>) -> Result<bool, String> {
            let hit = fps.contains(&kepr_core::canary::fingerprint(self.0.as_bytes()));
            *self.1.lock().unwrap() += u32::from(hit);
            Ok(hit)
        }
    }

    #[tokio::test]
    async fn a_planted_canary_is_refused_and_reported() {
        let (up, mut rx) =
            fake_upstream_with(Some(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")).await;
        let decoy = kepr_core::canary::make("anthropic").unwrap();
        let planted = Planted(decoy.clone(), Arc::default());
        let gate = start_gate_resolver(up, Box::new(planted.clone()), Default::default()).await;
        // Sent where the placeholder goes, and inside a body.
        let r = send(&gate, &decoy, "{}").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let body =
            String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(
            body.contains("kepr_blocked") && !body.contains("canary"),
            "{body}"
        );
        let ph = placeholder::make(&KEY, SID, 0);
        let r = send(&gate, &ph, &format!("{{\"note\":\"{decoy}\"}}")).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(*planted.1.lock().unwrap(), 2, "both reported to the daemon");
        // A clean request still goes through; the refused ones never left.
        assert_eq!(send(&gate, &ph, "{}").await.status(), StatusCode::OK);
        assert!(!rx.recv().await.unwrap().contains(&decoy));
        assert!(rx.try_recv().is_err());
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
            .with_egress(Some(ca.clone()), tunnel);
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
        let tls_cfg =
            rustls::ClientConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
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
