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
            client: build_client(false),
            base_override: None,
        }
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
    let path = req.uri().path().to_string();
    if path == "/__kepr/health" {
        return Ok(json(StatusCode::OK, "\"ok\"".into()));
    }
    let not_found = || kepr_error(StatusCode::NOT_FOUND, "kepr", "unknown kepr route");
    let Some((pname, rest)) = routes::split_path(&path) else {
        return Ok(not_found());
    };
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
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
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
            .with_test_upstream(upstream);
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
