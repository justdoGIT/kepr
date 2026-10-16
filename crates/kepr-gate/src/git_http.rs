//! T12.07: the `git` route (github.com through the egress proxy, or
//! `/git/...` on the gate) serves git smart-HTTP and nothing else:
//!
//!   GET  /<owner>/<repo>[.git]/info/refs?service=git-upload-pack|git-receive-pack
//!   POST /<owner>/<repo>[.git]/git-upload-pack|git-receive-pack
//!
//! Any other request is refused before upstream is contacted. The checks
//! and the injection are the ones every HTTP route uses (forward.rs).
//! upload-pack bodies (fetch negotiation, often gzip) are inflated for the
//! DLP scan and forwarded as sent. receive-pack bodies (packs, often past
//! MAX_BODY) stream upstream unbuffered; their objects are deflated, so a
//! byte scan can't see into them and DLP checks the URL and headers only.

use std::convert::Infallible;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONTENT_ENCODING, WWW_AUTHENTICATE};
use hyper::http::request::Parts;
use hyper::{Method, Request, Response, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use kepr_core::binding::Inject;
use kepr_core::generate::ZeroString;
use zeroize::Zeroizing;

use crate::journal::Log;
use crate::proxy::{build_client, kepr_error, Body, State, MAX_BODY};
use crate::{dlp, forward, routes};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Service {
    UploadPack,
    ReceivePack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    /// `GET …/info/refs?service=…`: the ref advertisement.
    Refs(Service),
    /// `POST …/git-upload-pack|git-receive-pack`.
    Rpc(Service),
}

fn service(name: &str) -> Option<Service> {
    match name {
        "git-upload-pack" => Some(Service::UploadPack),
        "git-receive-pack" => Some(Service::ReceivePack),
        _ => None,
    }
}

/// An owner or repository name: no empty, dot-only or encoded segments.
fn segment(s: &str) -> bool {
    (1..=100).contains(&s.len())
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// The smart-HTTP call a request is, or `None` for anything else.
fn classify(method: &Method, path: &str, query: Option<&str>) -> Option<Call> {
    let mut parts = path.strip_prefix('/')?.split('/');
    let (owner, repo) = (parts.next()?, parts.next()?);
    if !segment(owner) || !segment(repo) {
        return None;
    }
    let rest: Vec<&str> = parts.collect();
    match (method, rest.as_slice()) {
        (&Method::GET, ["info", "refs"]) => {
            Some(Call::Refs(service(query?.strip_prefix("service=")?)?))
        }
        (&Method::POST, [name]) if query.is_none() => Some(Call::Rpc(service(name)?)),
        _ => None,
    }
}

/// `Some(true)` for one `Content-Encoding: gzip`, `Some(false)` for none
/// (or identity), `None` for anything a scan can't see through.
fn gzip(parts: &Parts) -> Option<bool> {
    let all: Vec<&[u8]> = (parts.headers.get_all(CONTENT_ENCODING).iter())
        .map(|v| v.as_bytes())
        .filter(|v| !v.eq_ignore_ascii_case(b"identity"))
        .collect();
    match all.as_slice() {
        [] => Some(false),
        [one] if one.eq_ignore_ascii_case(b"gzip") => Some(true),
        _ => None,
    }
}

fn encoded() -> Response<Body> {
    let msg = "kepr blocked this request: this request body encoding can't be checked for secrets; send it uncompressed.";
    kepr_error(StatusCode::FORBIDDEN, "kepr_blocked", msg)
}

fn too_large() -> Response<Body> {
    let msg = "request body too large for kepr";
    kepr_error(StatusCode::PAYLOAD_TOO_LARGE, "kepr", msg)
}

/// Append without leaving an unwiped copy behind when the buffer grows.
fn append(buf: &mut Zeroizing<Vec<u8>>, data: &[u8]) {
    if buf.capacity() - buf.len() < data.len() {
        let want = (buf.len() + data.len()).next_power_of_two();
        let mut bigger = Zeroizing::new(Vec::with_capacity(want));
        bigger.extend_from_slice(buf);
        *buf = bigger;
    }
    buf.extend_from_slice(data);
}

/// A gzip body inflated (every member); `None` past MAX_BODY bytes,
/// `Some(Err)` when it isn't gzip.
fn inflate(gz: &[u8]) -> Option<Result<Zeroizing<Vec<u8>>, ()>> {
    let mut out = Zeroizing::new(Vec::new());
    let mut d = flate2::read::MultiGzDecoder::new(gz);
    let mut chunk = Zeroizing::new(vec![0u8; 64 * 1024]);
    loop {
        let Ok(n) = d.read(&mut chunk[..]) else {
            return Some(Err(()));
        };
        if n == 0 {
            return Some(Ok(out));
        }
        if out.len() + n > MAX_BODY {
            return None;
        }
        append(&mut out, &chunk[..n]);
    }
}

fn corrupt() -> Response<Body> {
    let msg = "kepr could not read the gzip request body";
    kepr_error(StatusCode::BAD_REQUEST, "kepr", msg)
}

/// The body checks of `proxy_request_to`: canary fingerprints, then DLP.
async fn screen(
    state: &State,
    parts: &Parts,
    body: &[u8],
) -> Option<(Response<Body>, &'static str)> {
    let canary = crate::canary::screen(&state.cache, &parts.headers, None, Some(body));
    if let Some(hit) = canary.await {
        return Some(hit);
    }
    let msg = dlp::check(parts, body, &state.cache.values())?;
    Some((
        kepr_error(StatusCode::FORBIDDEN, "kepr_blocked", &msg),
        "dlp",
    ))
}

/// git sends its login only after a 401 that offers Basic.
fn challenge(mut r: Response<Body>) -> Response<Body> {
    if r.status() == StatusCode::UNAUTHORIZED {
        let v = HeaderValue::from_static("Basic realm=\"kepr\"");
        r.headers_mut().insert(WWW_AUTHENTICATE, v);
    }
    r
}

/// The key for one request, with the forms masked in the reply.
struct Key {
    inject: Inject,
    value: ZeroString,
    own: Vec<ZeroString>,
}

/// Build, send and hand back the upstream reply; `sent` counts the
/// request body bytes for the journal.
async fn send<B>(
    log: &Log<'_>,
    client: &Client<HttpsConnector<HttpConnector>, B>,
    parts: &Parts,
    key: Key,
    body: B,
    sent: &AtomicUsize,
) -> Response<Body>
where
    B: hyper::body::Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let up = forward::upstream_request(log, parts, &key.inject, key.value.as_str(), body);
    drop(key.value);
    let Some(up) = up else {
        return log.reply(forward::cannot_build(), 0, None);
    };
    match client.request(up).await {
        Ok(resp) => {
            let (p, b) = forward::for_agent(log.state, resp, &key.inject, key.own);
            log.emit(p.status, sent.load(Ordering::Relaxed), None);
            Response::from_parts(p, b)
        }
        Err(_) => log.reply(
            forward::upstream_failed(),
            sent.load(Ordering::Relaxed),
            None,
        ),
    }
}

/// upload-pack: buffered (up to MAX_BODY), scanned inflated, sent as is.
async fn upload_pack(log: &Log<'_>, parts: &Parts, body: Incoming, key: Key) -> Response<Body> {
    let Ok(bytes) = Limited::new(body, MAX_BODY).collect().await else {
        return log.reply(too_large(), 0, None);
    };
    let bytes = bytes.to_bytes();
    let refusal = match gzip(parts) {
        None => Some((encoded(), "dlp")),
        Some(false) => screen(log.state, parts, &bytes).await,
        Some(true) => {
            let plain = match inflate(&bytes) {
                Some(Ok(p)) => p,
                Some(Err(())) => return log.reply(corrupt(), bytes.len(), None),
                None => return log.reply(too_large(), bytes.len(), None),
            };
            let mut bare = parts.clone();
            bare.headers.remove(CONTENT_ENCODING);
            screen(log.state, &bare, &plain).await
        }
    };
    if let Some((r, why)) = refusal {
        return log.reply(r, bytes.len(), Some(why));
    }
    let sent = AtomicUsize::new(bytes.len());
    send(log, &log.state.client, parts, key, Full::new(bytes), &sent).await
}

/// The URL and headers of a request whose body isn't scanned, which may
/// carry no body encoding.
async fn screen_head(state: &State, parts: &Parts) -> Option<(Response<Body>, &'static str)> {
    match gzip(parts) {
        Some(false) => screen(state, parts, &[]).await,
        _ => Some((encoded(), "dlp")),
    }
}

/// receive-pack: streamed upstream as it arrives, counted for the journal.
async fn receive_pack(log: &Log<'_>, parts: &Parts, body: Incoming, key: Key) -> Response<Body> {
    if let Some((r, why)) = screen_head(log.state, parts).await {
        return log.reply(r, 0, Some(why));
    }
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = sent.clone();
    let body: Body = body
        .map_frame(move |f| {
            if let Some(d) = f.data_ref() {
                counter.fetch_add(d.len(), Ordering::Relaxed);
            }
            f
        })
        .boxed();
    let client = build_client::<Body>(log.state.base_override.is_some());
    send(log, &client, parts, key, body, &sent).await
}

/// Serve one request on the git route; `path` is its path on github.com.
pub async fn handle(
    state: Arc<State>,
    path: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let (Some(provider), Some(route)) = (routes::lookup("git"), state.routes.get("git")) else {
        return Ok(kepr_error(
            StatusCode::NOT_FOUND,
            "kepr",
            "unknown kepr route",
        ));
    };
    let method = req.method().to_string();
    let log = Log {
        state: &state,
        provider: "git",
        host: provider.host,
        method: &method,
        path,
        start: Instant::now(),
    };
    let Some(call) = classify(req.method(), path, req.uri().query()) else {
        let msg = "kepr: the git route serves git smart-HTTP only";
        let r = kepr_error(StatusCode::FORBIDDEN, "kepr_blocked", msg);
        return Ok(log.reply(r, 0, Some("git")));
    };
    let (value, inject) = match forward::admit(&log, route, req.headers(), req.uri().query()).await
    {
        Ok(v) => v,
        Err(r) => return Ok(challenge(r)),
    };
    let own = crate::mask::forms(value.as_str()); // T12.01
    let key = Key { inject, value, own };
    let (parts, body) = req.into_parts();
    Ok(match call {
        Call::Rpc(Service::UploadPack) => upload_pack(&log, &parts, body, key).await,
        Call::Rpc(Service::ReceivePack) => receive_pack(&log, &parts, body, key).await,
        Call::Refs(_) => {
            if let Some((r, why)) = screen_head(&state, &parts).await {
                return Ok(log.reply(r, 0, Some(why)));
            }
            let sent = AtomicUsize::new(0);
            send(
                &log,
                &state.client,
                &parts,
                key,
                Full::new(Bytes::new()),
                &sent,
            )
            .await
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::Route;
    use crate::vault::{Cache, Resolve, DEFAULT_TTL};
    use base64::Engine;
    use hyper::header::AUTHORIZATION;
    use hyper::HeaderMap;
    use kepr_core::secmem::SplitKey;
    use std::collections::HashMap;
    use std::io::Write;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    const SID: &str = "0123456789abcdef";
    const KEY: [u8; 32] = [5u8; 32];
    const REAL: &str = "real-github-token-1234567890";

    struct Fixed;
    impl Resolve for Fixed {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, host: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            assert_eq!(host, "github.com");
            Ok((ZeroString::from(REAL), Inject::BasicPassword))
        }
    }

    /// What the fake github.com received: request line, headers, body.
    type Seen = (String, HeaderMap, Bytes);

    async fn upstream() -> (String, mpsc::UnboundedReceiver<Seen>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let tx = tx.clone();
                let svc = hyper::service::service_fn(move |r: Request<Incoming>| {
                    let tx = tx.clone();
                    async move {
                        let line = format!("{} {}", r.method(), r.uri());
                        let (p, b) = r.into_parts();
                        let body = b.collect().await.unwrap().to_bytes();
                        let _ = tx.send((line, p.headers, body));
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                    }
                });
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(s), svc),
                );
            }
        });
        (base, rx)
    }

    async fn gate(base: String) -> (String, Arc<State>) {
        let cache = Arc::new(Cache::new(Box::new(Fixed), DEFAULT_TTL));
        let route = Route {
            cred: "GH".into(),
            slot: 0,
        };
        let routes: HashMap<String, Route> = [("git".to_string(), route)].into();
        let mut st = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache);
        st.client = build_client(true);
        st.base_override = Some(base);
        let st = Arc::new(st);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(crate::proxy::serve(l, st.clone()));
        (addr, st)
    }

    fn login(user_and_pass: &str) -> String {
        let b = base64::engine::general_purpose::STANDARD.encode(user_and_pass);
        format!("Basic {b}")
    }

    fn ph() -> String {
        crate::placeholder::make(&KEY, SID, 0)
    }

    async fn call(
        gate: &str,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, HeaderMap, Bytes) {
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
        let mut req = Request::builder()
            .method(method)
            .uri(format!("{gate}/git{path}"));
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = (client.request(req.body(Full::new(Bytes::from(body))).unwrap()))
            .await
            .unwrap();
        let (p, b) = resp.into_parts();
        (p.status, p.headers, b.collect().await.unwrap().to_bytes())
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    const PACK: &str = "/o/r.git/git-upload-pack";

    #[tokio::test]
    async fn info_refs_gets_the_token_as_the_basic_password() {
        let (base, mut rx) = upstream().await;
        let (gate, _) = gate(base).await;
        let auth = login(&format!("x-access-token:{}", ph()));
        let path = "/o/r.git/info/refs?service=git-upload-pack";
        let (status, _, body) = call(
            &gate,
            Method::GET,
            path,
            &[("authorization", &auth)],
            vec![],
        )
        .await;
        assert_eq!((status, &body[..]), (StatusCode::OK, &b"ok"[..]));
        let (line, h, _) = rx.recv().await.unwrap();
        assert_eq!(line, "GET /o/r.git/info/refs?service=git-upload-pack");
        let want = login(&format!("x-access-token:{REAL}"));
        assert_eq!(h[AUTHORIZATION], want.as_str());
    }

    #[tokio::test]
    async fn a_gzip_fetch_hiding_the_token_is_blocked_before_upstream() {
        let (base, mut rx) = upstream().await;
        let (gate, _) = gate(base).await;
        let auth = login(&format!("x-access-token:{}", ph()));
        let body = gz(format!("0032want {REAL}\n0000").as_bytes());
        let hs = [
            ("authorization", auth.as_str()),
            ("content-encoding", "gzip"),
        ];
        let (status, _, b) = call(&gate, Method::POST, PACK, &hs, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&b).contains("kepr_blocked"));
        assert!(!String::from_utf8_lossy(&b).contains(REAL));
        assert!(rx.try_recv().is_err(), "upstream was contacted");
    }

    #[tokio::test]
    async fn a_clean_gzip_fetch_is_forwarded_byte_for_byte() {
        let (base, mut rx) = upstream().await;
        let (gate, _) = gate(base).await;
        let auth = login(&format!("x-access-token:{}", ph()));
        let body = gz(b"0032want 0123456789abcdef0123456789abcdef01234567\n00000009done\n");
        let hs = [
            ("authorization", auth.as_str()),
            ("content-encoding", "gzip"),
        ];
        let (status, _, _) = call(&gate, Method::POST, PACK, &hs, body.clone()).await;
        assert_eq!(status, StatusCode::OK);
        let (line, h, got) = rx.recv().await.unwrap();
        assert_eq!(line, format!("POST {PACK}"));
        assert_eq!(h[CONTENT_ENCODING], "gzip");
        assert_eq!(&got[..], &body[..]);
    }

    #[tokio::test]
    async fn a_20_mib_push_streams_through() {
        let (base, mut rx) = upstream().await;
        let (gate, st) = gate(base).await;
        let auth = login(&format!("alice:{}", ph()));
        let big = vec![b'p'; 20 * 1024 * 1024];
        let path = "/o/r/git-receive-pack";
        let (status, _, _) =
            call(&gate, Method::POST, path, &[("authorization", &auth)], big).await;
        assert_eq!(status, StatusCode::OK);
        let (_, h, got) = rx.recv().await.unwrap();
        assert_eq!(got.len(), 20 * 1024 * 1024);
        assert_eq!(h[AUTHORIZATION], login(&format!("alice:{REAL}")).as_str());
        let lines = st.journal.take();
        let push = lines.iter().find(|e| e.method == "POST").unwrap();
        assert_eq!(push.bytes_out, 20 * 1024 * 1024);
    }

    #[tokio::test]
    async fn other_paths_and_bad_logins_are_refused() {
        let (base, mut rx) = upstream().await;
        let (gate, _) = gate(base).await;
        let auth = login(&format!("x-access-token:{}", ph()));
        let (status, _, b) = call(
            &gate,
            Method::GET,
            "/settings/tokens",
            &[("authorization", &auth)],
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&b).contains("git smart-HTTP only"));
        let bad = login("x-access-token:kepr-ph-0123456789abcdef-0000-0011223344556677");
        let path = "/o/r.git/info/refs?service=git-upload-pack";
        let (status, h, _) =
            call(&gate, Method::GET, path, &[("authorization", &bad)], vec![]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(h[WWW_AUTHENTICATE], "Basic realm=\"kepr\"");
        let (status, _, _) = call(&gate, Method::GET, path, &[], vec![]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(rx.try_recv().is_err(), "upstream was contacted");
    }

    #[tokio::test]
    async fn a_gzip_bomb_is_refused_with_413() {
        let (base, mut rx) = upstream().await;
        let (gate, _) = gate(base).await;
        let auth = login(&format!("x-access-token:{}", ph()));
        let bomb = gz(&vec![b'0'; MAX_BODY + 1]);
        assert!(bomb.len() < MAX_BODY / 100);
        let hs = [
            ("authorization", auth.as_str()),
            ("content-encoding", "gzip"),
        ];
        let (status, _, _) = call(&gate, Method::POST, PACK, &hs, bomb).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let hs = [("authorization", auth.as_str()), ("content-encoding", "br")];
        let (status, _, _) = call(&gate, Method::POST, PACK, &hs, vec![1, 2]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = call(&gate, Method::POST, PACK, &hs[..1], {
            let mut two = gz(b"0009done\n");
            two.extend_from_slice(b"trailing junk");
            two
        })
        .await;
        assert_eq!(status, StatusCode::OK, "no encoding: scanned as sent");
        assert!(rx.recv().await.is_some());
        let hs = [
            ("authorization", auth.as_str()),
            ("content-encoding", "gzip"),
        ];
        let mut junk = gz(b"0009done\n");
        junk.extend_from_slice(b"trailing junk");
        let (status, _, _) = call(&gate, Method::POST, PACK, &hs, junk).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unreadable gzip");
        let mut hidden = gz(b"0009done\n");
        hidden.extend(gz(REAL.as_bytes()));
        let (status, _, _) = call(&gate, Method::POST, PACK, &hs, hidden).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a second gzip member is scanned"
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn only_smart_http_paths_classify() {
        let q = Some("service=git-upload-pack");
        let refs = Some(Call::Refs(Service::UploadPack));
        assert_eq!(classify(&Method::GET, "/o/r.git/info/refs", q), refs);
        assert_eq!(classify(&Method::GET, "/o/r/info/refs", q), refs);
        assert_eq!(
            classify(
                &Method::GET,
                "/o/r/info/refs",
                Some("service=git-receive-pack")
            ),
            Some(Call::Refs(Service::ReceivePack))
        );
        assert_eq!(
            classify(&Method::POST, "/o/r/git-receive-pack", None),
            Some(Call::Rpc(Service::ReceivePack))
        );
        for (m, p, q) in [
            (Method::GET, "/o/r/info/refs", None),
            (
                Method::GET,
                "/o/r/info/refs",
                Some("service=git-upload-archive"),
            ),
            (Method::POST, "/o/r/info/refs", q),
            (Method::GET, "/o/r/git-upload-pack", None),
            (Method::POST, "/o/r/git-upload-pack", Some("x=1")),
            (Method::POST, "/o/r/objects/info/packs", None),
            (Method::POST, "/o/../git-upload-pack", None),
            (Method::POST, "/o/r%2e/git-upload-pack", None),
            (Method::POST, "//r/git-upload-pack", None),
            (Method::POST, "/o/r/x/git-upload-pack", None),
            (Method::GET, "/settings/tokens", None),
            (Method::GET, "/o/r/info/lfs/objects/batch", None),
        ] {
            assert_eq!(classify(&m, p, q), None, "{m} {p}");
        }
    }
}
