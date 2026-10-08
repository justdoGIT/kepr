//! AWS requests through the egress proxy (T2.02, batch: aws).
//!
//! `bound` decides whether a CONNECT to `*.amazonaws.com` is intercepted:
//! only when the daemon releases one of the session's AWS keys for that
//! exact host (the daemon holds the bindings). `handle` serves each
//! decrypted request: placeholder signature check (sigv4_resign.rs),
//! limits, the credential-minting refusal, DLP, re-signing with the real
//! key and forwarding over TLS with the gate's compiled-in roots.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::AUTHORIZATION;
use hyper::{Request, Response, StatusCode, Uri};
use kepr_core::binding::Inject;
use kepr_core::sigv4_req::{placeholder_access_key_id, AwsKey};

use crate::journal::Log;
use crate::proxy::{kepr_error, limit_response, Body, State, MAX_BODY};
use crate::sigv4_resign::{self as rs, ReqView};

/// The route key prefix of AWS routes (`gate_protocol::aws_route_key`).
const PREFIX: &str = "aws:";

/// Is `host:port` an AWS host one of this session's AWS keys is bound to?
pub async fn bound(state: &Arc<State>, host: &str, port: u16) -> bool {
    let covered = state.ca.as_ref().is_some_and(|c| c.covers(host));
    if port != 443 || !host.ends_with(".amazonaws.com") || !covered {
        return false;
    }
    let creds: Vec<String> = state
        .routes
        .iter()
        .filter(|(k, _)| k.starts_with(PREFIX))
        .map(|(_, r)| r.cred.clone())
        .collect();
    for cred in creds {
        let (cache, h) = (state.cache.clone(), host.to_string());
        let got = tokio::task::spawn_blocking(move || cache.get(&cred, &h, 443)).await;
        if let Ok(Ok((_, Inject::Sigv4))) = got {
            return true;
        }
    }
    false
}

/// `(credential, placeholder)` of the AWS route whose placeholder key id
/// signed the request.
fn route_for(state: &State, akid: &str) -> Option<(String, String)> {
    state
        .routes
        .iter()
        .filter(|(k, _)| k.starts_with(PREFIX))
        .find_map(|(_, r)| {
            let ph = state
                .session_key
                .with_key(|k| crate::placeholder::make(k, &state.session_id, r.slot));
            (placeholder_access_key_id(&ph) == akid).then(|| (r.cred.clone(), ph))
        })
}

fn deny(
    log: &Log,
    status: StatusCode,
    kind: &str,
    msg: &str,
) -> Result<Response<Body>, Infallible> {
    Ok(log.reply(kepr_error(status, kind, msg), 0, Some("aws")))
}

pub async fn handle(
    state: Arc<State>,
    host: String,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let (method, path) = (req.method().to_string(), req.uri().path().to_string());
    let query = req.uri().query().unwrap_or("").to_string();
    let log = Log {
        state: &state,
        provider: "aws",
        host: &host,
        method: &method,
        path: &path,
        start: Instant::now(),
    };
    if rs::presigned(&query) {
        return deny(
            &log,
            StatusCode::FORBIDDEN,
            "kepr_blocked",
            "kepr: presigned AWS URLs are not supported",
        );
    }
    let auth = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let Some(auth) = auth.and_then(rs::parse_authorization) else {
        let msg = "kepr: sign AWS requests with SigV4 (AWS4-HMAC-SHA256) and the session's key";
        return deny(&log, StatusCode::FORBIDDEN, "kepr_blocked", msg);
    };
    let Some((cred, placeholder)) = route_for(&state, &auth.access_key_id) else {
        return deny(
            &log,
            StatusCode::UNAUTHORIZED,
            "kepr",
            "invalid or missing kepr placeholder",
        );
    };
    let host_hdr = rs::header_value(req.headers(), "host").unwrap_or_default();
    if host_hdr.trim_end_matches(":443") != host {
        return deny(
            &log,
            StatusCode::BAD_REQUEST,
            "kepr",
            "Host header does not match the connection",
        );
    }
    if let Err(refusal) = state.limiter.admit(Instant::now()) {
        return Ok(log.reply(limit_response(refusal), 0, Some("limit")));
    }
    let (parts, body) = req.into_parts();
    let Ok(bytes) = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map(|c| c.to_bytes())
    else {
        return deny(
            &log,
            StatusCode::PAYLOAD_TOO_LARGE,
            "kepr",
            "request body too large for kepr",
        );
    };
    let hash = rs::header_value(&parts.headers, "x-amz-content-sha256")
        .unwrap_or_else(|| kepr_core::sigv4::hex_sha256(&bytes));
    let view = ReqView {
        method: &method,
        path: &path,
        query: &query,
        headers: &parts.headers,
        payload_hash: &hash,
    };
    if rs::signed_streaming(&hash) {
        return deny(
            &log,
            StatusCode::FORBIDDEN,
            "kepr_blocked",
            "kepr: signed streaming uploads are not supported; use UNSIGNED-PAYLOAD",
        );
    }
    if !rs::verify(&view, &auth, &placeholder) {
        return deny(
            &log,
            StatusCode::UNAUTHORIZED,
            "kepr",
            "AWS signature does not match the session's placeholder key",
        );
    }
    if rs::mints_credentials(&view, &bytes) {
        return deny(
            &log,
            StatusCode::FORBIDDEN,
            "kepr_blocked",
            "kepr: this session may not create AWS credentials",
        );
    }
    let (cache, c, h) = (state.cache.clone(), cred.clone(), host.clone());
    let real = match tokio::task::spawn_blocking(move || cache.get(&c, &h, 443)).await {
        Ok(Ok((v, Inject::Sigv4))) => AwsKey::parse(v.as_str()).ok(),
        _ => None,
    };
    let Some(real) = real else {
        return deny(
            &log,
            StatusCode::BAD_GATEWAY,
            "kepr",
            "kepr could not obtain the credential",
        );
    };
    if let Some(msg) = crate::dlp::check(&parts, &bytes, &state.cache.values()) {
        return Ok(log.reply(
            kepr_error(StatusCode::FORBIDDEN, "kepr_blocked", &msg),
            bytes.len(),
            Some("dlp"),
        ));
    }
    let now = kepr_core::sigv4::format_amz_date(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    );
    let headers = rs::resign(&view, &auth, &real, &now);
    drop(real);
    let base = (state.base_override.clone()).unwrap_or_else(|| format!("https://{host}"));
    let q = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    let up = headers
        .ok()
        .zip(format!("{base}{path}{q}").parse::<Uri>().ok())
        .and_then(|(hm, uri)| {
            let mut up = Request::builder()
                .method(parts.method.clone())
                .uri(uri)
                .body(Full::new(bytes.clone()))
                .ok()?;
            *up.headers_mut() = hm;
            Some(up)
        });
    let Some(up) = up else {
        return deny(
            &log,
            StatusCode::BAD_REQUEST,
            "kepr",
            "kepr could not build the upstream request",
        );
    };
    match state.client.request(up).await {
        Ok(resp) => {
            let (mut p, b) = resp.into_parts();
            crate::rewrite::strip_hop_by_hop(&mut p.headers);
            log.emit(p.status, bytes.len(), None);
            Ok(Response::from_parts(p, b.boxed()))
        }
        Err(_) => deny(
            &log,
            StatusCode::BAD_GATEWAY,
            "kepr",
            "upstream request failed",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::Route;
    use crate::sigv4_resign::tests::{headers, sdk_sign};
    use crate::vault::{Cache, Resolve, DEFAULT_TTL};
    use bytes::Bytes;
    use kepr_core::generate::ZeroString;
    use kepr_core::secmem::SplitKey;
    use std::collections::HashMap;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    const SID: &str = "0123456789abcdef";
    const KEY: [u8; 32] = [5u8; 32];
    const REAL: &str =
        r#"{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"real/secret"}"#;

    /// Releases the key only for sts.amazonaws.com, like a binding would.
    struct Daemon;
    impl Resolve for Daemon {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, host: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            match host {
                "sts.amazonaws.com" => Ok((ZeroString::from(REAL), Inject::Sigv4)),
                _ => Err("credential unavailable".into()),
            }
        }
    }

    async fn upstream() -> (String, mpsc::UnboundedReceiver<String>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = mpsc::unbounded_channel();
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

    async fn gate(up: String) -> (String, Arc<crate::ca::SessionCa>) {
        let ca = Arc::new(crate::ca::SessionCa::with_suffixes(&[], &["amazonaws.com"]).unwrap());
        let cache = Arc::new(Cache::new(Box::new(Daemon), DEFAULT_TTL));
        let mut routes = HashMap::new();
        let route = Route {
            cred: "AWS_KEY".into(),
            slot: 0,
        };
        routes.insert("aws:AWS_KEY".to_string(), route);
        let mut st = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache)
            .with_egress(Some(ca.clone()), false);
        st.client = crate::proxy::build_client(true);
        st.base_override = Some(up);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(crate::proxy::serve(l, Arc::new(st)));
        (addr, ca)
    }

    async fn connect(gate: &str, target: &str) -> (tokio::net::TcpStream, String) {
        let mut s = tokio::net::TcpStream::connect(gate).await.unwrap();
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

    async fn send(
        stream: tokio::net::TcpStream,
        ca: &crate::ca::SessionCa,
        secret: &str,
        body: &'static [u8],
    ) -> StatusCode {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_der()).unwrap();
        let cfg =
            rustls::ClientConfig::builder_with_provider(Arc::new(crate::tls_provider::provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect("sts.amazonaws.com".try_into().unwrap(), stream)
            .await
            .unwrap();
        let (mut tx, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(conn);
        let ph = crate::placeholder::make(&KEY, SID, 0);
        let (mut h, hash) = headers(body);
        sdk_sign(
            "POST",
            "/",
            "",
            &mut h,
            &hash,
            (&placeholder_access_key_id(&ph), secret),
        );
        let mut req = Request::post("/")
            .body(Full::new(Bytes::from_static(body)))
            .unwrap();
        *req.headers_mut() = h;
        tx.send_request(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn re_signs_for_a_bound_aws_host_and_refuses_the_rest() {
        let (up, mut rx) = upstream().await;
        let (gate, ca) = gate(up).await;
        let ph = crate::placeholder::make(&KEY, SID, 0);

        let (s, status) = connect(&gate, "sts.amazonaws.com:443").await;
        assert!(status.contains("200"), "{status}");
        assert_eq!(
            send(s, &ca, &ph, b"Action=GetCallerIdentity").await,
            StatusCode::OK
        );
        let seen = rx.recv().await.unwrap();
        assert!(seen.contains("Credential=AKIAIOSFODNN7EXAMPLE/"), "{seen}");
        assert!(!seen.contains("KEPRPH") && !seen.contains("kepr-ph-"));
        assert!(
            !seen.contains("real/secret"),
            "the secret itself never travels"
        );

        // Signed with anything but the placeholder: refused, nothing sent.
        let (s, _) = connect(&gate, "sts.amazonaws.com:443").await;
        assert_eq!(
            send(s, &ca, "guess", b"Action=GetCallerIdentity").await,
            StatusCode::UNAUTHORIZED
        );
        // Minting credentials: refused.
        let (s, _) = connect(&gate, "sts.amazonaws.com:443").await;
        assert_eq!(
            send(s, &ca, &ph, b"Action=GetSessionToken").await,
            StatusCode::FORBIDDEN
        );
        assert!(rx.try_recv().is_err());

        // An AWS host the key is not bound to is not intercepted.
        let (_s, status) = connect(&gate, "s3.amazonaws.com:443").await;
        assert!(status.contains("403"), "{status}");
    }
}
