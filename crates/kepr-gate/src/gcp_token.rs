//! Google access tokens minted per session (T12.09, batch: gate-providers),
//! the gate half of `kepr_core::gcp_token`.
//!
//! A route whose sealed credential carries `Inject::GcpToken` resolves to
//! a service-account key or an `authorized_user` file (JSON). The gate
//! gets a 1-hour access token for it: a service account signs an RS256
//! JWT (github_app::rs256) and trades it at `TOKEN_URL`; an
//! `authorized_user` file sends its refresh grant there. With
//! `impersonate`, that token then asks the IAM Credentials API for one
//! of the target service account. The token is injected as Bearer and
//! cached with the GitHub App tokens (vault.rs `minted`, secret memory)
//! until 5 minutes before it expires; whatever empties the session cache
//! (a store change) ends it. Neither the source, the JWT nor a token ever
//! reaches the agent; errors carry the HTTP status only.

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use hyper::Request;
use kepr_core::gcp_token::{self as gcp, Source};
use kepr_core::generate::ZeroString;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::github_app::{cached, key_pair, rs256, MAX_REPLY};
use crate::proxy::State;

/// What minted a token: source, scopes and target, length-prefixed and
/// tagged so it can't collide with a GitHub App cache key.
fn cache_key(source: &str, scopes: &[String], impersonate: Option<&str>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"kepr-gcp-token\0");
    let target = impersonate.unwrap_or("");
    let parts = std::iter::once(source).chain(scopes.iter().map(String::as_str));
    for p in parts.chain([target]) {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p.as_bytes());
    }
    h.finalize().into()
}

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// The signed service-account JWT for `scopes`, issued at `now`.
pub fn service_account_jwt(
    client_email: &str,
    private_key: &ZeroString,
    scopes: &[String],
    now: u64,
) -> Result<ZeroString, String> {
    let key = key_pair(private_key.as_str())?;
    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let claims = gcp::jwt_claims(client_email, scopes, now);
    let input = format!(
        "{}.{}",
        b64url(header.as_bytes()),
        b64url(claims.as_bytes())
    );
    let sig = rs256(&key, input.as_bytes()).map_err(|_| "signing the token request failed")?;
    Ok(kepr_core::github_app::jwt_finish(&input, &sig))
}

/// `https://host/path` on the real host, or the same path on the test
/// upstream.
fn at(state: &State, url: &str) -> String {
    match &state.base_override {
        Some(base) => {
            let rest = url.strip_prefix("https://").unwrap_or(url);
            format!("{base}{}", rest.find('/').map_or("/", |i| &rest[i..]))
        }
        None => url.to_string(),
    }
}

/// POST `body` to `url`; the reply body of a 2xx, else the status only.
async fn post(
    state: &State,
    url: &str,
    content_type: &'static str,
    bearer: Option<&ZeroString>,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut req = Request::post(at(state, url))
        .header(CONTENT_TYPE, content_type)
        .header("user-agent", "kepr-gate")
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|_| "could not build the Google token request")?;
    if let Some(t) = bearer {
        let mut v = HeaderValue::from_str(&format!("Bearer {}", t.as_str()))
            .map_err(|_| "Google token is not a header value")?;
        v.set_sensitive(true);
        req.headers_mut().insert(AUTHORIZATION, v);
    }
    let resp = (state.client.request(req).await).map_err(|_| "Google token request failed")?;
    let status = resp.status().as_u16();
    let reply = Limited::new(resp.into_body(), MAX_REPLY)
        .collect()
        .await
        .map_err(|_| "Google token reply unreadable")?
        .to_bytes();
    let reply = Zeroizing::new(reply.to_vec());
    if !(200..300).contains(&status) {
        return Err(format!("Google refused the token request: HTTP {status}"));
    }
    Ok(reply)
}

const FORM: &str = "application/x-www-form-urlencoded";

/// `(token, expiry)` from the source alone.
async fn source_token(
    state: &State,
    source: &Source,
    scopes: &[String],
    now: u64,
) -> Result<(ZeroString, u64), String> {
    let body = match source {
        Source::ServiceAccount {
            client_email,
            private_key,
        } => gcp::jwt_grant_body(&service_account_jwt(
            client_email,
            private_key,
            scopes,
            now,
        )?),
        Source::AuthorizedUser { .. } => {
            gcp::refresh_grant_body(source).ok_or("not a refresh credential")?
        }
    };
    let reply = post(state, gcp::TOKEN_URL, FORM, None, body.as_bytes()).await?;
    let (token, expires_in) = gcp::parse_token_reply(&reply)?;
    Ok((token, now.saturating_add(expires_in)))
}

/// The access token for this source, scopes and target: the cached one
/// while it has more than 5 minutes left, else a new one.
pub async fn token(
    state: &State,
    source_json: &ZeroString,
    scopes: &[String],
    impersonate: Option<&str>,
    now: u64,
) -> Result<ZeroString, String> {
    let key = cache_key(source_json.as_str(), scopes, impersonate);
    if let Some(t) = cached(state, &key, now) {
        return Ok(t);
    }
    let source = gcp::parse_source(source_json.as_str())?;
    let (mut token, mut exp) = source_token(state, &source, scopes, now).await?;
    drop(source);
    if let Some(target) = impersonate {
        let url = gcp::impersonate_url(target)?;
        let body = gcp::impersonate_body(scopes, gcp::MAX_LIFETIME);
        let reply = post(
            state,
            &url,
            "application/json",
            Some(&token),
            body.as_bytes(),
        )
        .await?;
        (token, exp) = gcp::parse_impersonate_reply(&reply)?;
    }
    state.cache.mint(key, &token, exp, now);
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{build_client, Route};
    use crate::vault::{Cache, Resolve, DEFAULT_TTL};
    use hyper::body::Incoming;
    use hyper::{HeaderMap, Response, StatusCode};
    use kepr_core::binding::Inject;
    use kepr_core::secmem::SplitKey;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    const SID: &str = "0123456789abcdef";
    const KEY: [u8; 32] = [6u8; 32];
    const SA: &str = "bot@proj.iam.gserviceaccount.com";
    const TARGET: &str = "deploy@other-proj.iam.gserviceaccount.com";
    const USER: &str = r#"{"type":"authorized_user","client_id":"cid.apps.googleusercontent.com",
        "client_secret":"user-client-secret","refresh_token":"1//user-refresh-token"}"#;

    fn fixture_pem() -> String {
        let b64 =
            include_str!("../../../src/cli_sharing/testdata/rsa2048-test-only.der.b64").trim();
        let lines: Vec<&str> = (b64.as_bytes().chunks(64))
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
            lines.join("\n")
        )
    }

    fn sa_json() -> ZeroString {
        let j = serde_json::json!({
            "type": "service_account", "client_email": SA, "private_key": fixture_pem(),
            "token_uri": "https://evil.example/token",
        });
        ZeroString::from(j.to_string())
    }

    fn scopes() -> Vec<String> {
        vec![gcp::DEFAULT_SCOPE.to_string()]
    }

    /// Google stand-in: numbered tokens from `/token` and
    /// `…:generateAccessToken`, `{}` for API calls, `fail` as the status
    /// when set; reports (request line, headers, body).
    struct Fake {
        base: String,
        rx: mpsc::UnboundedReceiver<(String, HeaderMap, String)>,
        fail: Arc<AtomicU16>,
    }

    async fn fake_google() -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = mpsc::unbounded_channel();
        let fail = Arc::new(AtomicU16::new(0));
        let (n, f) = (Arc::new(AtomicUsize::new(0)), fail.clone());
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let (tx, n, f) = (tx.clone(), n.clone(), f.clone());
                let svc = hyper::service::service_fn(move |r: Request<Incoming>| {
                    let (tx, n, f) = (tx.clone(), n.clone(), f.clone());
                    async move {
                        let line = format!("{} {}", r.method(), r.uri().path());
                        let (p, b) = r.into_parts();
                        let body = b.collect().await.unwrap().to_bytes();
                        let _ = tx.send((
                            line.clone(),
                            p.headers,
                            String::from_utf8_lossy(&body).into(),
                        ));
                        let i = n.fetch_add(1, Ordering::SeqCst) + 1;
                        let (status, out) = match f.load(Ordering::SeqCst) {
                            0 if line == "POST /token" => (
                                200,
                                format!(r#"{{"access_token":"ya29.src-{i}","expires_in":3600}}"#),
                            ),
                            0 if line.ends_with(":generateAccessToken") => (
                                200,
                                format!(
                                    r#"{{"accessToken":"ya29.imp-{i}","expireTime":"2030-01-01T00:00:00Z"}}"#
                                ),
                            ),
                            0 => (200, "{}".to_string()),
                            s => (
                                s,
                                r#"{"error":"denied","echo":"ya29.secret-echo"}"#.to_string(),
                            ),
                        };
                        let mut resp = Response::new(Full::new(Bytes::from(out)));
                        *resp.status_mut() = StatusCode::from_u16(status).unwrap();
                        Ok::<_, Infallible>(resp)
                    }
                });
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(s), svc),
                );
            }
        });
        Fake { base, rx, fail }
    }

    struct Creds(ZeroString, Option<String>);
    impl Resolve for Creds {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            let inject = Inject::GcpToken {
                scopes: scopes(),
                impersonate: self.1.clone(),
            };
            Ok((ZeroString::from(self.0.as_str()), inject))
        }
    }

    fn state(base: &str, source: ZeroString, imp: Option<&str>) -> State {
        let resolver = Creds(source, imp.map(str::to_string));
        let cache = Arc::new(Cache::new(Box::new(resolver), DEFAULT_TTL));
        let route = Route {
            cred: "GCP".into(),
            slot: 0,
        };
        let routes = [("gcloud".to_string(), route)].into();
        let mut st = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache);
        st.client = build_client(true);
        st.base_override = Some(base.to_string());
        st
    }

    fn form_field(body: &str, name: &str) -> Option<String> {
        body.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == name).then(|| v.to_string())
        })
    }

    #[tokio::test]
    async fn a_service_account_signs_a_jwt_that_verifies() {
        let mut g = fake_google().await;
        let st = state(&g.base, sa_json(), None);
        let t = token(&st, &sa_json(), &scopes(), None, 1_700_000_000)
            .await
            .unwrap();
        assert_eq!(t.as_str(), "ya29.src-1");
        let (line, h, body) = g.rx.recv().await.unwrap();
        assert_eq!(line, "POST /token", "the file's token_uri is ignored");
        assert_eq!(h[CONTENT_TYPE], FORM);
        let grant = form_field(&body, "grant_type").unwrap();
        assert_eq!(
            grant,
            "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
        );
        let jwt = form_field(&body, "assertion").unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let dec = |s: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .unwrap()
        };
        let header: serde_json::Value = serde_json::from_slice(&dec(parts[0])).unwrap();
        assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
        let claims: serde_json::Value = serde_json::from_slice(&dec(parts[1])).unwrap();
        assert_eq!(claims["iss"], SA);
        assert_eq!(claims["aud"], gcp::TOKEN_URL);
        assert_eq!(claims["scope"], gcp::DEFAULT_SCOPE);
        assert_eq!(claims["exp"], 1_700_003_600u64);
        let key = key_pair(&fixture_pem()).unwrap();
        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            crate::github_app::public_der(&key),
        );
        let input = format!("{}.{}", parts[0], parts[1]);
        assert!(pk.verify(input.as_bytes(), &dec(parts[2])).is_ok());
        assert!(!body.contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn an_authorized_user_sends_its_refresh_grant() {
        let mut g = fake_google().await;
        let src = ZeroString::from(USER);
        let st = state(&g.base, ZeroString::from(USER), None);
        assert_eq!(
            token(&st, &src, &scopes(), None, 10)
                .await
                .unwrap()
                .as_str(),
            "ya29.src-1"
        );
        let (line, _, body) = g.rx.recv().await.unwrap();
        assert_eq!(line, "POST /token");
        assert_eq!(
            form_field(&body, "grant_type").as_deref(),
            Some("refresh_token")
        );
        assert_eq!(
            form_field(&body, "refresh_token").as_deref(),
            Some("1%2F%2Fuser-refresh-token")
        );
        assert_eq!(
            form_field(&body, "client_secret").as_deref(),
            Some("user-client-secret")
        );
    }

    #[tokio::test]
    async fn impersonation_carries_the_source_token_and_the_target() {
        let mut g = fake_google().await;
        let st = state(&g.base, sa_json(), Some(TARGET));
        let t = token(&st, &sa_json(), &scopes(), Some(TARGET), 1_800_000_000).await;
        assert_eq!(t.unwrap().as_str(), "ya29.imp-2");
        g.rx.recv().await.unwrap();
        let (line, h, body) = g.rx.recv().await.unwrap();
        assert_eq!(
            line,
            format!("POST /v1/projects/-/serviceAccounts/{TARGET}:generateAccessToken")
        );
        assert_eq!(h[AUTHORIZATION], "Bearer ya29.src-1");
        let b: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            b,
            serde_json::json!({"scope": scopes(), "lifetime": "3600s"})
        );
        assert!(token(&st, &sa_json(), &scopes(), Some("x@example.com"), 1)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn tokens_are_reused_until_5_minutes_before_expiry_and_dropped_with_the_cache() {
        let mut g = fake_google().await;
        let st = state(&g.base, sa_json(), None);
        let now = 1_000_000;
        let (src, sc) = (sa_json(), scopes());
        let get = |n| token(&st, &src, &sc, None, n);
        assert_eq!(get(now).await.unwrap().as_str(), "ya29.src-1");
        assert_eq!(get(now + 3299).await.unwrap().as_str(), "ya29.src-1");
        g.rx.recv().await.unwrap();
        assert!(g.rx.try_recv().is_err(), "one upstream call");
        assert_eq!(get(now + 3300).await.unwrap().as_str(), "ya29.src-2");
        st.cache.clear(); // a store change
        assert_eq!(get(now + 3300).await.unwrap().as_str(), "ya29.src-3");
        let other = vec![format!("{}devstorage.read_only", gcp::SCOPE_PREFIX)];
        let t = token(&st, &sa_json(), &other, None, now + 3300)
            .await
            .unwrap();
        assert_eq!(t.as_str(), "ya29.src-4", "other scopes, another token");
    }

    #[tokio::test]
    async fn the_route_injects_the_token_and_a_refusal_is_a_bare_502() {
        let mut g = fake_google().await;
        let st = Arc::new(state(&g.base, sa_json(), None));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(crate::proxy::serve(l, st));
        let ph = crate::placeholder::make(&KEY, SID, 0);
        let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let call = |path: &str| {
            let req = Request::get(format!("{gate}/gcloud{path}"))
                .header("authorization", format!("Bearer {ph}"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            client.request(req)
        };
        let r = call("/storage/v1/b").await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        g.rx.recv().await.unwrap();
        let (line, h, _) = g.rx.recv().await.unwrap();
        assert_eq!(line, "GET /storage/v1/b");
        assert_eq!(h[AUTHORIZATION], "Bearer ya29.src-1");

        let mut g = fake_google().await;
        g.fail.store(403, Ordering::SeqCst);
        let st = Arc::new(state(&g.base, sa_json(), None));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(crate::proxy::serve(l, st));
        let req = Request::get(format!("{gate}/gcloud/storage/v1/b"))
            .header("authorization", format!("Bearer {ph}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let r = client.request(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
        let body = r.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("kepr could not obtain a token"), "{body}");
        assert!(!body.contains("denied") && !body.contains("ya29"), "{body}");
        assert_eq!(g.rx.recv().await.unwrap().0, "POST /token");
        assert!(g.rx.try_recv().is_err(), "the API was not called");
    }

    #[tokio::test]
    async fn creating_a_service_account_key_is_refused_and_never_forwarded() {
        let mut g = fake_google().await;
        let st = Arc::new(state(&g.base, sa_json(), None));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(crate::proxy::serve(l, st));
        let ph = crate::placeholder::make(&KEY, SID, 0);
        let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let req = Request::post(format!(
            "{gate}/gcloud/v1/projects/p/serviceAccounts/{SA}/keys"
        ))
        .header("authorization", format!("Bearer {ph}"))
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap();
        // The route host here is the provider's own (www.googleapis.com).
        let r = client.request(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("kepr_blocked"));
        // The route's own token request may have happened; the call did not.
        while let Ok((line, ..)) = g.rx.try_recv() {
            assert_eq!(line, "POST /token", "the API was called");
        }
    }
}
