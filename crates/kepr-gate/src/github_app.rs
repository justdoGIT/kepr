//! GitHub App installation tokens (T7.08, batch: aws), the gate half.
//!
//! A route whose sealed key carries `Inject::GithubApp` resolves to the
//! App's private key (PEM). The gate signs a 9-minute app JWT with it
//! (RS256, ring), exchanges that at
//! `POST /app/installations/{id}/access_tokens` for a 1-hour installation
//! token and injects the token as a Bearer credential. Tokens are cached
//! per key until 5 minutes before their `expires_at`, so each session
//! mints its own and renews it as it runs; they live in the session's
//! cache (vault.rs), so whatever empties it (a store change) ends them.
//! Neither the key, the JWT nor the token ever reaches the agent; errors
//! carry the HTTP status only.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderValue, AUTHORIZATION};
use hyper::Request;
use kepr_core::binding::Inject;
use kepr_core::generate::ZeroString;
use kepr_core::github_app::{self as gh, KeyDer};
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::proxy::State;

/// Renew this long before `expires_at`.
pub(crate) const MARGIN_SECS: u64 = 300;
pub(crate) const MAX_REPLY: usize = 64 * 1024;

pub fn key_pair(pem: &str) -> Result<RsaKeyPair, String> {
    match gh::pem_der(pem)? {
        KeyDer::Pkcs1(der) => RsaKeyPair::from_der(&der),
        KeyDer::Pkcs8(der) => RsaKeyPair::from_pkcs8(&der),
    }
    .map_err(|_| "not a usable RSA private key".to_string())
}

/// RS256 (RSA PKCS#1 v1.5 with SHA-256) over `input`; shared with the
/// Google service-account JWTs (T12.09).
pub fn rs256(key: &RsaKeyPair, input: &[u8]) -> Result<Vec<u8>, ()> {
    let mut sig = vec![0u8; key.public().modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input, &mut sig)
        .map_err(|_| ())?;
    Ok(sig)
}

/// The RS256 app JWT for `app_id`, issued at `now`.
pub fn app_jwt(pem: &str, app_id: u64, now: u64) -> Result<ZeroString, String> {
    let key = key_pair(pem)?;
    let input = gh::jwt_signing_input(app_id, now);
    let sig = rs256(&key, input.as_bytes()).map_err(|_| "signing the app JWT failed")?;
    Ok(gh::jwt_finish(&input, &sig))
}

fn cache_key(pem: &str, app_id: u64, installation_id: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pem.as_bytes());
    h.update(app_id.to_be_bytes());
    h.update(installation_id.to_be_bytes());
    h.finalize().into()
}

/// A minted token still good for more than `MARGIN_SECS`.
pub(crate) fn cached(state: &State, key: &[u8; 32], now: u64) -> Option<ZeroString> {
    let (t, exp) = state.cache.minted(key)?;
    (now + MARGIN_SECS < exp).then_some(t)
}

/// The installation token for this key, minted when none is cached or
/// the cached one is within `MARGIN_SECS` of expiring.
pub async fn installation_token(
    state: &State,
    pem: &ZeroString,
    app_id: u64,
    installation_id: u64,
    now: u64,
) -> Result<ZeroString, String> {
    let key = cache_key(pem.as_str(), app_id, installation_id);
    if let Some(t) = cached(state, &key, now) {
        return Ok(t);
    }
    let jwt = app_jwt(pem.as_str(), app_id, now)?;
    let base = (state.base_override.clone()).unwrap_or_else(|| format!("https://{}", gh::API_HOST));
    let mut auth = HeaderValue::from_str(&format!("Bearer {}", jwt.as_str()))
        .map_err(|_| "app JWT is not a header value")?;
    auth.set_sensitive(true);
    drop(jwt);
    let mut req = Request::builder()
        .method("POST")
        .uri(format!(
            "{base}/app/installations/{installation_id}/access_tokens"
        ))
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "kepr-gate")
        .header("x-github-api-version", "2022-11-28")
        .body(Full::new(Bytes::new()))
        .map_err(|_| "could not build the GitHub token request")?;
    req.headers_mut().insert(AUTHORIZATION, auth);
    let resp = (state.client.request(req).await).map_err(|_| "GitHub token request failed")?;
    let status = resp.status().as_u16();
    let body = Limited::new(resp.into_body(), MAX_REPLY)
        .collect()
        .await
        .map_err(|_| "GitHub token reply unreadable")?
        .to_bytes();
    let body = Zeroizing::new(body.to_vec());
    if !(200..300).contains(&status) {
        return Err(format!(
            "GitHub refused the app token request: HTTP {status}"
        ));
    }
    let (token, exp) = gh::parse_token_reply(&body)?;
    state.cache.mint(key, &token, exp, now);
    Ok(token)
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A route's resolved key, with a GitHub App key swapped for an
/// installation token and a Google credential for an access token (T12.09),
/// both injected as Bearer; anything else unchanged.
pub async fn swap(
    state: &State,
    value: ZeroString,
    inject: Inject,
) -> Result<(ZeroString, Inject), String> {
    match inject {
        Inject::GithubApp {
            app_id,
            installation_id,
        } => {
            let t = installation_token(state, &value, app_id, installation_id, now_secs()).await?;
            Ok((t, Inject::Bearer))
        }
        Inject::GcpToken {
            scopes,
            impersonate,
        } => {
            let imp = impersonate.as_deref();
            let t = crate::gcp_token::token(state, &value, &scopes, imp, now_secs()).await?;
            Ok((t, Inject::Bearer))
        }
        other => Ok((value, other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{build_client, Route};
    use crate::vault::{Cache, Resolve, DEFAULT_TTL};
    use kepr_core::secmem::SplitKey;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    const SID: &str = "0123456789abcdef";
    const KEY: [u8; 32] = [5u8; 32];
    /// 2030-01-01T00:00:00Z
    const EXP: u64 = 1_893_456_000;

    fn fixture_pem() -> String {
        let b64 =
            include_str!("../../../src/cli_sharing/testdata/rsa2048-test-only.der.b64").trim();
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
            lines.join("\n")
        )
    }

    struct Pem(Inject);
    impl Resolve for Pem {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            Ok((ZeroString::from_string(fixture_pem()), self.0.clone()))
        }
    }

    /// GitHub stand-in: `access_tokens` POSTs get a token (numbered),
    /// anything else `{}`; every request is reported.
    async fn fake_github() -> (String, mpsc::UnboundedReceiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut minted = 0;
            while let Ok((mut s, _)) = l.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !String::from_utf8_lossy(&buf).contains("\r\n\r\n") {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let req = String::from_utf8_lossy(&buf).to_string();
                let (status, body) = if req.contains("/access_tokens") {
                    minted += 1;
                    let b = format!(
                        r#"{{"token":"ghs_test{minted}","expires_at":"2030-01-01T00:00:00Z"}}"#
                    );
                    ("201 Created", b)
                } else {
                    ("200 OK", "{}".to_string())
                };
                let _ = tx.send(req);
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        (base, rx)
    }

    fn state(base: String, inject: Inject) -> State {
        let cache = Arc::new(Cache::new(Box::new(Pem(inject)), DEFAULT_TTL));
        let routes = [(
            "github".to_string(),
            Route {
                cred: "GH_APP".into(),
                slot: 0,
            },
        )]
        .into();
        let mut st = State::new(SID.into(), SplitKey::new(&KEY).unwrap(), routes, cache);
        st.client = build_client(true);
        st.base_override = Some(base);
        st
    }

    fn app(installation_id: u64) -> Inject {
        Inject::GithubApp {
            app_id: 42,
            installation_id,
        }
    }

    #[test]
    fn jwt_is_rs256_signed_by_the_app_key() {
        use base64::Engine;
        let jwt = app_jwt(&fixture_pem(), 42, 1_700_000_000).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let dec = |s: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .unwrap()
        };
        let claims: serde_json::Value = serde_json::from_slice(&dec(parts[1])).unwrap();
        assert_eq!(claims["iss"], 42);
        assert_eq!(claims["exp"], 1_700_000_540u64);
        let key = key_pair(&fixture_pem()).unwrap();
        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key.public().as_ref(),
        );
        let input = format!("{}.{}", parts[0], parts[1]);
        assert!(pk.verify(input.as_bytes(), &dec(parts[2])).is_ok());
        assert!(pk.verify(b"other", &dec(parts[2])).is_err());
        assert!(app_jwt("ghp_not_a_key", 42, 0).is_err());
    }

    #[tokio::test]
    async fn tokens_are_cached_until_shortly_before_they_expire() {
        let (base, mut rx) = fake_github().await;
        let st = state(base, app(1001));
        let pem = ZeroString::from_string(fixture_pem());
        let fresh = EXP - 3600;
        let t1 = installation_token(&st, &pem, 42, 1001, fresh)
            .await
            .unwrap();
        let t2 = installation_token(&st, &pem, 42, 1001, fresh + 600)
            .await
            .unwrap();
        assert_eq!((t1.as_str(), t2.as_str()), ("ghs_test1", "ghs_test1"));
        let req = rx.recv().await.unwrap();
        assert!(req.starts_with("POST /app/installations/1001/access_tokens HTTP/1.1"));
        assert!(req
            .to_ascii_lowercase()
            .contains("authorization: bearer eyj"));
        assert!(!req.contains("PRIVATE KEY"));
        assert!(rx.try_recv().is_err(), "the cached token is reused");
        let t3 = installation_token(&st, &pem, 42, 1001, EXP - 200)
            .await
            .unwrap();
        assert_eq!(t3.as_str(), "ghs_test2", "renewed inside the margin");
    }

    #[tokio::test]
    async fn the_gh_route_sends_the_installation_token_never_the_key() {
        let (base, mut rx) = fake_github().await;
        let st = Arc::new(state(base, app(1002)));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(crate::proxy::serve(l, st));
        let ph = crate::placeholder::make(&KEY, SID, 0);
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let req = format!(
            "GET /github/user HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {ph}\r\nconnection: close\r\n\r\n"
        );
        c.write_all(req.as_bytes()).await.unwrap();
        let mut reply = String::new();
        c.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        let mint = rx.recv().await.unwrap();
        assert!(mint.starts_with("POST /app/installations/1002/access_tokens"));
        let api = rx.recv().await.unwrap();
        assert!(api.starts_with("GET /user HTTP/1.1"), "{api}");
        assert!(api.contains("authorization: Bearer ghs_test1"), "{api}");
        for r in [&mint, &api] {
            assert!(!r.contains("PRIVATE KEY") && !r.contains("MIIEow") && !r.contains(&ph));
        }
    }

    #[tokio::test]
    async fn other_injects_pass_through_and_failures_say_only_the_status() {
        let st = state("http://127.0.0.1:9".into(), Inject::Bearer);
        let (v, i) = swap(&st, ZeroString::from("k"), Inject::Bearer)
            .await
            .unwrap();
        assert_eq!((v.as_str(), i), ("k", Inject::Bearer));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 4096];
            let _ = s.read(&mut b).await;
            let body = r#"{"message":"A JSON web token could not be decoded","secret":"x"}"#;
            let _ = s
                .write_all(
                    format!(
                        "HTTP/1.1 401 X\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await;
        });
        let st = state(base, app(1003));
        let pem = ZeroString::from_string(fixture_pem());
        let e = installation_token(&st, &pem, 42, 1003, EXP - 3600)
            .await
            .unwrap_err();
        assert_eq!(e, "GitHub refused the app token request: HTTP 401");
    }

    /// Security review (T7.08): what empties the session's cache (a store
    /// change: revoke, rotate, a grant or approval window ending) drops the
    /// installation tokens minted from it too; another session's cache
    /// never hands out this one's token.
    #[tokio::test]
    async fn minted_tokens_go_with_the_cached_values() {
        let (base, mut rx) = fake_github().await;
        let st = state(base.clone(), app(1009));
        let pem = ZeroString::from_string(fixture_pem());
        let now = EXP - 3600;
        let t1 = installation_token(&st, &pem, 42, 1009, now).await.unwrap();
        assert_eq!(t1.as_str(), "ghs_test1");
        rx.recv().await.unwrap();
        st.cache.clear(); // what a generation change does
        let t2 = installation_token(&st, &pem, 42, 1009, now).await.unwrap();
        assert_eq!(t2.as_str(), "ghs_test2", "minted again");
        rx.recv().await.unwrap();
        let other = state(base, app(1009));
        let t3 = installation_token(&other, &pem, 42, 1009, now)
            .await
            .unwrap();
        assert_eq!(t3.as_str(), "ghs_test3", "its own token");
    }
}
