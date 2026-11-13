//! Cloudflare routing and authentication stay inside the gate. Applications
//! use /cloudflare/compat and session placeholders, never account IDs or keys.

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::AUTHORIZATION;
use hyper::{Request, Uri};
use kepr_core::binding::Inject;
use kepr_core::cloudflare::{GatewayCredential, HOST};
use zeroize::Zeroizing;

use crate::journal::Log;

fn endpoint<'a>(path: &'a str, body: &[u8]) -> Option<&'a str> {
    match path {
        // OMP's Cloudflare transport selects the native protocol and strips
        // OpenAI's model prefix, even when its base URL is overridden.
        "/compat/v1/messages" => Some("/anthropic/v1/messages"),
        "/compat/responses" => Some("/openai/responses"),
        "/compat/chat/completions" => {
            #[derive(serde::Deserialize)]
            struct Model<'b> {
                #[serde(borrow)]
                model: std::borrow::Cow<'b, str>,
            }
            let model: Model<'_> = serde_json::from_slice(body).ok()?;
            Some(if model.model.contains('/') {
                path
            } else {
                "/openai/chat/completions"
            })
        }
        "/openai/chat/completions" | "/openai/responses" | "/anthropic/v1/messages" => Some(path),
        _ => None,
    }
}

fn request_suffix<'a>(
    log: &Log<'a>,
    parts: &hyper::http::request::Parts,
    login: &GatewayCredential,
    body: &[u8],
) -> Option<&'a str> {
    if log.host != HOST || parts.method != hyper::Method::POST {
        return None;
    }
    let prefix = format!("/v1/{}/{}", login.account_id, login.gateway_id);
    let path = if log.path.starts_with("/v1/") {
        // Egress-proxy traffic may already have an upstream URL. It must
        // address the stored account, not a caller-selected gateway.
        log.path.strip_prefix(&prefix)?
    } else {
        log.path
    };
    endpoint(path, body)
}

/// Select a reviewed privacy schema only after authenticating the gateway prefix.
pub(crate) fn privacy_path(
    log: &Log<'_>,
    parts: &hyper::http::request::Parts,
    value: &str,
    body: &[u8],
) -> Option<&'static str> {
    let login = GatewayCredential::parse(value).ok()?;
    match request_suffix(log, parts, &login, body)? {
        "/compat/chat/completions" | "/openai/chat/completions" => Some("/v1/chat/completions"),
        "/openai/responses" => Some("/v1/responses"),
        "/anthropic/v1/messages" => Some("/v1/messages"),
        _ => None,
    }
}

pub(crate) fn upstream_request(
    log: &Log<'_>,
    parts: &hyper::http::request::Parts,
    value: &str,
    body: Bytes,
) -> Option<Request<Full<Bytes>>> {
    let login = GatewayCredential::parse(value).ok()?;
    let suffix = request_suffix(log, parts, &login, &body)?;
    let path = login.upstream_path(suffix).ok()?;
    let base = log
        .state
        .base_override
        .as_deref()
        .unwrap_or("https://gateway.ai.cloudflare.com");
    let query = crate::rewrite::upstream_query(parts.uri.query(), &Inject::CloudflareGateway, "")
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let uri = format!("{base}{path}{query}").parse::<Uri>().ok()?;
    let header = Zeroizing::new(format!("Bearer {}", login.token.as_str()));
    let inject = Inject::Header {
        name: "cf-aig-authorization".into(),
    };
    let mut headers = crate::rewrite::upstream_headers(&parts.headers, &inject, &header).ok()?;
    headers.remove(AUTHORIZATION);
    headers.remove("x-api-key");
    let mut request = Request::builder()
        .method(parts.method.clone())
        .uri(uri)
        .body(Full::new(body))
        .ok()?;
    *request.headers_mut() = headers;
    Some(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{Route, State};
    use crate::vault::{Cache, Resolve, DEFAULT_TTL};
    use http_body_util::BodyExt;
    use hyper::{Response, StatusCode};
    use hyper_util::client::legacy::{connect::HttpConnector, Client};
    use kepr_core::generate::ZeroString;
    use kepr_core::secmem::SplitKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::net::TcpListener;

    const TOKEN: &str = "synthetic-cloudflare-secret";
    const SID: &str = "0123456789abcdef";
    const KEY: [u8; 32] = [7; 32];

    fn login() -> ZeroString {
        GatewayCredential::new(TOKEN.into(), "a".repeat(32), "coding".into())
            .unwrap()
            .encode()
    }

    struct Vault;
    impl Resolve for Vault {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, host: &str, port: u16) -> Result<(ZeroString, Inject), String> {
            assert_eq!((host, port), (HOST, 443));
            Ok((login(), Inject::CloudflareGateway))
        }
    }

    fn state() -> State {
        State::new(
            SID.into(),
            SplitKey::new(&KEY).unwrap(),
            HashMap::new(),
            Arc::new(Cache::new(Box::new(Vault), DEFAULT_TTL)),
        )
    }

    #[test]
    fn protocol_selection_preserves_native_and_compat_requests() {
        for (path, body, expected) in [
            (
                "/compat/chat/completions",
                br#"{"model":"reflection-ai/beam-1.0-501b-a23b"}"#.as_slice(),
                "/compat/chat/completions",
            ),
            (
                "/compat/chat/completions",
                br#"{"model":"gpt-test"}"#.as_slice(),
                "/openai/chat/completions",
            ),
            (
                "/compat/chat/completions",
                br#"{"model":"reflection-ai\/beam"}"#.as_slice(),
                "/compat/chat/completions",
            ),
            (
                "/compat/chat/completions",
                br#"{"model":"reflection-ai\u002fbeam"}"#.as_slice(),
                "/compat/chat/completions",
            ),
            (
                "/compat/chat/completions",
                br#"{"model":"gp\u0074-test"}"#.as_slice(),
                "/openai/chat/completions",
            ),
            (
                "/compat/v1/messages",
                b"{}".as_slice(),
                "/anthropic/v1/messages",
            ),
            ("/compat/responses", b"{}".as_slice(), "/openai/responses"),
        ] {
            assert_eq!(endpoint(path, body), Some(expected));
        }
        assert!(endpoint("/compat/chat/completions", b"{}").is_none());
        assert!(endpoint("/admin/tokens", b"{}").is_none());
    }

    #[test]
    fn destination_and_login_cannot_be_overridden_by_the_caller() {
        let state = state();
        let body = Bytes::from_static(br#"{"model":"reflection-ai/beam"}"#);
        let request = Request::post("/cloudflare/compat/chat/completions?stream=true")
            .header("authorization", "Bearer caller-controlled")
            .header("x-api-key", "caller-controlled")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        let log = Log {
            state: &state,
            provider: "cloudflare",
            host: HOST,
            method: "POST",
            path: "/compat/chat/completions",
            start: Instant::now(),
        };
        let built = upstream_request(&log, &parts, login().as_str(), body.clone()).unwrap();
        assert_eq!(
            built.uri().to_string(),
            format!(
                "https://{HOST}/v1/{}/coding/compat/chat/completions?stream=true",
                "a".repeat(32)
            )
        );
        assert_eq!(
            built.headers()["cf-aig-authorization"],
            format!("Bearer {TOKEN}")
        );
        assert!(built.headers()["cf-aig-authorization"].is_sensitive());
        assert!(built.headers().get(AUTHORIZATION).is_none());
        assert!(built.headers().get("x-api-key").is_none());
        let log = Log {
            path: "/v1/another/account/compat/chat/completions",
            ..log
        };
        assert!(upstream_request(&log, &parts, login().as_str(), body.clone()).is_none());
        let log = Log {
            host: "attacker.example",
            path: "/compat/chat/completions",
            ..log
        };
        assert!(upstream_request(&log, &parts, login().as_str(), body).is_none());
    }

    #[test]
    fn cached_login_token_is_screened_in_agent_prompts() {
        let state = state();
        state
            .cache
            .get("CLOUDFLARE_AI_GATEWAY_API_KEY", HOST, 443)
            .unwrap();
        assert_eq!(
            crate::dlp::scan(TOKEN.as_bytes(), &state.cache.values()),
            crate::dlp::Verdict::StoredSecret("CLOUDFLARE_AI_GATEWAY_API_KEY".into())
        );
    }

    #[tokio::test]
    async fn actual_gate_injects_the_token_and_masks_upstream_disclosures() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", upstream.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = upstream.accept().await.unwrap();
            let handler =
                hyper::service::service_fn(|request: Request<hyper::body::Incoming>| async move {
                    assert_eq!(request.method(), hyper::Method::POST);
                    assert_eq!(
                        request.uri().path(),
                        format!("/v1/{}/coding/compat/chat/completions", "a".repeat(32))
                    );
                    assert_eq!(
                        request.headers()["cf-aig-authorization"],
                        format!("Bearer {TOKEN}")
                    );
                    assert!(!request
                        .headers()
                        .values()
                        .any(|v| v.to_str().is_ok_and(|s| s.contains("kepr-ph-"))));
                    let request_body = request.into_body().collect().await.unwrap().to_bytes();
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&request_body).unwrap()
                            ["model"],
                        "reflection-ai/beam"
                    );
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(200)
                            .header("x-upstream-debug", TOKEN)
                            .body(Full::new(Bytes::from_static(TOKEN.as_bytes())))
                            .unwrap(),
                    )
                });
            hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(hyper_util::rt::TokioIo::new(socket), handler)
                .await
                .unwrap();
        });
        let mut state = state();
        state.routes.insert(
            "cloudflare".into(),
            Route {
                cred: "CLOUDFLARE_AI_GATEWAY_API_KEY".into(),
                slot: 0,
            },
        );
        state.client = crate::proxy::build_client(true);
        state.base_override = Some(base);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate = format!(
            "http://{}/cloudflare/compat/chat/completions",
            listener.local_addr().unwrap()
        );
        let gate_task = tokio::spawn(crate::proxy::serve(listener, Arc::new(state)));
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
        let req = Request::post(gate)
            .header(
                "cf-aig-authorization",
                format!("Bearer {}", crate::placeholder::make(&KEY, SID, 0)),
            )
            .body(Full::new(Bytes::from_static(
                br#"{"model":"reflection-ai/beam"}"#,
            )))
            .unwrap();
        let result: Response<_> =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.request(req))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert!(!result.headers()["x-upstream-debug"]
            .to_str()
            .unwrap()
            .contains(TOKEN));
        let body = result.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), "*".repeat(TOKEN.len()).as_bytes());
        server.await.unwrap();
        gate_task.abort();
    }

    #[tokio::test]
    async fn omp_privacy_routes_expand_the_gateway_and_mask_the_actual_upstream_request() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", upstream.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (socket, _) = upstream.accept().await.unwrap();
                let handler = hyper::service::service_fn(
                    |request: Request<hyper::body::Incoming>| async move {
                        assert_eq!(
                            request.uri().path(),
                            format!("/v1/{}/coding/compat/chat/completions", "a".repeat(32))
                        );
                        assert_eq!(
                            request.headers()["cf-aig-authorization"],
                            format!("Bearer {TOKEN}")
                        );
                        assert!(request.headers().get("x-personal-email").is_none());
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        assert!(!std::str::from_utf8(&bytes)
                            .unwrap()
                            .contains("alice@example.invalid"));
                        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                        assert_eq!(body["model"], "reflection-ai/beam");
                        assert!(body.get("metadata").is_none());
                        assert!(body["messages"][0]["content"]
                            .as_str()
                            .unwrap()
                            .contains("kepr-private-email-"));
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::from_static(b"{}")))
                                .unwrap(),
                        )
                    },
                );
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), handler)
                    .await
                    .unwrap();
            }
        });
        let mut state = state();
        let name = kepr_core::http_route::key(HOST, "CLOUDFLARE_AI_GATEWAY_API_KEY").unwrap();
        state.routes.insert(
            name.clone(),
            Route {
                cred: "CLOUDFLARE_AI_GATEWAY_API_KEY".into(),
                slot: 0,
            },
        );
        state.privacy =
            crate::privacy::Filter::new(Some(kepr_core::privacy::Policy::default())).unwrap();
        state.client = crate::proxy::build_client(true);
        state.base_override = Some(base);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate = format!("http://{}/{}", listener.local_addr().unwrap(), name);
        let gate_task = tokio::spawn(crate::proxy::serve(listener, Arc::new(state)));
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
        for suffix in [
            "/compat/chat/completions".to_string(),
            format!("/v1/{}/coding/compat/chat/completions", "a".repeat(32)),
        ] {
            let request = Request::post(format!("{gate}{suffix}"))
                .header("cf-aig-authorization", format!("Bearer {}", crate::placeholder::make(&KEY, SID, 0)))
                .header("content-type", "application/json")
                .header("x-personal-email", "alice@example.invalid")
                .body(Full::new(Bytes::from_static(br#"{"model":"reflection-ai/beam","messages":[{"role":"user","content":"Email alice@example.invalid"}],"metadata":{"email":"alice@example.invalid"}}"#))).unwrap();
            let response =
                tokio::time::timeout(std::time::Duration::from_secs(5), client.request(request))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "a protected OMP Cloudflare route must reach the masked upstream"
            );
            response.into_body().collect().await.unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        let request = Request::post(format!("{gate}/compat/chat/completions"))
            .header("cf-aig-authorization", format!("Bearer {}", crate::placeholder::make(&KEY, SID, 0)))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(br#"{"model":"reflection-ai/beam","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://media.example.invalid/private.png"}}]}]}"#))).unwrap();
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.request(request))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        gate_task.abort();
    }
}
