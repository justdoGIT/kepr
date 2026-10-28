//! The steps every proxied HTTP request shares (split out of proxy.rs
//! for T12.07, so the git route reuses them rather than copying them):
//! the checks before anything is forwarded, the upstream request with
//! the key injected, and the response as the agent may see it.

use std::time::Instant;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HeaderMap;
use hyper::{Request, Response, StatusCode, Uri};
use kepr_core::binding::Inject;
use kepr_core::generate::ZeroString;

use crate::journal::Log;
use crate::proxy::{kepr_error, limit_response, Body, Route, State};
use crate::rewrite::{placeholders_in, upstream_headers, upstream_query};

/// What every HTTP route checks before it forwards (T12.07: git_http.rs
/// too): the canary screen of the head, the placeholder, the limits, then
/// the key for `log.host` (a GitHub App key swapped for its token). `Err`
/// is the refusal, already journaled.
pub(crate) async fn admit(
    log: &Log<'_>,
    route: &Route,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<(ZeroString, Inject), Response<Body>> {
    admit_at(log, route, headers, query, (log.host, 443)).await
}

/// [`admit`] for a credential bound to `(host, port)` (T13.04: a Kubernetes
/// API server is not on 443).
pub(crate) async fn admit_at(
    log: &Log<'_>,
    route: &Route,
    headers: &HeaderMap,
    query: Option<&str>,
    (host, port): (&str, u16),
) -> Result<(ZeroString, Inject), Response<Body>> {
    let state = log.state;
    if let Some((r, why)) = crate::canary::screen(&state.cache, headers, query, None).await {
        return Err(log.reply(r, 0, Some(why))); // T9.08
    }
    let phs = placeholders_in(headers, query);
    if phs.is_empty() || !phs.iter().all(|p| state.valid_placeholder(p, route.slot)) {
        let msg = "invalid or missing kepr placeholder";
        return Err(log.reply(kepr_error(StatusCode::UNAUTHORIZED, "kepr", msg), 0, None));
    }
    if let Err(refusal) = state.limiter.admit(Instant::now()) {
        return Err(log.reply(limit_response(refusal), 0, Some("limit")));
    }
    let today = (state.limiter).admit_today(state.cache.clone(), route.cred.clone());
    if let Err(refusal) = today.await {
        return Err(log.reply(limit_response(refusal), 0, Some("limit"))); // T9.06
    }
    let (cache, cred, h) = (state.cache.clone(), route.cred.clone(), host.to_string());
    let Ok(Ok((value, inject))) =
        tokio::task::spawn_blocking(move || cache.get(&cred, &h, port)).await
    else {
        let msg = "kepr could not obtain the credential";
        return Err(log.reply(kepr_error(StatusCode::BAD_GATEWAY, "kepr", msg), 0, None));
    };
    // T7.08: a GitHub App key becomes an installation token here.
    crate::github_app::swap(state, value, inject)
        .await
        .map_err(|_| {
            let msg = "kepr could not obtain a token";
            log.reply(kepr_error(StatusCode::BAD_GATEWAY, "kepr", msg), 0, None)
        })
}

/// The upstream request for `log.path` on `log.host` (or the test base):
/// the agent's method and query, headers rebuilt with the key.
pub(crate) fn upstream_request<B>(
    log: &Log<'_>,
    parts: &hyper::http::request::Parts,
    inject: &Inject,
    value: &str,
    body: B,
) -> Option<Request<B>> {
    let base = (log.state.base_override.clone()).unwrap_or_else(|| format!("https://{}", log.host));
    let q = upstream_query(parts.uri.query(), inject, value)
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let uri = format!("{base}{}{q}", log.path).parse::<Uri>().ok()?;
    let headers = upstream_headers(&parts.headers, inject, value).ok()?;
    let mut up = Request::builder()
        .method(parts.method.clone())
        .uri(uri)
        .body(body)
        .ok()?;
    *up.headers_mut() = headers;
    Some(up)
}

/// An upstream response as the agent may see it: hop-by-hop headers
/// gone and every value the session resolved masked (T12.01); `own` are
/// the forms of the key this request used.
pub(crate) fn for_agent(
    state: &State,
    resp: Response<Incoming>,
    inject: &Inject,
    own: Vec<ZeroString>,
) -> (hyper::http::response::Parts, Body) {
    let (mut p, b) = resp.into_parts();
    crate::rewrite::clean_response(&mut p.headers, inject);
    let mut n = state.cache.needles();
    n.extend(own);
    crate::mask::headers(&mut p.headers, &n);
    (p, crate::mask::body(b.boxed(), n))
}

pub(crate) fn cannot_build() -> Response<Body> {
    let msg = "kepr could not build the upstream request";
    kepr_error(StatusCode::BAD_REQUEST, "kepr", msg)
}

pub(crate) fn upstream_failed() -> Response<Body> {
    kepr_error(StatusCode::BAD_GATEWAY, "kepr", "upstream request failed")
}
