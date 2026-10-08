//! Honeytokens (T9.08): every key-shaped string in a request (headers,
//! query, then the body) is fingerprinted and checked with the daemon,
//! which keeps the fingerprints of the decoys `kepr canary plant` wrote.
//! A match is refused like any key-shaped string the DLP finds, and the
//! daemon raises the alarm (audit `canary-tripped`). The check runs
//! before the placeholder check, so a decoy sent instead of a
//! placeholder is caught too. The gate never holds the canary list.

use std::sync::Arc;

use hyper::header::HeaderMap;
use hyper::{Response, StatusCode};

use crate::proxy::{kepr_error, Body};
use crate::vault::Cache;

/// The request head as the agent sent it: query and header values.
fn head(headers: &HeaderMap, query: Option<&str>) -> Vec<u8> {
    let mut out = query.unwrap_or_default().as_bytes().to_vec();
    for v in headers.values() {
        out.push(b'\n');
        out.extend_from_slice(v.as_bytes());
    }
    out
}

/// Whether `text` holds a planted canary (the daemon decides; an
/// unreachable daemon counts as no, the DLP still refuses key shapes).
async fn tripped(cache: &Arc<Cache>, text: &[u8]) -> bool {
    let probes = kepr_core::leak::canary_probes(text);
    if probes.is_empty() {
        return false;
    }
    let cache = cache.clone();
    let r = tokio::task::spawn_blocking(move || cache.canary(probes)).await;
    matches!(r, Ok(Ok(true)))
}

/// The refusal for a request carrying a canary: the DLP's wording, so
/// the sender learns nothing about which keys are decoys.
fn refusal() -> Response<Body> {
    kepr_error(
        StatusCode::FORBIDDEN,
        "kepr_blocked",
        "kepr blocked this request: it contains what looks like an API key. Remove it and retry.",
    )
}

/// Screen the head (`body: None`) or the body of a request.
pub async fn screen(
    cache: &Arc<Cache>,
    headers: &HeaderMap,
    query: Option<&str>,
    body: Option<&[u8]>,
) -> Option<Response<Body>> {
    let hit = match body {
        Some(b) => tripped(cache, b).await,
        None => tripped(cache, &head(headers, query)).await,
    };
    hit.then(refusal)
}
