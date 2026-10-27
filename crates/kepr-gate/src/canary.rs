//! Honeytokens (T9.08): every key-shaped string in a request (headers,
//! query, then the body) is fingerprinted and checked with the daemon,
//! which keeps the fingerprints of the decoys `kepr canary plant` wrote.
//! A match is refused like any key-shaped string the DLP finds, and the
//! daemon raises the alarm (audit `canary-tripped`). The check runs
//! before the placeholder check, so a decoy sent instead of a
//! placeholder is caught too. The gate never holds the canary list.
//!
//! A JSON body is also probed as decoded (`\u0073k-…` is the decoy to
//! the provider, not to a byte match), and a request with more than
//! `MAX_CANARY_PROBES` distinct key-shaped strings is refused outright
//! with the same wording: junk keys sent first must not push a decoy
//! out of the check.

use std::sync::Arc;

use hyper::header::HeaderMap;
use hyper::{Response, StatusCode};

use kepr_core::leak::TooManyKeys;

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

/// Why `texts` must be refused: they hold a planted canary (the daemon
/// decides; an unreachable daemon counts as no, the DLP still refuses
/// key shapes), or too many key-shaped strings to check.
async fn tripped(cache: &Arc<Cache>, texts: &[&[u8]]) -> Option<&'static str> {
    let probes = match kepr_core::leak::canary_probes(texts) {
        Ok(p) if p.is_empty() => return None,
        Ok(p) => p,
        Err(TooManyKeys) => return Some("dlp"),
    };
    let cache = cache.clone();
    let r = tokio::task::spawn_blocking(move || cache.canary(probes)).await;
    matches!(r, Ok(Ok(true))).then_some("canary")
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

/// Screen the head (`body: None`) or the body of a request: the refusal
/// and why, for the journal (`canary`, or `dlp` for too many keys).
pub async fn screen(
    cache: &Arc<Cache>,
    headers: &HeaderMap,
    query: Option<&str>,
    body: Option<&[u8]>,
) -> Option<(Response<Body>, &'static str)> {
    let why = match body {
        Some(b) => match crate::dlp::unescape_json(b) {
            Some(decoded) => tripped(cache, &[b, &decoded]).await,
            None => tripped(cache, &[b]).await,
        },
        None => tripped(cache, &[&head(headers, query)]).await,
    };
    why.map(|why| (refusal(), why))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Resolve, DEFAULT_TTL};
    use http_body_util::BodyExt;
    use kepr_core::binding::Inject;
    use kepr_core::canary::{fingerprint, make};
    use kepr_core::generate::ZeroString;
    use std::sync::Mutex;

    /// The daemon's side: one decoy planted; counts the hits it saw.
    struct Planted(String, Arc<Mutex<u32>>);
    impl Resolve for Planted {
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            Err("not here".into())
        }
        fn generation(&self) -> Result<u64, String> {
            Ok(0)
        }
        fn canary(&self, fps: Vec<String>) -> Result<bool, String> {
            assert!(fps.len() <= kepr_core::leak::MAX_CANARY_PROBES);
            let hit = fps.contains(&fingerprint(self.0.as_bytes()));
            *self.1.lock().unwrap() += u32::from(hit);
            Ok(hit)
        }
    }

    fn planted() -> (String, Arc<Cache>, Arc<Mutex<u32>>) {
        let decoy = make("anthropic").unwrap();
        let hits = Arc::new(Mutex::new(0));
        let r = Planted(decoy.clone(), hits.clone());
        (decoy, Arc::new(Cache::new(Box::new(r), DEFAULT_TTL)), hits)
    }

    fn junk(n: usize) -> String {
        (0..n).map(|_| make("openai").unwrap() + " ").collect()
    }

    /// Security review (T9.08): a JSON escape spells the decoy for the
    /// provider (which decodes it) but not for a raw byte match.
    #[tokio::test]
    async fn an_escaped_decoy_in_a_json_body_is_caught() {
        let (decoy, cache, hits) = planted();
        let body = format!("{{\"note\":\"\\u0073{}\"}}", &decoy[1..]);
        let none = HeaderMap::new();
        let got = screen(&cache, &none, None, Some(body.as_bytes())).await;
        assert_eq!(got.map(|(_, why)| why), Some("canary"));
        assert_eq!(*hits.lock().unwrap(), 1, "the daemon heard of it");
    }

    /// Security review (T9.08): sixteen junk keys sent first must not push
    /// the decoy out of the probe list, in the body or in the head.
    #[tokio::test]
    async fn junk_keys_cannot_hide_a_decoy() {
        let (decoy, cache, _) = planted();
        let body = format!("{} {decoy}", junk(16));
        let none = HeaderMap::new();
        let (r, why) = screen(&cache, &none, None, Some(body.as_bytes()))
            .await
            .unwrap();
        assert_eq!((r.status(), why), (StatusCode::FORBIDDEN, "dlp"));
        let text = r.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&text);
        assert!(text.contains("looks like an API key"), "{text}");
        let mut headers = HeaderMap::new();
        headers.insert("x-note", body.parse().unwrap());
        assert!(screen(&cache, &headers, None, None).await.is_some());
        // The same key many times over is one probe, not many.
        let one = make("openai").unwrap();
        let repeated = format!("{one} {} {one} {one}", junk(15));
        assert!(screen(&cache, &none, None, Some(repeated.as_bytes()))
            .await
            .is_none());
    }
}
