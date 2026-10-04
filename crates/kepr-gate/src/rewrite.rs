//! Request/response rewriting for the forwarding proxy: find
//! placeholders, build the upstream query and headers with the real
//! credential, strip hop-by-hop headers.

use base64::Engine;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use kepr_core::binding::Inject;

use crate::placeholder::PREFIX;

pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Every placeholder-looking value in the credential-carrying places of
/// a request: any header (optionally after an auth scheme such as
/// `Bearer`) and any query-string value.
pub fn placeholders_in(headers: &HeaderMap, query: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    for v in headers.values() {
        if let Ok(s) = v.to_str() {
            // Any auth scheme (`Bearer`, `bearer`, `Token`, ...) or none:
            // the placeholder is the last whitespace-separated token.
            if let Some(tok) = s
                .split_whitespace()
                .last()
                .filter(|t| t.starts_with(PREFIX))
            {
                out.push(tok.to_string());
            }
        }
    }
    for pair in query.unwrap_or_default().split('&') {
        if let Some((_, v)) = pair.split_once('=') {
            if v.starts_with(PREFIX) {
                out.push(v.to_string());
            }
        }
    }
    out
}

fn pct_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub fn upstream_query(query: Option<&str>, inject: &Inject, value: &str) -> Option<String> {
    let mut parts: Vec<String> = query
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
        .filter(|p| {
            !p.split_once('=')
                .is_some_and(|(_, v)| v.starts_with(PREFIX))
        })
        .map(str::to_string)
        .collect();
    if let Inject::Query { param } = inject {
        parts.push(format!("{param}={}", pct_encode(value)));
    }
    (!parts.is_empty()).then(|| parts.join("&"))
}

fn sensitive(v: String) -> Result<HeaderValue, String> {
    let mut hv = HeaderValue::from_str(&v).map_err(|_| "credential is not a valid header value")?;
    hv.set_sensitive(true);
    Ok(hv)
}

pub fn upstream_headers(
    src: &HeaderMap,
    inject: &Inject,
    value: &str,
) -> Result<HeaderMap, String> {
    let mut out = HeaderMap::new();
    for (k, v) in src {
        let name = k.as_str();
        let carries_placeholder = v.to_str().is_ok_and(|s| s.contains(PREFIX));
        if HOP_BY_HOP.contains(&name)
            || name == "host"
            || name == "content-length"
            || carries_placeholder
        {
            continue;
        }
        out.append(k.clone(), v.clone());
    }
    match inject {
        Inject::Bearer => {
            out.insert(AUTHORIZATION, sensitive(format!("Bearer {value}"))?);
        }
        Inject::Header { name } => {
            let n = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "invalid header name")?;
            out.insert(n, sensitive(value.to_string())?);
        }
        Inject::Basic => {
            let enc = base64::engine::general_purpose::STANDARD.encode(value);
            out.insert(AUTHORIZATION, sensitive(format!("Basic {enc}"))?);
        }
        Inject::Query { .. } => {}
        // A database login is never sent as an HTTP header.
        Inject::Postgres => return Err("not an HTTP credential".into()),
    }
    Ok(out)
}

pub fn strip_hop_by_hop(h: &mut HeaderMap) {
    for n in HOP_BY_HOP {
        h.remove(*n);
    }
}
