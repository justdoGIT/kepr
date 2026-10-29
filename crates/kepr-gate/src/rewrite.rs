//! Request/response rewriting for the forwarding proxy: find
//! placeholders, build the upstream query and headers with the real
//! credential, strip hop-by-hop headers.

use base64::Engine;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use kepr_core::binding::Inject;
use zeroize::Zeroizing;

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
            } else if let Some(ph) = basic_placeholder(s) {
                out.push(ph);
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

/// `(user, password)` of a `Basic base64(user:password)` header. Only
/// ever called on the agent's own headers, which carry placeholders.
fn basic_parts(header: &str) -> Option<(String, String)> {
    let (scheme, b64) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// T2.04: the placeholder in `Basic base64(user:placeholder)` (docker
/// and registry clients log in this way).
pub fn basic_placeholder(header: &str) -> Option<String> {
    let (_, pass) = basic_parts(header)?;
    pass.starts_with(PREFIX).then_some(pass)
}

/// T12.05: the user part of a `Basic` header, for `Inject::BasicPassword`.
pub fn basic_user(header: &str) -> Option<String> {
    basic_parts(header).map(|(user, _)| user)
}

/// The user `Inject::BasicPassword` sends: the agent's own Basic user,
/// else `x-access-token` (what GitHub expects with a token).
fn basic_password_user(src: &HeaderMap) -> String {
    src.get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(basic_user)
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "x-access-token".to_string())
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
        let carries_placeholder = v
            .to_str()
            .is_ok_and(|s| s.contains(PREFIX) || basic_placeholder(s).is_some());
        if HOP_BY_HOP.contains(&name)
            || name == "host"
            || name == "content-length"
            || name == "accept-encoding"
            || carries_placeholder
        {
            continue;
        }
        out.append(k.clone(), v.clone());
    }
    // Uncompressed responses: the token meter reads provider `usage`
    // fields from the bytes, which compression would hide.
    out.insert(
        hyper::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
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
        Inject::BasicPassword => {
            let login = Zeroizing::new(format!("{}:{value}", basic_password_user(src)));
            let enc = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*login));
            out.insert(AUTHORIZATION, sensitive(format!("Basic {}", *enc))?);
        }
        Inject::Query { .. } => {}
        // A database login is never sent as an HTTP header; an AWS key
        // signs requests instead (sigv4_resign.rs); a GitHub App key is
        // swapped for an installation token first (github_app.rs), a
        // Google credential for an access token (T12.09).
        Inject::Postgres
        | Inject::Redis
        | Inject::Mysql
        | Inject::Sigv4
        | Inject::GithubApp { .. }
        | Inject::GcpToken { .. }
        // A kube login is a record; kube.rs takes the token out of it.
        | Inject::KubeToken => return Err("not an HTTP credential".into()),
    }
    Ok(out)
}

/// Response headers for the agent: hop-by-hop removed and, for a query
/// injected key, that parameter cut out of any `Location` (a redirect
/// would otherwise hand the real key back to the agent).
pub fn clean_response(h: &mut HeaderMap, inject: &Inject) {
    strip_hop_by_hop(h);
    let Inject::Query { param } = inject else {
        return;
    };
    let Some(loc) = h.get(hyper::header::LOCATION).and_then(|v| v.to_str().ok()) else {
        return;
    };
    let cleaned = match loc.split_once('?') {
        Some((base, q)) => {
            let kept: Vec<&str> = q
                .split('&')
                .filter(|kv| kv.split('=').next() != Some(param.as_str()))
                .collect();
            match kept.is_empty() {
                true => base.to_string(),
                false => format!("{base}?{}", kept.join("&")),
            }
        }
        None => return,
    };
    match HeaderValue::from_str(&cleaned) {
        Ok(v) => {
            h.insert(hyper::header::LOCATION, v);
        }
        Err(_) => {
            h.remove(hyper::header::LOCATION);
        }
    }
}

pub fn strip_hop_by_hop(h: &mut HeaderMap) {
    for n in HOP_BY_HOP {
        h.remove(*n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_never_carry_a_query_injected_key() {
        let inject = Inject::Query {
            param: "key".into(),
        };
        let mut h = HeaderMap::new();
        h.insert(
            hyper::header::LOCATION,
            HeaderValue::from_static("https://api.example/v1/x?alt=json&key=REAL-SECRET"),
        );
        clean_response(&mut h, &inject);
        assert_eq!(
            h[hyper::header::LOCATION],
            "https://api.example/v1/x?alt=json"
        );
        h.insert(
            hyper::header::LOCATION,
            HeaderValue::from_static("https://api.example/v1/?key=REAL-SECRET"),
        );
        clean_response(&mut h, &inject);
        assert_eq!(h[hyper::header::LOCATION], "https://api.example/v1/");
    }

    #[test]
    fn placeholders_inside_basic_credentials() {
        let ph = "kepr-ph-0123456789abcdef-0001-0011223344556677";
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("me:{ph}"));
        let mut src = HeaderMap::new();
        let basic = HeaderValue::from_str(&format!("Basic {enc}")).unwrap();
        src.insert(AUTHORIZATION, basic);
        src.insert("x-other", HeaderValue::from_static("ok"));
        assert_eq!(placeholders_in(&src, None), [ph]);
        let out = upstream_headers(&src, &Inject::Header { name: "x-k".into() }, "REAL").unwrap();
        assert!(
            out.get(AUTHORIZATION).is_none(),
            "the placeholder login is dropped"
        );
        assert_eq!(out["x-k"], "REAL");
        let out = upstream_headers(&src, &Inject::Basic, "user:REAL").unwrap();
        let want = base64::engine::general_purpose::STANDARD.encode("user:REAL");
        assert_eq!(out[AUTHORIZATION], format!("Basic {want}").as_str());
        for other in ["Basic !!!", "Basic bWU6cGFzcw==", "Bearer x", "basic"] {
            assert_eq!(basic_placeholder(other), None, "{other}");
        }
    }

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    fn with_auth(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_str(v).unwrap());
        h
    }

    const PH: &str = "kepr-ph-0123456789abcdef-0001-0011223344556677";

    #[test]
    fn basic_password_keeps_the_clients_user_name() {
        let src = with_auth(&format!("Basic {}", b64(&format!("alice:{PH}"))));
        assert_eq!(
            basic_user(src[AUTHORIZATION].to_str().unwrap()),
            Some("alice".into())
        );
        let out = upstream_headers(&src, &Inject::BasicPassword, "REAL").unwrap();
        let auth = &out[AUTHORIZATION];
        assert_eq!(auth, format!("Basic {}", b64("alice:REAL")).as_str());
        assert!(auth.is_sensitive());
        assert_eq!(
            out.get_all(AUTHORIZATION).iter().count(),
            1,
            "placeholder gone"
        );
        assert!(!format!("{out:?}").contains(PH));
    }

    #[test]
    fn basic_password_without_a_basic_user_uses_x_access_token() {
        let want = format!("Basic {}", b64("x-access-token:REAL"));
        for src in [
            with_auth(&format!("Bearer {PH}")),
            with_auth(&format!("Basic {}", b64(&format!(":{PH}")))),
            HeaderMap::new(),
        ] {
            let out = upstream_headers(&src, &Inject::BasicPassword, "REAL").unwrap();
            assert_eq!(out[AUTHORIZATION], want.as_str());
        }
        assert_eq!(basic_user("Bearer x"), None);
        assert_eq!(basic_user("Basic !!!"), None);
        let not_utf8 = base64::engine::general_purpose::STANDARD.encode([0xff, b':', b'x']);
        assert_eq!(basic_user(&format!("Basic {not_utf8}")), None);
    }

    #[test]
    fn upstream_always_asks_for_identity_encoding() {
        let mut src = HeaderMap::new();
        src.insert(
            hyper::header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, br"),
        );
        let out = upstream_headers(&src, &Inject::Bearer, "k").unwrap();
        assert_eq!(out[hyper::header::ACCEPT_ENCODING], "identity");
    }
}
