//! SigV4 verify-and-re-sign (T2.02, batch: aws): the pure half.
//!
//! An `aws:<CRED>` route gives the agent a placeholder key pair: access
//! key id `KEPRPH…` (derived from the placeholder) and the session
//! placeholder as the secret. AWS CLIs and SDKs sign with it as usual. The
//! gate checks that signature with the placeholder secret (constant-time),
//! then signs the same request again with the real key: new `x-amz-date`,
//! the real key's session token, a new `Authorization`. The placeholder's
//! signature and token never go upstream. Presigned URLs, SigV4a and
//! signed streaming payloads are refused (aws_egress.rs answers 403).

use hyper::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use kepr_core::sigv4_req::{self as s4, AwsKey, Canonical, Scope};

use crate::rewrite::HOP_BY_HOP;

/// A parsed `Authorization: AWS4-HMAC-SHA256 …` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Auth {
    pub access_key_id: String,
    pub scope: Scope,
    /// Lower-case names, as listed (SigV4 lists them sorted).
    pub signed_headers: Vec<String>,
    pub signature: String,
}

fn token_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub fn parse_authorization(h: &str) -> Option<SigV4Auth> {
    let rest = h.strip_prefix(s4::ALGORITHM)?.strip_prefix(' ')?;
    let (mut cred, mut signed, mut sig) = (None, None, None);
    for part in rest.split(',') {
        match part.trim().split_once('=')? {
            ("Credential", v) => cred = Some(v),
            ("SignedHeaders", v) => signed = Some(v),
            ("Signature", v) => sig = Some(v),
            _ => return None,
        }
    }
    let c: Vec<&str> = cred?.split('/').collect();
    let [akid, date, region, service, term] = c.as_slice() else {
        return None;
    };
    let date_ok = date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit());
    if *term != "aws4_request" || !date_ok || !token_ok(akid) || !token_ok(service) {
        return None;
    }
    if !s4::valid_region(region) {
        return None;
    }
    let signed_headers: Vec<String> = signed?.split(';').map(str::to_string).collect();
    let names_ok = signed_headers.iter().all(|n| {
        !n.is_empty() && HeaderName::from_bytes(n.as_bytes()).is_ok_and(|h| h.as_str() == n)
    });
    let sig = sig?;
    let sig_ok = sig.len() == 64 && sig.bytes().all(|b| b.is_ascii_hexdigit());
    if !names_ok || !sig_ok || !signed_headers.iter().any(|n| n == "host") {
        return None;
    }
    Some(SigV4Auth {
        access_key_id: akid.to_string(),
        scope: Scope {
            date: date.to_string(),
            region: region.to_string(),
            service: service.to_string(),
        },
        signed_headers,
        signature: sig.to_ascii_lowercase(),
    })
}

/// The parts of an agent's request a signature covers.
pub struct ReqView<'a> {
    pub method: &'a str,
    /// Path and query exactly as sent on the wire.
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a HeaderMap,
    /// `x-amz-content-sha256` if sent, else the body's SHA-256.
    pub payload_hash: &'a str,
}

/// All values of `name`, trimmed and joined with `,` (SigV4's rule).
pub fn header_value(h: &HeaderMap, name: &str) -> Option<String> {
    let vals: Vec<&str> = h
        .get_all(name)
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<_, _>>()
        .ok()?;
    (!vals.is_empty()).then(|| {
        let t: Vec<&str> = vals.iter().map(|v| v.trim()).collect();
        t.join(",")
    })
}

/// Canonical request over `names`, values from `over` first, then the
/// request's own headers. `None` when a signed header is missing.
fn canonical(
    req: &ReqView,
    service: &str,
    names: &[String],
    over: &[(&str, &str)],
) -> Option<(String, String)> {
    let mut hs = Vec::with_capacity(names.len());
    for n in names {
        let v = match over.iter().find(|(k, _)| k == n) {
            Some((_, v)) => v.to_string(),
            None => header_value(req.headers, n)?,
        };
        hs.push((n.clone(), v));
    }
    let uri = s4::canonical_uri(req.path, service);
    let query = s4::canonical_query(req.query);
    let c = Canonical {
        method: req.method,
        uri: &uri,
        query: &query,
        headers: &hs,
        payload_hash: req.payload_hash,
    };
    Some(c.build())
}

/// Was `req` signed with `placeholder_secret`? Constant-time compare.
pub fn verify(req: &ReqView, auth: &SigV4Auth, placeholder_secret: &str) -> bool {
    let Some(date) = header_value(req.headers, "x-amz-date") else {
        return false;
    };
    let date_signed = auth.signed_headers.iter().any(|h| h == "x-amz-date");
    if !date_signed || date.len() != 16 || !date.starts_with(&auth.scope.date) {
        return false;
    }
    let Some((text, _)) = canonical(req, &auth.scope.service, &auth.signed_headers, &[]) else {
        return false;
    };
    s4::signature_matches(
        placeholder_secret,
        &date,
        &auth.scope,
        &text,
        &auth.signature,
    )
}

fn sensitive(v: &str) -> Result<HeaderValue, String> {
    let mut hv = HeaderValue::from_str(v).map_err(|_| "credential is not a valid header value")?;
    hv.set_sensitive(true);
    Ok(hv)
}

/// Headers for the upstream request: the agent's (minus hop-by-hop and
/// the placeholder's date, token and signature), with a fresh date, the
/// real key's session token and its signature over the same headers.
pub fn resign(
    req: &ReqView,
    auth: &SigV4Auth,
    real: &AwsKey,
    amz_date: &str,
) -> Result<HeaderMap, String> {
    let token = real.session_token.as_ref().map(|t| t.as_str());
    let mut names: Vec<String> = auth
        .signed_headers
        .iter()
        .filter(|h| *h != "x-amz-security-token")
        .cloned()
        .collect();
    let mut over = vec![("x-amz-date", amz_date)];
    if let Some(t) = token {
        names.push("x-amz-security-token".into());
        over.push(("x-amz-security-token", t));
    }
    let scope = Scope {
        date: amz_date.get(..8).ok_or("bad date")?.to_string(),
        ..auth.scope.clone()
    };
    let (text, signed) =
        canonical(req, &scope.service, &names, &over).ok_or("a signed header is missing")?;
    let sig = s4::signature(real.secret_access_key.as_str(), amz_date, &scope, &text);
    let value = s4::authorization(&real.access_key_id, &scope, &signed, &sig);

    let mut out = HeaderMap::new();
    for (k, v) in req.headers {
        let n = k.as_str();
        let replaced = matches!(
            n,
            "authorization" | "x-amz-date" | "x-amz-security-token" | "content-length"
        );
        if !HOP_BY_HOP.contains(&n) && !replaced {
            out.append(k.clone(), v.clone());
        }
    }
    let date = HeaderValue::from_str(amz_date).map_err(|_| "bad date")?;
    out.insert(HeaderName::from_static("x-amz-date"), date);
    if let Some(t) = token {
        out.insert(
            HeaderName::from_static("x-amz-security-token"),
            sensitive(t)?,
        );
    }
    out.insert(AUTHORIZATION, sensitive(&value)?);
    Ok(out)
}

/// A presigned URL (signature in the query string): refused.
pub fn presigned(query: &str) -> bool {
    query.split('&').any(|p| {
        let k = p.split('=').next().unwrap_or("").to_ascii_lowercase();
        k == "x-amz-signature" || k == "x-amz-credential"
    })
}

/// A body whose chunks are signed one by one: re-signing would mean
/// re-signing every chunk, so these are refused.
pub fn signed_streaming(payload_hash: &str) -> bool {
    payload_hash.starts_with("STREAMING-") && payload_hash != "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
}

/// Calls that turn the session's access into credentials usable without
/// the gate (temporary keys, new access keys, console passwords).
const MINTING: &[&str] = &[
    "GetSessionToken",
    "GetFederationToken",
    "AssumeRole",
    "AssumeRoleWithSAML",
    "AssumeRoleWithWebIdentity",
    "AssumeRoot",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "CreateServiceSpecificCredential",
    "ResetServiceSpecificCredential",
];

/// The API action: `X-Amz-Target`'s suffix, or `Action` in the query or
/// a form body.
pub fn action(req: &ReqView, body: &[u8]) -> Option<String> {
    if let Some(t) = header_value(req.headers, "x-amz-target") {
        return t.rsplit('.').next().map(str::to_string);
    }
    let find = |q: &str| {
        q.split('&')
            .find_map(|p| p.strip_prefix("Action="))
            .map(|v| String::from_utf8_lossy(&s4::pct_decode(v)).into_owned())
    };
    let form = header_value(req.headers, "content-type")
        .is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
    find(req.query).or_else(|| form.then(|| find(&String::from_utf8_lossy(body))).flatten())
}

pub fn mints_credentials(req: &ReqView, body: &[u8]) -> bool {
    action(req, body).is_some_and(|a| MINTING.contains(&a.as_str()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use kepr_core::generate::ZeroString;
    use kepr_core::sigv4::hex_sha256;

    pub const PH: &str = "kepr-ph-0123456789abcdef-0000-0011223344556677";
    const DATE: &str = "20150830T123600Z";

    /// Sign the way an SDK does: every header present, with `secret`.
    pub fn sdk_sign(
        method: &str,
        path: &str,
        query: &str,
        h: &mut HeaderMap,
        payload_hash: &str,
        (akid, secret): (&str, &str),
    ) {
        let mut names: Vec<String> = h.keys().map(|k| k.as_str().to_string()).collect();
        names.sort();
        names.dedup();
        let scope = Scope {
            date: DATE[..8].into(),
            region: "us-east-1".into(),
            service: "sts".into(),
        };
        let v = ReqView {
            method,
            path,
            query,
            headers: h,
            payload_hash,
        };
        let (text, signed) = canonical(&v, "sts", &names, &[]).unwrap();
        let sig = s4::signature(secret, DATE, &scope, &text);
        let auth = s4::authorization(akid, &scope, &signed, &sig);
        h.insert(AUTHORIZATION, auth.parse().unwrap());
    }

    pub fn headers(body: &[u8]) -> (HeaderMap, String) {
        let mut h = HeaderMap::new();
        h.insert("host", "sts.amazonaws.com".parse().unwrap());
        h.insert("x-amz-date", DATE.parse().unwrap());
        h.insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        (h, hex_sha256(body))
    }

    fn view<'a>(h: &'a HeaderMap, path: &'a str, hash: &'a str) -> ReqView<'a> {
        ReqView {
            method: "POST",
            path,
            query: "",
            headers: h,
            payload_hash: hash,
        }
    }

    fn real(token: Option<&str>) -> AwsKey {
        AwsKey {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: ZeroString::from("real/secret/key"),
            session_token: token.map(ZeroString::from),
        }
    }

    fn signed(body: &[u8]) -> (HeaderMap, String, SigV4Auth) {
        let akid = s4::placeholder_access_key_id(PH);
        let (mut h, hash) = headers(body);
        sdk_sign("POST", "/", "", &mut h, &hash, (&akid, PH));
        let auth = parse_authorization(h[AUTHORIZATION].to_str().unwrap()).unwrap();
        (h, hash, auth)
    }

    #[test]
    fn a_request_signed_with_the_placeholder_verifies() {
        let (h, hash, auth) = signed(b"Action=GetCallerIdentity");
        assert_eq!(auth.access_key_id, s4::placeholder_access_key_id(PH));
        assert_eq!(auth.signed_headers, ["content-type", "host", "x-amz-date"]);
        assert!(verify(&view(&h, "/", &hash), &auth, PH));
        assert!(!verify(&view(&h, "/", &hash), &auth, "kepr-ph-other"));
    }

    #[test]
    fn tampering_with_path_body_or_a_signed_header_fails() {
        let (h, hash, auth) = signed(b"Action=GetCallerIdentity");
        assert!(!verify(&view(&h, "/x", &hash), &auth, PH));
        let other = hex_sha256(b"Action=GetSessionToken");
        assert!(!verify(&view(&h, "/", &other), &auth, PH));
        let mut h2 = h.clone();
        h2.insert("host", "evil.amazonaws.com".parse().unwrap());
        assert!(!verify(&view(&h2, "/", &hash), &auth, PH));
        let mut h3 = h.clone();
        h3.remove("content-type");
        assert!(!verify(&view(&h3, "/", &hash), &auth, PH));
        // An unsigned header may change freely.
        let mut h4 = h.clone();
        h4.insert("user-agent", "aws-cli/2".parse().unwrap());
        assert!(verify(&view(&h4, "/", &hash), &auth, PH));
    }

    #[test]
    fn resigned_request_verifies_under_the_real_secret_only() {
        let (mut h, hash, auth) = signed(b"Action=GetCallerIdentity");
        h.insert("x-amz-security-token", "agent-supplied".parse().unwrap());
        h.insert("connection", "keep-alive".parse().unwrap());
        let real = real(Some("real-session-token"));
        let out = resign(&view(&h, "/", &hash), &auth, &real, "20150831T000000Z").unwrap();
        assert_eq!(out["x-amz-date"], "20150831T000000Z");
        assert_eq!(out["x-amz-security-token"], "real-session-token");
        assert!(out.get("connection").is_none());
        let a2 = parse_authorization(out[AUTHORIZATION].to_str().unwrap()).unwrap();
        assert_eq!(a2.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(a2.scope.date, "20150831");
        assert_eq!(
            a2.signed_headers,
            ["content-type", "host", "x-amz-date", "x-amz-security-token"]
        );
        let v = view(&out, "/", &hash);
        assert!(verify(&v, &a2, "real/secret/key"));
        assert!(!verify(&v, &a2, PH));
        let all = format!("{out:?}");
        assert!(!all.contains(PH) && !all.contains("agent-supplied"));
    }

    #[test]
    fn unsigned_payload_is_supported_and_signed_streaming_is_not() {
        let (mut h, _) = headers(b"");
        h.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        let akid = s4::placeholder_access_key_id(PH);
        sdk_sign("PUT", "/k", "", &mut h, "UNSIGNED-PAYLOAD", (&akid, PH));
        let auth = parse_authorization(h[AUTHORIZATION].to_str().unwrap()).unwrap();
        let v = ReqView {
            method: "PUT",
            path: "/k",
            query: "",
            headers: &h,
            payload_hash: "UNSIGNED-PAYLOAD",
        };
        assert!(verify(&v, &auth, PH));
        let out = resign(&v, &auth, &real(None), "20150830T130000Z").unwrap();
        assert_eq!(out["x-amz-content-sha256"], "UNSIGNED-PAYLOAD");
        assert!(out.get("x-amz-security-token").is_none());
        let a2 = parse_authorization(out[AUTHORIZATION].to_str().unwrap()).unwrap();
        let v2 = ReqView { headers: &out, ..v };
        assert!(verify(&v2, &a2, "real/secret/key"));
        assert!(signed_streaming("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"));
        assert!(!signed_streaming("STREAMING-UNSIGNED-PAYLOAD-TRAILER"));
        assert!(!signed_streaming("UNSIGNED-PAYLOAD"));
    }

    #[test]
    fn authorization_parsing_refuses_other_schemes() {
        let (_, _, auth) = signed(b"");
        assert_eq!(auth.scope.service, "sts");
        for bad in [
            "AWS4-ECDSA-P256-SHA256 Credential=K/20150830/sts/aws4_request, SignedHeaders=host, Signature=00",
            "Bearer x",
            "AWS4-HMAC-SHA256 Credential=K/2015/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=ab",
            "AWS4-HMAC-SHA256 Credential=K/20150830/us-east-1/sts/aws4_request, SignedHeaders=x-amz-date, \
             Signature=0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(parse_authorization(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn presigned_urls_and_credential_minting_are_recognised() {
        assert!(presigned(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=ab"
        ));
        assert!(!presigned("list-type=2&prefix=a"));
        let (h, hash) = headers(b"");
        let v = view(&h, "/", &hash);
        assert!(mints_credentials(
            &v,
            b"Action=GetSessionToken&Version=2011-06-15"
        ));
        assert!(!mints_credentials(&v, b"Action=GetCallerIdentity"));
        let mut t = HeaderMap::new();
        t.insert(
            "x-amz-target",
            "AWSSecurityTokenServiceV20110615.AssumeRole"
                .parse()
                .unwrap(),
        );
        assert!(mints_credentials(&view(&t, "/", &hash), b"{}"));
        let empty = HeaderMap::new();
        let q = ReqView {
            query: "Action=CreateAccessKey&Version=2010-05-08",
            ..view(&empty, "/", &hash)
        };
        assert!(mints_credentials(&q, b""));
    }
}
