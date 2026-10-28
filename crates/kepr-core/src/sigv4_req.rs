//! Generic SigV4 signing (batch `aws`: T7.06, T2.02).
//!
//! `sigv4.rs` signs the one JSON-target request shape `kepr sync` sends.
//! This module signs any request: the Query API that STS and IAM speak
//! (T7.06), and requests an agent's SDK signed with a placeholder secret
//! that the gate checks and signs again with the real key (T2.02).
//!
//! The canonical request is built from parts the caller has already put
//! in canonical form (`canonical_uri`, `canonical_query` help with that),
//! so the same code verifies a signature and makes a new one.

use zeroize::Zeroizing;

use crate::generate::ZeroString;
use crate::sigv4::{hex, hmac};

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// `x-amz-content-sha256` for a body that is not hashed into the signature.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// A request reduced to what SigV4 signs.
pub struct Canonical<'a> {
    pub method: &'a str,
    /// Canonical URI (see `canonical_uri`).
    pub uri: &'a str,
    /// Canonical query string (see `canonical_query`).
    pub query: &'a str,
    /// The signed headers: lowercase names; values are trimmed here.
    pub headers: &'a [(String, String)],
    /// Hex SHA-256 of the body, or `UNSIGNED-PAYLOAD` (or another value
    /// the client put in `x-amz-content-sha256`).
    pub payload_hash: &'a str,
}

/// Where a signature is valid: `date` is `YYYYMMDD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub date: String,
    pub region: String,
    pub service: String,
}

impl Scope {
    pub fn text(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date, self.region, self.service
        )
    }
}

/// SigV4 value encoding: every byte but `A-Za-z0-9-_.~` as `%XX`
/// (upper-case hex); `/` kept when `keep_slash`.
pub fn aws_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Percent-decode (`+` stays a plus: SigV4 clients encode spaces as %20).
pub fn pct_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex_at = |j: usize| b.get(j).copied().map(|c| (c as char).to_digit(16));
        match (b[i], hex_at(i + 1), hex_at(i + 2)) {
            (b'%', Some(Some(h)), Some(Some(l))) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// The canonical URI of a request path as sent on the wire. S3 signs the
/// path as sent; every other service normalises dot segments and encodes
/// the (already encoded) path once more.
pub fn canonical_uri(path: &str, service: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    if service == "s3" {
        return path.to_string();
    }
    let mut segs: Vec<&str> = Vec::new();
    for seg in path.split('/').skip(1) {
        match seg {
            "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    aws_encode(&format!("/{}", segs.join("/")), true)
}

/// The canonical query string: each name and value decoded and encoded
/// again the SigV4 way, sorted by name, then value.
pub fn canonical_query(raw: &str) -> String {
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let enc = |s: &str| aws_encode(&String::from_utf8_lossy(&pct_decode(s)), false);
            (enc(k), enc(v))
        })
        .collect();
    pairs.sort();
    let parts: Vec<String> = pairs.into_iter().map(|(k, v)| format!("{k}={v}")).collect();
    parts.join("&")
}

fn trim_value(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Canonical<'_> {
    /// `(canonical request, signed header list)`.
    pub fn build(&self) -> (String, String) {
        let mut hs: Vec<(String, String)> = self
            .headers
            .iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), trim_value(v)))
            .collect();
        hs.sort_by(|a, b| a.0.cmp(&b.0));
        let mut canon_headers = String::new();
        for (n, v) in &hs {
            canon_headers.push_str(&format!("{n}:{v}\n"));
        }
        let signed: Vec<&str> = hs.iter().map(|(n, _)| n.as_str()).collect();
        let signed = signed.join(";");
        let text = format!(
            "{}\n{}\n{}\n{canon_headers}\n{signed}\n{}",
            self.method, self.uri, self.query, self.payload_hash
        );
        (text, signed)
    }
}

fn string_to_sign(amz_date: &str, scope: &Scope, canonical_request: &str) -> String {
    let hash = hex(&crate::mac::sha256(&[canonical_request.as_bytes()]));
    format!("{ALGORITHM}\n{amz_date}\n{}\n{hash}", scope.text())
}

fn signing_key(secret: &str, scope: &Scope) -> Zeroizing<Vec<u8>> {
    let mut k = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
    k.extend_from_slice(b"AWS4");
    k.extend_from_slice(secret.as_bytes());
    let k = hmac(&k, scope.date.as_bytes());
    let k = hmac(&k, scope.region.as_bytes());
    let k = hmac(&k, scope.service.as_bytes());
    hmac(&k, b"aws4_request")
}

/// Hex signature of `canonical_request` under `secret`.
pub fn signature(secret: &str, amz_date: &str, scope: &Scope, canonical_request: &str) -> String {
    let sts = string_to_sign(amz_date, scope, canonical_request);
    hex(&hmac(&signing_key(secret, scope), sts.as_bytes()))
}

/// Constant-time check of a hex signature.
pub fn signature_matches(
    secret: &str,
    amz_date: &str,
    scope: &Scope,
    canonical_request: &str,
    sig_hex: &str,
) -> bool {
    let Some(want) = hex_decode(sig_hex) else {
        return false;
    };
    let sts = string_to_sign(amz_date, scope, canonical_request);
    // `hmac_sha256_verify` takes truncated tags; a signature is all 32 bytes.
    want.len() == 32
        && crate::mac::hmac_sha256_verify(&signing_key(secret, scope), &[sts.as_bytes()], &want)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() & 1 == 1 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The `Authorization` header value.
pub fn authorization(access_key_id: &str, scope: &Scope, signed: &str, sig: &str) -> String {
    format!(
        "{ALGORITHM} Credential={access_key_id}/{}, SignedHeaders={signed}, Signature={sig}",
        scope.text()
    )
}

/// An AWS access key as kepr stores it: a JSON object
/// `{"access_key_id","secret_access_key","session_token"?}`.
pub struct AwsKey {
    pub access_key_id: String,
    pub secret_access_key: ZeroString,
    pub session_token: Option<ZeroString>,
}

impl AwsKey {
    /// Parse a stored value. Errors never quote it.
    pub fn parse(value: &str) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        struct Raw {
            access_key_id: String,
            secret_access_key: ZeroString,
            #[serde(default)]
            session_token: Option<ZeroString>,
        }
        let bad =
            "an AWS key must be JSON {\"access_key_id\",\"secret_access_key\",\"session_token\"?}";
        let r: Raw = serde_json::from_str(value).map_err(|_| bad.to_string())?;
        let id_ok = (16..=128).contains(&r.access_key_id.len())
            && r.access_key_id.bytes().all(|b| b.is_ascii_alphanumeric());
        if !id_ok || r.secret_access_key.is_empty() {
            return Err(bad.to_string());
        }
        Ok(Self {
            access_key_id: r.access_key_id,
            secret_access_key: r.secret_access_key,
            session_token: r.session_token.filter(|t| !t.is_empty()),
        })
    }

    /// The JSON form `parse` reads (for storing a new key).
    pub fn to_json(&self) -> ZeroString {
        let mut v = serde_json::json!({
            "access_key_id": self.access_key_id,
            "secret_access_key": self.secret_access_key.as_str(),
        });
        if let Some(t) = &self.session_token {
            v["session_token"] = serde_json::Value::String(t.as_str().to_string());
        }
        let s = ZeroString::from_string(v.to_string());
        if let serde_json::Value::Object(mut m) = v {
            for (_, val) in m.iter_mut() {
                if let serde_json::Value::String(s) = val {
                    zeroize::Zeroize::zeroize(s);
                }
            }
        }
        s
    }
}

impl std::fmt::Debug for AwsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AwsKey({}, <redacted>)", self.access_key_id)
    }
}

/// The access key id an agent session uses with its placeholder secret
/// (T2.02): `KEPRPH` + 14 base32 chars derived from the placeholder, so
/// it is shaped like an AWS key id and both the CLI and the gate can
/// compute it.
pub fn placeholder_access_key_id(placeholder: &str) -> String {
    const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let d = crate::mac::sha256(&[b"kepr-sigv4-akid\0", placeholder.as_bytes()]);
    let mut bits: u128 = 0;
    for b in &d[..9] {
        bits = (bits << 8) | u128::from(*b);
    }
    let mut out = String::from("KEPRPH");
    for i in (0..14).rev() {
        out.push(B32[((bits >> (i * 5)) & 31) as usize] as char);
    }
    out
}

/// A region name: 1-32 of `a-z 0-9 -` (it becomes part of a host name).
pub fn valid_region(r: &str) -> bool {
    (1..=32).contains(&r.len())
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const DATE: &str = "20150830T123600Z";

    fn scope() -> Scope {
        Scope {
            date: "20150830".into(),
            region: "us-east-1".into(),
            service: "service".into(),
        }
    }

    fn hdrs(h: &[(&str, &str)]) -> Vec<(String, String)> {
        h.iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    fn sign(method: &str, query: &str, h: &[(&str, &str)], body: &[u8]) -> (String, String) {
        let headers = hdrs(h);
        let hash = hex(&crate::mac::sha256(&[body]));
        let c = Canonical {
            method,
            uri: "/",
            query,
            headers: &headers,
            payload_hash: &hash,
        };
        let (text, signed) = c.build();
        (signature(SECRET, DATE, &scope(), &text), signed)
    }

    // AWS SigV4 test suite vectors (aws-sig-v4-test-suite).
    #[test]
    fn get_vanilla_matches_the_aws_suite() {
        let h = [("Host", "example.amazonaws.com"), ("X-Amz-Date", DATE)];
        let (sig, signed) = sign("GET", "", &h, b"");
        assert_eq!(signed, "host;x-amz-date");
        assert_eq!(
            sig,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn post_form_urlencoded_matches_the_aws_suite() {
        let h = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Host", "example.amazonaws.com"),
            ("X-Amz-Date", DATE),
        ];
        let (sig, signed) = sign("POST", "", &h, b"Param1=value1");
        assert_eq!(signed, "content-type;host;x-amz-date");
        assert_eq!(
            sig,
            "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"
        );
        let auth = authorization("AKIDEXAMPLE", &scope(), &signed, &sig);
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"
        );
    }

    #[test]
    fn query_order_matches_the_aws_suite() {
        let q = canonical_query("Param2=value2&Param1=value1");
        assert_eq!(q, "Param1=value1&Param2=value2");
        let h = [("Host", "example.amazonaws.com"), ("X-Amz-Date", DATE)];
        let (sig, _) = sign("GET", &q, &h, b"");
        assert_eq!(
            sig,
            "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        );
    }

    #[test]
    fn signature_check_is_exact() {
        let h = hdrs(&[("host", "example.amazonaws.com"), ("x-amz-date", DATE)]);
        let c = Canonical {
            method: "GET",
            uri: "/",
            query: "",
            headers: &h,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        let (text, _) = c.build();
        let sig = signature(SECRET, DATE, &scope(), &text);
        assert!(signature_matches(SECRET, DATE, &scope(), &text, &sig));
        assert!(!signature_matches("other", DATE, &scope(), &text, &sig));
        assert!(!signature_matches(SECRET, DATE, &scope(), &text, "zz"));
        assert!(!signature_matches(
            SECRET,
            DATE,
            &scope(),
            &text,
            &sig[..62]
        ));
    }

    #[test]
    fn uri_and_query_canonical_forms() {
        assert_eq!(canonical_uri("", "sts"), "/");
        assert_eq!(canonical_uri("/a/./b/../c", "iam"), "/a/c");
        assert_eq!(canonical_uri("/a%20b/c d", "lambda"), "/a%2520b/c%20d");
        assert_eq!(canonical_uri("/a%20b/./x", "s3"), "/a%20b/./x");
        assert_eq!(canonical_query("b=2&a=x%2Fy&a=1&c"), "a=1&a=x%2Fy&b=2&c=");
        assert_eq!(canonical_query("k=a+b~"), "k=a%2Bb~");
        assert_eq!(aws_encode("a b/c", true), "a%20b/c");
        assert_eq!(pct_decode("%zz%41"), b"%zzA");
    }

    #[test]
    fn aws_key_parses_and_never_quotes_the_value() {
        let k = AwsKey::parse(
            r#"{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"s3cr3t"}"#,
        )
        .unwrap();
        assert_eq!(k.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert!(k.session_token.is_none());
        assert!(!format!("{k:?}").contains("s3cr3t"));
        let back = AwsKey::parse(k.to_json().as_str()).unwrap();
        assert_eq!(back.secret_access_key.as_str(), "s3cr3t");
        let e =
            AwsKey::parse(r#"{"access_key_id":"x","secret_access_key":"hunter2"}"#).unwrap_err();
        assert!(!e.contains("hunter2"));
        assert!(AwsKey::parse("hunter2").unwrap_err().contains("JSON"));
    }

    #[test]
    fn placeholder_key_id_is_shaped_like_an_aws_one() {
        let a = placeholder_access_key_id("kepr-ph-0123456789abcdef-0000-0011223344556677");
        assert_eq!(a.len(), 20);
        assert!(a.starts_with("KEPRPH"));
        assert!(a
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)));
        assert_ne!(a, placeholder_access_key_id("kepr-ph-other"));
        assert!(valid_region("eu-west-2"));
        assert!(!valid_region("x@evil.com#"));
    }
}
