//! GitHub App installation tokens (T7.08, batch: aws): the pure pieces
//! shared by `kepr github-app add` (checks the key) and kepr-gate (signs
//! the app JWT with `ring` and exchanges it for an installation token).
//!
//! The private key is stored sealed and bound to `api.github.com` with
//! `Inject::GithubApp`; it never leaves the gate, and neither does the
//! 1-hour installation token the gate mints with it.

use base64::Engine;
use zeroize::Zeroizing;

use crate::generate::ZeroString;

pub const API_HOST: &str = "api.github.com";

/// The DER inside a PEM private key, by its format.
pub enum KeyDer {
    /// `-----BEGIN RSA PRIVATE KEY-----` (what GitHub hands out).
    Pkcs1(Zeroizing<Vec<u8>>),
    /// `-----BEGIN PRIVATE KEY-----`.
    Pkcs8(Zeroizing<Vec<u8>>),
}

/// Decode a PEM RSA private key. Errors never quote it.
pub fn pem_der(pem: &str) -> Result<KeyDer, String> {
    let bad = || "not a PEM RSA private key".to_string();
    let (kind, rest) = [("RSA PRIVATE KEY", true), ("PRIVATE KEY", false)]
        .iter()
        .find_map(|(label, pkcs1)| {
            let begin = format!("-----BEGIN {label}-----");
            let start = pem.find(&begin)? + begin.len();
            let end = pem[start..].find(&format!("-----END {label}-----"))?;
            Some((*pkcs1, &pem[start..start + end]))
        })
        .ok_or_else(bad)?;
    let b64: Zeroizing<String> =
        Zeroizing::new(rest.chars().filter(|c| !c.is_whitespace()).collect());
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| bad())?;
    if der.is_empty() {
        return Err(bad());
    }
    Ok(if kind {
        KeyDer::Pkcs1(der)
    } else {
        KeyDer::Pkcs8(der)
    })
}

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// `b64url(header).b64url(claims)` of the app JWT: issued 60 s in the
/// past (clock drift), valid 9 minutes (GitHub allows at most 10).
pub fn jwt_signing_input(app_id: u64, now: u64) -> String {
    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let claims = serde_json::json!({
        "iat": now.saturating_sub(60),
        "exp": now + 540,
        "iss": app_id,
    });
    format!(
        "{}.{}",
        b64url(header.as_bytes()),
        b64url(claims.to_string().as_bytes())
    )
}

/// `input.b64url(signature)`.
pub fn jwt_finish(input: &str, signature: &[u8]) -> ZeroString {
    ZeroString::from_string(format!("{input}.{}", b64url(signature)))
}

/// Seconds since the epoch of `YYYY-MM-DDTHH:MM:SSZ` (GitHub's form).
pub fn rfc3339_secs(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[19] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<u64>().ok();
    let (y, mo, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (h, mi, se) = (n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    if h > 23 || mi > 59 || se > 60 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let (y, m) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se)
}

/// `(token, expires_at)` from an `access_tokens` reply.
pub fn parse_token_reply(body: &[u8]) -> Result<(ZeroString, u64), String> {
    #[derive(serde::Deserialize)]
    struct Reply {
        token: ZeroString,
        expires_at: String,
    }
    let r: Reply = serde_json::from_slice(body).map_err(|_| "GitHub reply has no token")?;
    if r.token.is_empty() || r.token.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err("GitHub reply has no usable token".into());
    }
    let exp = rfc3339_secs(&r.expires_at).ok_or("GitHub reply has no valid expires_at")?;
    Ok((r.token, exp))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// The repo's RSA test key (PKCS#1 DER, base64), as GitHub's PEM.
    pub fn fixture_pem() -> String {
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

    #[test]
    fn pem_decoding() {
        let KeyDer::Pkcs1(der) = pem_der(&fixture_pem()).unwrap() else {
            panic!("PKCS#1 expected");
        };
        assert_eq!(der[0], 0x30, "a DER SEQUENCE");
        let p8 = "-----BEGIN PRIVATE KEY-----\nMAEC\n-----END PRIVATE KEY-----";
        assert!(matches!(pem_der(p8), Ok(KeyDer::Pkcs8(_))));
        for bad in [
            "",
            "ghp_token",
            "-----BEGIN RSA PRIVATE KEY-----\n!!\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nMAEC",
        ] {
            let e = pem_der(bad).err().unwrap();
            assert_eq!(e, "not a PEM RSA private key");
        }
    }

    #[test]
    fn jwt_header_and_claims() {
        let input = jwt_signing_input(12345, 1_700_000_000);
        let (h, c) = input.split_once('.').unwrap();
        let dec = |s: &str| -> serde_json::Value {
            serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(s)
                    .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(dec(h), serde_json::json!({"alg": "RS256", "typ": "JWT"}));
        assert_eq!(
            dec(c),
            serde_json::json!({"iat": 1_699_999_940u64, "exp": 1_700_000_540u64, "iss": 12345})
        );
        assert!(!input.contains('='));
        assert_eq!(jwt_finish("a.b", &[0xfb, 0xff]).as_str(), "a.b.-_8");
    }

    #[test]
    fn token_reply_and_expiry() {
        assert_eq!(rfc3339_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_secs("2015-08-30T12:36:00Z"), Some(1_440_938_160));
        assert_eq!(rfc3339_secs("2024-02-29T23:59:59Z"), Some(1_709_251_199));
        for bad in ["2024-13-01T00:00:00Z", "2024-01-01 00:00:00Z", "soon", ""] {
            assert_eq!(rfc3339_secs(bad), None, "{bad}");
        }
        let body = br#"{"token":"ghs_16C7e42F292c6912E7710c838347Ae178B4a",
            "expires_at":"2016-07-11T22:14:10Z","permissions":{"issues":"write"}}"#;
        let (t, exp) = parse_token_reply(body).unwrap();
        assert_eq!(t.as_str(), "ghs_16C7e42F292c6912E7710c838347Ae178B4a");
        assert_eq!(exp, 1_468_275_250);
        assert!(parse_token_reply(br#"{"message":"Bad credentials"}"#).is_err());
        assert!(
            parse_token_reply(br#"{"token":"a b","expires_at":"2016-07-11T22:14:10Z"}"#).is_err()
        );
        assert!(parse_token_reply(br#"{"token":"t","expires_at":"later"}"#).is_err());
    }
}
