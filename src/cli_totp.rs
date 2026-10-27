// cli_totp.rs — `kepr totp NAME` (agent vault P5.5): print the current
// RFC 6238 code for a stored TOTP seed. The stored value may be a bare
// base32 seed (as shown by sites during 2FA setup) or an otpauth:// URI;
// SHA1, 30-second steps and 6 digits unless the URI says otherwise.

use hmac::{Hmac, KeyInit, Mac};
use kepr_core::protocol::Response;
use zeroize::Zeroizing;

use crate::cli_exec::{CredFetcher, DaemonFetcher};

#[derive(Debug, PartialEq, Eq)]
pub struct TotpParams {
    pub digits: u32,
    pub period: u64,
}

/// RFC 4648 base32 decode; ignores spaces, '-' and padding, any case.
pub fn base32_decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    let (mut buf, mut bits) = (0u64, 0u32);
    for c in s.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Split a stored value into (base32 secret, params).
pub fn parse_seed(stored: &str) -> Result<(Zeroizing<String>, TotpParams), String> {
    let mut p = TotpParams {
        digits: 6,
        period: 30,
    };
    let Some(rest) = stored.trim().strip_prefix("otpauth://totp/") else {
        return Ok((Zeroizing::new(stored.trim().to_string()), p));
    };
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or_default();
    let mut secret = None;
    for kv in query.split('&') {
        match kv.split_once('=') {
            Some(("secret", v)) => secret = Some(Zeroizing::new(v.to_string())),
            Some(("digits", v)) => p.digits = v.parse().map_err(|_| "bad digits")?,
            Some(("period", v)) => p.period = v.parse().map_err(|_| "bad period")?,
            Some(("algorithm", v)) if !v.eq_ignore_ascii_case("SHA1") => {
                return Err(format!("unsupported TOTP algorithm {v} (only SHA1)"))
            }
            _ => {}
        }
    }
    if !(6..=8).contains(&p.digits) || p.period == 0 {
        return Err("TOTP digits must be 6-8 and period > 0".into());
    }
    Ok((secret.ok_or("otpauth URI has no secret")?, p))
}

/// RFC 6238 / RFC 4226 code for `key` at unix time `now`.
pub fn code(key: &[u8], now: u64, p: &TotpParams) -> String {
    let counter = (now / p.period).to_be_bytes();
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(&counter);
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    format!(
        "{:0width$}",
        bin % 10u32.pow(p.digits),
        width = p.digits as usize
    )
}

pub fn cmd_totp(name: &str) -> Response {
    let stored = match DaemonFetcher.fetch(&name.to_uppercase()) {
        Ok(v) => v,
        Err(e) => return Response::fail(e),
    };
    let (secret, params) = match parse_seed(stored.as_str()) {
        Ok(x) => x,
        Err(e) => return Response::fail(e),
    };
    let Some(key) = base32_decode(&secret) else {
        return Response::fail("stored value is not a base32 TOTP seed or otpauth:// URI");
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("{}", code(&key, now, &params));
    eprintln!("(valid for {}s)", params.period - now % params.period);
    Response::Pong
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 Appendix B, SHA1 seed "12345678901234567890", 8 digits.
        let key = b"12345678901234567890";
        let p8 = TotpParams {
            digits: 8,
            period: 30,
        };
        for (t, want) in [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1234567890, "89005924"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(code(key, t, &p8), want, "t={t}");
        }
        assert_eq!(
            code(
                key,
                59,
                &TotpParams {
                    digits: 6,
                    period: 30
                }
            ),
            "287082"
        );
    }

    #[test]
    fn base32_and_uri() {
        // "12345678901234567890" in base32
        let b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(&base32_decode(b32).unwrap()[..], b"12345678901234567890");
        assert_eq!(
            &base32_decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap()[..],
            b"12345678901234567890"
        );
        assert!(base32_decode("not base32!").is_none());
        let (s, p) = parse_seed(&format!(
            "otpauth://totp/x:y?secret={b32}&digits=8&issuer=x"
        ))
        .unwrap();
        assert_eq!((s.as_str(), p.digits), (b32, 8));
        assert!(parse_seed("otpauth://totp/x?secret=A&algorithm=SHA256").is_err());
        assert_eq!(parse_seed(" ABC ").unwrap().0.as_str(), "ABC");
    }
}
