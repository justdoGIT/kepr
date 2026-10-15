// pki.rs — shared types and name rules for the local PKI (T10.10).
//
// The CA's private key is a sealed credential (`CA_NAME`) that `Get`
// never returns; its certificate and the list of issued certificates are
// public and live in that credential's `.meta` (`pki`). Leaf keys are made
// by the CLI: only the public key reaches the daemon, which signs.

use serde::{Deserialize, Serialize};

/// The credential holding the CA key (sealed: never returned by `Get`).
pub const CA_NAME: &str = "KEPR_PKI_CA";

/// Default and maximum leaf validity, in days.
pub const DEFAULT_LEAF_DAYS: u32 = 30;
pub const MAX_LEAF_DAYS: u32 = 825;
/// Default CA validity (10 years).
pub const DEFAULT_CA_DAYS: u32 = 3650;
/// `kepr health` warns this many days before a certificate expires.
pub const WARN_DAYS: u64 = 14;
/// At most this many subject alternative names per certificate.
pub const MAX_SANS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkiCa {
    pub cn: String,
    pub cert_pem: String,
    pub not_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkiCert {
    /// Hex serial number.
    pub serial: String,
    pub sans: Vec<String>,
    pub not_after: u64,
    pub issued_at: u64,
    /// T10.11: a SPIFFE ID when this is an X.509 SVID.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub spiffe_id: Option<String>,
}

/// The `.meta` `pki` record on `CA_NAME`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkiState {
    pub ca: PkiCa,
    #[serde(default)]
    pub issued: Vec<PkiCert>,
    /// T10.11: once enrolled, every SVID needs a TPM2 quote over PCR 7
    /// that matches this policy.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tpm: Option<TpmPolicy>,
}

/// T10.11: the attestation key and PCR 7 value SVIDs are tied to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmPolicy {
    /// Uncompressed P-256 point of the TPM attestation key (hex).
    pub ak_public: String,
    /// SHA-256 bank PCR 7 (Secure Boot state), hex.
    pub pcr7: String,
}

/// T10.11: a quote as `tpm2_quote -m MSG -s SIG` writes it (TPMS_ATTEST
/// and TPMT_SIGNATURE, both TSS-marshalled), over a daemon nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmQuote {
    pub nonce: String,
    pub attest: String,
    pub signature: String,
}

/// SVID lifetimes: default and cap (T10.11).
pub const DEFAULT_SVID_TTL: u64 = 3600;
pub const MAX_SVID_TTL: u64 = 24 * 3600;

/// A SPIFFE ID for a workload: `spiffe://TRUST-DOMAIN/PATH` (SPIFFE ID
/// spec: lower-case trust domain of `[a-z0-9._-]`, a non-empty path of
/// `[A-Za-z0-9._-]` segments, no `.`/`..` segments, no trailing `/`, no
/// port, user info, query or fragment).
pub fn validate_spiffe_id(id: &str) -> Result<(), String> {
    let bad = |why: &str| format!("not a SPIFFE ID ({why}): {id}");
    if id.len() > 2048 {
        return Err(bad("longer than 2048 bytes"));
    }
    let rest = id
        .strip_prefix("spiffe://")
        .ok_or_else(|| bad("must start with spiffe://"))?;
    let (td, path) = rest.split_once('/').ok_or_else(|| bad("needs a path"))?;
    if td.is_empty()
        || td.len() > 255
        || !td
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    {
        return Err(bad(
            "trust domain: lower-case letters, digits, '.', '-', '_'",
        ));
    }
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(bad("empty, '.' or '..' path segment"));
        }
        if !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(bad("path: letters, digits, '.', '-', '_'"));
        }
    }
    Ok(())
}

/// `90s`, `15m`, `1h`, `1d` or seconds; capped at `MAX_SVID_TTL`.
pub fn parse_svid_ttl(s: Option<&str>) -> Result<u64, String> {
    let Some(s) = s else {
        return Ok(DEFAULT_SVID_TTL);
    };
    let s = s.trim();
    let (num, mult) = match s.char_indices().last() {
        Some((i, 's')) => (&s[..i], 1),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3600),
        Some((i, 'd')) => (&s[..i], 86_400),
        _ => (s, 1),
    };
    let secs = num
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|n| *n >= 60)
        .ok_or_else(|| format!("--ttl: at least 60 s, e.g. 1h or 30m (got {s})"))?;
    if secs > MAX_SVID_TTL {
        return Err(format!("--ttl: at most {} h", MAX_SVID_TTL / 3600));
    }
    Ok(secs)
}

/// `YYYY-MM-DD` (UTC) for `kepr pki ls`.
pub fn date(unix: u64) -> String {
    let (y, m, d) = crate::x509_build::civil((unix / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// A DNS name (optionally `*.` wildcard in the first label) or an IP
/// address, in the form rcgen puts in the certificate.
pub fn validate_san(s: &str) -> Result<(), String> {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let bad = || format!("not a DNS name or IP address: {s:?}");
    let host = s.strip_prefix("*.").unwrap_or(s);
    if host.is_empty() || s.len() > 253 || host.ends_with('.') {
        return Err(bad());
    }
    for label in host.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(bad());
        }
    }
    // A bare `*.tld` wildcard would cover a whole top-level domain.
    if s.starts_with("*.") && !host.contains('.') {
        return Err(format!("wildcard too broad: {s}"));
    }
    Ok(())
}

/// Lower-cased, validated, deduplicated SANs.
pub fn normalize_sans(sans: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for s in sans {
        let s = s.trim().to_ascii_lowercase();
        validate_san(&s)?;
        if !out.contains(&s) {
            out.push(s);
        }
    }
    if out.is_empty() {
        return Err("give at least one DNS name or IP address".into());
    }
    if out.len() > MAX_SANS {
        return Err(format!("at most {MAX_SANS} names per certificate"));
    }
    Ok(out)
}

/// `kepr health` lines for certificates expiring within `WARN_DAYS` (or
/// expired in the last 30 days). Each starts with "certificate". SVIDs are
/// left out: they live an hour or so by design and are re-issued, not renewed.
pub fn expiry_issues(state: &PkiState, now: u64) -> Vec<String> {
    let day = 86_400;
    let line = |what: &str, not_after: u64| -> Option<String> {
        if not_after <= now {
            let ago = (now - not_after) / day;
            (ago <= 30).then(|| format!("certificate {what} expired {ago} day(s) ago"))
        } else {
            let left = (not_after - now).div_ceil(day);
            (left <= WARN_DAYS).then(|| format!("certificate {what} expires in {left} day(s)"))
        }
    };
    let mut out: Vec<String> = line(&format!("\"{}\"", state.ca.cn), state.ca.not_after)
        .into_iter()
        .collect();
    for c in state.issued.iter().filter(|c| c.spiffe_id.is_none()) {
        let who = c.sans.first().map(String::as_str).unwrap_or("?");
        out.extend(line(&format!("{who} (serial {})", c.serial), c.not_after));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn san_rules() {
        for ok in [
            "app.local",
            "localhost",
            "*.dev.test",
            "a-b.c1.example",
            "127.0.0.1",
            "::1",
        ] {
            assert!(validate_san(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", "*.", "*.test", "a..b", "-a.b", "a-.b", "a.b.", "A.b", "a_b.c", "a b", "*.*.x.y",
            "x.*.y",
        ] {
            assert!(validate_san(bad).is_err(), "{bad:?}");
        }
        assert!(validate_san(&format!("{}.x", "a".repeat(64))).is_err());
        assert_eq!(
            normalize_sans(&["App.Local".into(), "app.local".into(), "::1".into()]).unwrap(),
            ["app.local", "::1"]
        );
        assert!(normalize_sans(&[]).is_err());
    }

    #[test]
    fn spiffe_ids() {
        for ok in [
            "spiffe://example.org/ns/prod/sa/api",
            "spiffe://td/w",
            "spiffe://a-b_c.d/x.y-z_1/A",
        ] {
            assert!(validate_spiffe_id(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "https://example.org/x",
            "spiffe://example.org",
            "spiffe://example.org/",
            "spiffe://example.org/a/",
            "spiffe://example.org//a",
            "spiffe://example.org/./a",
            "spiffe://example.org/a/..",
            "spiffe://Example.org/a",
            "spiffe://ex:8080/a",
            "spiffe://u@ex/a",
            "spiffe://ex/a?b",
            "spiffe://ex/a#b",
            "spiffe://ex/a b",
            "spiffe:///a",
        ] {
            assert!(validate_spiffe_id(bad).is_err(), "{bad:?}");
        }
        assert!(validate_spiffe_id(&format!("spiffe://t/{}", "a".repeat(2048))).is_err());
    }

    #[test]
    fn svid_ttl_is_capped() {
        assert_eq!(parse_svid_ttl(None), Ok(3600));
        assert_eq!(parse_svid_ttl(Some("1h")), Ok(3600));
        assert_eq!(parse_svid_ttl(Some("30m")), Ok(1800));
        assert_eq!(parse_svid_ttl(Some("90")), Ok(90));
        assert_eq!(parse_svid_ttl(Some("24h")), Ok(MAX_SVID_TTL));
        assert!(parse_svid_ttl(Some("25h")).is_err());
        assert!(parse_svid_ttl(Some("2d")).is_err());
        assert!(parse_svid_ttl(Some("59s")).is_err());
        assert!(parse_svid_ttl(Some("soon")).is_err());
        assert!(parse_svid_ttl(Some("99999999999999999999h")).is_err());
    }

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_791_462_896), "2026-10-08");
    }

    #[test]
    fn expiry_tracking() {
        let day = 86_400;
        let now = 1_000 * day;
        let cert = |sans: &[&str], not_after| PkiCert {
            serial: "0a".into(),
            sans: sans.iter().map(|s| s.to_string()).collect(),
            not_after,
            issued_at: now - 10 * day,
            spiffe_id: None,
        };
        let st = PkiState {
            ca: PkiCa {
                cn: "kepr local CA".into(),
                cert_pem: String::new(),
                not_after: now + 3000 * day,
            },
            issued: vec![
                cert(&["soon.test"], now + 3 * day),
                cert(&["later.test"], now + 20 * day),
                cert(&["gone.test"], now - 2 * day),
                cert(&["old.test"], now - 40 * day),
                PkiCert {
                    spiffe_id: Some("spiffe://td/w".into()),
                    ..cert(&[], now + day / 2)
                },
            ],
            tpm: None,
        };
        let issues = expiry_issues(&st, now);
        assert_eq!(
            issues,
            [
                "certificate soon.test (serial 0a) expires in 3 day(s)",
                "certificate gone.test (serial 0a) expired 2 day(s) ago",
            ]
        );
        assert!(issues.iter().all(|i| i.starts_with("certificate")));
        let ca_soon = PkiState {
            ca: PkiCa {
                not_after: now + 14 * day,
                ..st.ca.clone()
            },
            issued: vec![],
            tpm: None,
        };
        assert_eq!(
            expiry_issues(&ca_soon, now),
            ["certificate \"kepr local CA\" expires in 14 day(s)"]
        );
    }
}
