// x509_build.rs — the few X.509 / PKCS#8 structures the local PKI needs
// (T10.10, T10.11), DER-encoded by hand: ECDSA P-256 certificates with a
// CN subject, SANs (DNS, IP, URI), basic constraints, key usage, extended
// key usage and key identifiers; and PKCS#8 for a P-256 private key.
//
// Why not rcgen: it needs `time`, whose versions without RUSTSEC-2026-0009
// need Rust 1.88, above this crate's MSRV. Signing is the caller's (a
// closure), so this module holds no key material and does no crypto beyond
// the SHA-1 key identifier.

use sha1::{Digest, Sha1};

// ── DER primitives ──────────────────────────────────────────────────────

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// A non-negative INTEGER from big-endian bytes.
fn integer(be: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = be.iter().copied().skip_while(|x| *x == 0).collect();
    if b.is_empty() || b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

fn bit_string(bytes: &[u8], unused: u8) -> Vec<u8> {
    let mut c = vec![unused];
    c.extend_from_slice(bytes);
    tlv(0x03, &c)
}

fn octets(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

/// Days since 1970-01-01 → (year, month, day) (H. Hinnant's algorithm).
pub(crate) fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// UTCTime before 2050, GeneralizedTime from then on (RFC 5280 4.1.2.5).
fn time(unix: u64) -> Vec<u8> {
    let secs = unix as i64;
    let (y, mo, d) = civil(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    let (h, mi, se) = (s / 3600, s % 3600 / 60, s % 60);
    if (1950..2050).contains(&y) {
        let t = format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{se:02}Z", y % 100);
        tlv(0x17, t.as_bytes())
    } else {
        let t = format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{se:02}Z");
        tlv(0x18, t.as_bytes())
    }
}

/// `CN=cn` (empty Name for `None`).
fn name(cn: Option<&str>) -> Vec<u8> {
    match cn {
        None => seq(&[]),
        Some(cn) => seq(&[tlv(
            0x31,
            &seq(&[oid(COMMON_NAME), tlv(0x0c, cn.as_bytes())]),
        )]),
    }
}

fn spki(point: &[u8]) -> Vec<u8> {
    seq(&[
        seq(&[oid(EC_PUBLIC_KEY), oid(PRIME256V1)]),
        bit_string(point, 0),
    ])
}

/// RFC 5280 key identifier (method 1: SHA-1 of the public key bits).
pub fn key_id(point: &[u8]) -> Vec<u8> {
    Sha1::digest(point).to_vec()
}

fn ext(id: &[u8], critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut parts = vec![oid(id)];
    if critical {
        parts.push(vec![0x01, 0x01, 0xff]);
    }
    parts.push(octets(&value));
    seq(&parts)
}

/// KeyUsage bits (0 = digitalSignature … 6 = cRLSign) as a DER BIT STRING.
fn key_usage(bits: &[u8]) -> Vec<u8> {
    let mut byte = 0u8;
    for b in bits {
        byte |= 0x80 >> b;
    }
    let unused = byte.trailing_zeros().min(7) as u8;
    bit_string(&[byte], unused)
}

pub const KU_DIGITAL_SIGNATURE: u8 = 0;
pub const KU_KEY_AGREEMENT: u8 = 4;
pub const KU_KEY_CERT_SIGN: u8 = 5;
pub const KU_CRL_SIGN: u8 = 6;

/// A subject alternative name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum San {
    Dns(String),
    Ip(std::net::IpAddr),
    Uri(String),
}

impl San {
    /// An IP address if `s` parses as one, a DNS name otherwise.
    pub fn host(s: &str) -> Self {
        s.parse().map_or_else(|_| San::Dns(s.to_string()), San::Ip)
    }

    fn der(&self) -> Vec<u8> {
        match self {
            San::Dns(d) => tlv(0x82, d.as_bytes()),
            San::Uri(u) => tlv(0x86, u.as_bytes()),
            San::Ip(std::net::IpAddr::V4(a)) => tlv(0x87, &a.octets()),
            San::Ip(std::net::IpAddr::V6(a)) => tlv(0x87, &a.octets()),
        }
    }
}

/// What goes into one certificate.
pub struct CertSpec<'a> {
    pub serial: &'a [u8],
    pub issuer_cn: &'a str,
    /// `None`: empty subject (the SAN extension is then critical).
    pub subject_cn: Option<&'a str>,
    pub not_before: u64,
    pub not_after: u64,
    /// Uncompressed P-256 points.
    pub public_key: &'a [u8],
    pub issuer_public_key: &'a [u8],
    /// `Some(pathlen)` for a CA.
    pub ca_path_len: Option<u8>,
    pub key_usage: &'a [u8],
    pub server_auth: bool,
    pub client_auth: bool,
    pub sans: &'a [San],
}

/// The DER TBSCertificate, ready to be signed.
pub fn tbs_certificate(c: &CertSpec<'_>) -> Vec<u8> {
    let mut exts = Vec::new();
    let bc = match c.ca_path_len {
        Some(n) => seq(&[vec![0x01, 0x01, 0xff], integer(&[n])]),
        None => seq(&[]),
    };
    exts.push(ext(BASIC_CONSTRAINTS, true, bc));
    exts.push(ext(KEY_USAGE, true, key_usage(c.key_usage)));
    let ekus: Vec<Vec<u8>> = [(c.server_auth, SERVER_AUTH), (c.client_auth, CLIENT_AUTH)]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, o)| oid(o))
        .collect();
    if !ekus.is_empty() {
        exts.push(ext(EXT_KEY_USAGE, false, seq(&ekus)));
    }
    if !c.sans.is_empty() {
        let names: Vec<Vec<u8>> = c.sans.iter().map(San::der).collect();
        exts.push(ext(SUBJECT_ALT_NAME, c.subject_cn.is_none(), seq(&names)));
    }
    exts.push(ext(SUBJECT_KEY_ID, false, octets(&key_id(c.public_key))));
    exts.push(ext(
        AUTHORITY_KEY_ID,
        false,
        seq(&[tlv(0x80, &key_id(c.issuer_public_key))]),
    ));
    seq(&[
        tlv(0xa0, &integer(&[2])),
        integer(c.serial),
        seq(&[oid(ECDSA_SHA256)]),
        name(Some(c.issuer_cn)),
        seq(&[time(c.not_before), time(c.not_after)]),
        name(c.subject_cn),
        spki(c.public_key),
        tlv(0xa3, &seq(&exts)),
    ])
}

/// Certificate = TBS + algorithm + the DER ECDSA signature over the TBS.
pub fn certificate(tbs: &[u8], ecdsa_sig_der: &[u8]) -> Vec<u8> {
    seq(&[
        tbs.to_vec(),
        seq(&[oid(ECDSA_SHA256)]),
        bit_string(ecdsa_sig_der, 0),
    ])
}

/// PKCS#8 (RFC 5958 v1) for a P-256 key: scalar and public point.
/// Returns the DER; the caller keeps it in a zeroizing buffer.
pub fn pkcs8_p256(scalar: &[u8; 32], point: &[u8]) -> Vec<u8> {
    let ec_private_key = seq(&[
        integer(&[1]),
        octets(scalar),
        tlv(0xa1, &bit_string(point, 0)),
    ]);
    seq(&[
        integer(&[0]),
        seq(&[oid(EC_PUBLIC_KEY), oid(PRIME256V1)]),
        octets(&ec_private_key),
    ])
}

/// PEM armour, 64 columns.
pub fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_lengths_and_integers() {
        assert_eq!(tlv(0x04, &[1, 2]), [0x04, 2, 1, 2]);
        let long = tlv(0x04, &[0u8; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(integer(&[0x00, 0x7f]), [0x02, 1, 0x7f]);
        assert_eq!(integer(&[0x80]), [0x02, 2, 0x00, 0x80]);
        assert_eq!(integer(&[]), [0x02, 1, 0x00]);
    }

    #[test]
    fn times_switch_to_generalized_in_2050() {
        assert_eq!(time(0), tlv(0x17, b"700101000000Z"));
        // 2026-10-08 12:34:56 UTC
        assert_eq!(time(1_791_462_896), tlv(0x17, b"261008123456Z"));
        // 2050-01-01 00:00:00 UTC
        assert_eq!(time(2_524_608_000), tlv(0x18, b"20500101000000Z"));
        assert_eq!(civil(-1), (1969, 12, 31));
        assert_eq!(civil(11_016), (2000, 2, 29));
    }

    #[test]
    fn key_usage_bits() {
        assert_eq!(
            key_usage(&[KU_KEY_CERT_SIGN, KU_CRL_SIGN]),
            [0x03, 2, 1, 0x06]
        );
        assert_eq!(
            key_usage(&[KU_DIGITAL_SIGNATURE, KU_KEY_AGREEMENT]),
            [0x03, 2, 3, 0x88]
        );
    }

    #[test]
    fn sans_and_pem() {
        assert_eq!(San::host("10.0.0.1").der(), [0x87, 4, 10, 0, 0, 1]);
        assert_eq!(San::host("a.b").der(), [0x82, 3, b'a', b'.', b'b']);
        assert_eq!(San::Uri("x".into()).der(), [0x86, 1, b'x']);
        let p = pem("CERTIFICATE", &[0u8; 100]);
        assert!(p.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(p.lines().all(|l| l.len() <= 64));
        assert!(p.ends_with("-----END CERTIFICATE-----\n"));
    }
}
