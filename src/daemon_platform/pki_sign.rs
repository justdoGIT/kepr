// daemon_platform/pki_sign.rs — certificate signing for the local PKI
// (T10.10, T10.11). Pure over its inputs (times, keys); pki.rs does the
// storage. The CA key is a P-256 scalar held in zeroizing buffers (p256's
// SigningKey wipes itself on drop) and only used to sign here.
//
// The CA has pathlen 0 (no intermediates). Leaves carry the caller's public
// key (an uncompressed P-256 point): the CLI makes the leaf key and keeps
// it, so a leaf private key never passes through the daemon. The DER comes
// from kepr_core::x509_build (no rcgen: see that module).

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use zeroize::Zeroizing;

use kepr_core::pki::PkiCa;
use kepr_core::x509_build::{self as x509, CertSpec, San};

/// A fresh P-256 scalar from the OS CSPRNG.
pub fn new_scalar() -> Result<Zeroizing<[u8; 32]>, String> {
    loop {
        let mut b = Zeroizing::new([0u8; 32]);
        getrandom::fill(b.as_mut()).map_err(|e| format!("CSPRNG failure: {e}"))?;
        if p256::SecretKey::from_slice(b.as_ref()).is_ok() {
            return Ok(b);
        }
    }
}

fn signing_key(scalar: &[u8]) -> Result<SigningKey, String> {
    SigningKey::from_slice(scalar).map_err(|_| "the CA key is damaged".to_string())
}

/// The uncompressed public point of a signing key.
pub fn public_point(k: &SigningKey) -> Vec<u8> {
    k.verifying_key().to_sec1_point(false).as_bytes().to_vec()
}

fn random_serial() -> Result<([u8; 16], String), String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| format!("CSPRNG failure: {e}"))?;
    b[0] = (b[0] & 0x7f) | 0x01; // positive, no leading zero byte
    Ok((b, hex::encode(b)))
}

fn sign(spec: &CertSpec<'_>, key: &SigningKey) -> String {
    let tbs = x509::tbs_certificate(spec);
    let sig: Signature = key.sign(&tbs);
    x509::pem(
        "CERTIFICATE",
        &x509::certificate(&tbs, sig.to_der().as_bytes()),
    )
}

pub struct NewCa {
    /// The CA's P-256 scalar.
    pub key: Zeroizing<[u8; 32]>,
    pub ca: PkiCa,
}

/// A fresh self-signed CA valid from an hour ago for `days`.
pub fn new_ca(cn: &str, now: u64, days: u32) -> Result<NewCa, String> {
    let key = new_scalar()?;
    let sk = signing_key(key.as_ref())?;
    let point = public_point(&sk);
    let not_after = now + u64::from(days) * 86_400;
    let (serial, _) = random_serial()?;
    let spec = CertSpec {
        serial: &serial,
        issuer_cn: cn,
        subject_cn: Some(cn),
        not_before: now.saturating_sub(3600),
        not_after,
        public_key: &point,
        issuer_public_key: &point,
        ca_path_len: Some(0),
        key_usage: &[x509::KU_KEY_CERT_SIGN, x509::KU_CRL_SIGN],
        server_auth: false,
        client_auth: false,
        sans: &[],
    };
    let cert_pem = sign(&spec, &sk);
    Ok(NewCa {
        key,
        ca: PkiCa {
            cn: cn.to_string(),
            cert_pem,
            not_after,
        },
    })
}

/// A public key as received from the CLI: an uncompressed SEC1 P-256 point.
pub struct P256Public(Vec<u8>);

impl P256Public {
    /// Hex of a SEC1 point; checked to be on the curve.
    pub fn from_hex(h: &str) -> Result<Self, String> {
        let bytes = hex::decode(h.trim()).map_err(|_| "public key: not hex".to_string())?;
        let pk = p256::PublicKey::from_sec1_bytes(&bytes)
            .map_err(|_| "public key: not a P-256 point".to_string())?;
        Ok(Self(pk.to_sec1_point(false).as_bytes().to_vec()))
    }
}

/// What goes into a leaf.
pub struct Leaf<'a> {
    /// DNS names / IP addresses (validated by kepr_core::pki).
    pub sans: &'a [String],
    /// T10.11: a `spiffe://` URI SAN; such a leaf has an empty subject.
    pub uri: Option<&'a str>,
    pub not_before: u64,
    pub not_after: u64,
}

/// Sign `leaf` for `public_key` with the CA. Returns (PEM, hex serial).
pub fn sign_leaf(
    ca: &PkiCa,
    ca_key: &[u8],
    public_key: &P256Public,
    leaf: &Leaf<'_>,
) -> Result<(String, String), String> {
    let sk = signing_key(ca_key)?;
    let ca_point = public_point(&sk);
    let mut sans: Vec<San> = leaf.sans.iter().map(|s| San::host(s)).collect();
    sans.extend(leaf.uri.map(|u| San::Uri(u.to_string())));
    let (serial, serial_hex) = random_serial()?;
    let spec = CertSpec {
        serial: &serial,
        issuer_cn: &ca.cn,
        subject_cn: if leaf.uri.is_some() {
            None
        } else {
            leaf.sans.first().map(String::as_str)
        },
        not_before: leaf.not_before,
        not_after: leaf.not_after,
        public_key: &public_key.0,
        issuer_public_key: &ca_point,
        ca_path_len: None,
        key_usage: &[x509::KU_DIGITAL_SIGNATURE, x509::KU_KEY_AGREEMENT],
        server_auth: true,
        client_auth: leaf.uri.is_some(),
        sans: &sans,
    };
    Ok((sign(&spec, &sk), serial_hex))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::process::Command;

    /// A leaf key as the CLI makes it: (scalar, hex public point).
    pub fn leaf_key() -> (Zeroizing<[u8; 32]>, String) {
        let s = new_scalar().unwrap();
        let p = public_point(&signing_key(s.as_ref()).unwrap());
        (s, hex::encode(p))
    }

    /// `openssl` is on CI runners; skip quietly where it isn't.
    pub fn openssl(args: &[&str]) -> Option<(bool, String)> {
        let out = Command::new("openssl").args(args).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        Some((out.status.success(), text))
    }

    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn issued_cert_chains_to_the_ca_with_its_sans() {
        let now = now();
        let ca = new_ca("kepr local CA (test) 0001", now, 3650).unwrap();
        assert!(ca.ca.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        let (_k, pk) = leaf_key();
        let pk = P256Public::from_hex(&pk).unwrap();
        let sans = vec!["app.local".to_string(), "127.0.0.1".to_string()];
        let leaf = Leaf {
            sans: &sans,
            uri: None,
            not_before: now - 60,
            not_after: now + 30 * 86_400,
        };
        let (pem, serial) = sign_leaf(&ca.ca, ca.key.as_ref(), &pk, &leaf).unwrap();
        assert_eq!(serial.len(), 32);
        let dir = tempfile::tempdir().unwrap();
        let (cap, leafp) = (dir.path().join("ca.pem"), dir.path().join("leaf.pem"));
        std::fs::write(&cap, &ca.ca.cert_pem).unwrap();
        std::fs::write(&leafp, &pem).unwrap();
        let (c, l) = (cap.to_str().unwrap(), leafp.to_str().unwrap());
        let Some((ok, out)) = openssl(&["verify", "-CAfile", c, "-purpose", "sslserver", l]) else {
            eprintln!("skipping chain check: openssl not installed");
            return;
        };
        assert!(ok, "openssl verify: {out}");
        let (_, text) = openssl(&["x509", "-in", l, "-noout", "-text"]).unwrap();
        assert!(text.contains("DNS:app.local"), "{text}");
        assert!(text.contains("IP Address:127.0.0.1"), "{text}");
        assert!(text.contains("CA:FALSE"), "{text}");
        let (_, catext) = openssl(&["x509", "-in", c, "-noout", "-text"]).unwrap();
        assert!(catext.contains("CA:TRUE, pathlen:0"), "{catext}");
        assert!(catext.contains("Certificate Sign, CRL Sign"), "{catext}");
        // Another CA's leaf does not chain to this one.
        let other = new_ca("kepr local CA (test) 0002", now, 3650).unwrap();
        let (pem2, _) = sign_leaf(&other.ca, other.key.as_ref(), &pk, &leaf).unwrap();
        std::fs::write(&leafp, &pem2).unwrap();
        let (ok, _) = openssl(&["verify", "-CAfile", c, l]).unwrap();
        assert!(!ok, "a foreign leaf verified");
        // Expired: rejected by the verifier.
        let past = Leaf {
            not_before: now - 10 * 86_400,
            not_after: now - 86_400,
            ..leaf
        };
        let (pem3, _) = sign_leaf(&ca.ca, ca.key.as_ref(), &pk, &past).unwrap();
        std::fs::write(&leafp, &pem3).unwrap();
        let (ok, out) = openssl(&["verify", "-CAfile", c, l]).unwrap();
        assert!(!ok && out.contains("expired"), "{out}");
    }

    #[test]
    fn rejects_bad_public_keys_and_damaged_ca_keys() {
        assert!(P256Public::from_hex("zz").is_err());
        assert!(P256Public::from_hex(&hex::encode([4u8; 65])).is_err());
        let now = now();
        let ca = new_ca("x", now, 1).unwrap();
        let (_k, pk) = leaf_key();
        let pk = P256Public::from_hex(&pk).unwrap();
        let sans = vec!["a.test".to_string()];
        let leaf = Leaf {
            sans: &sans,
            uri: None,
            not_before: now,
            not_after: now + 86_400,
        };
        assert!(sign_leaf(&ca.ca, &[0u8; 32], &pk, &leaf).is_err());
        assert!(sign_leaf(&ca.ca, b"short", &pk, &leaf).is_err());
    }
}
