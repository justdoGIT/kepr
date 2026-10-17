// cli_sharing/jwt.rs — OIDC ID-token verification for device
// enrolment (T6.13): JWS compact form, RS256 or ES256, against the
// issuer's JWKS, then `iss`, `aud`, `exp` / `nbf` / `iat`.
//
// Verification only (public keys): no private-key RSA operation ever
// runs here. `alg: none`, HMAC algorithms and RSA keys under 2048 bits
// are refused.

use base64::Engine;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
/// Clock skew allowed on `exp` / `nbf` / `iat`.
const LEEWAY: u64 = 60;

#[derive(serde::Deserialize, Clone, Debug)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(serde::Deserialize, Clone, Debug, Default)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(serde::Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(untagged)]
enum Aud {
    One(String),
    Many(Vec<String>),
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    aud: Aud,
    pub exp: u64,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
}

fn b64(part: &str) -> Result<Vec<u8>, String> {
    B64.decode(part)
        .map_err(|_| "malformed ID token".to_string())
}

fn field(v: &Option<String>) -> Result<Vec<u8>, String> {
    b64(v.as_deref().ok_or("JWKS key is missing a field")?)
}

fn verify_rs256(k: &Jwk, input: &[u8], sig: &[u8]) -> Result<(), String> {
    use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
    let n = field(&k.n)?;
    let n: Vec<u8> = n.iter().copied().skip_while(|b| *b == 0).collect();
    let bits = n
        .first()
        .map_or(0, |b| (n.len() - 1) * 8 + (8 - b.leading_zeros() as usize));
    if bits < 2048 {
        return Err("the IdP's RSA key is too short".into());
    }
    let e = field(&k.e)?;
    let e: Vec<u8> = e.iter().copied().skip_while(|b| *b == 0).collect();
    // Verify-only, with `ring` (already in the tree via rustls): no RSA
    // private-key operation happens in kepr.
    RsaPublicKeyComponents { n, e }
        .verify(&RSA_PKCS1_2048_8192_SHA256, input, sig)
        .map_err(|_| "ID token signature is invalid".into())
}

fn verify_es256(k: &Jwk, input: &[u8], sig: &[u8]) -> Result<(), String> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    if k.crv.as_deref() != Some("P-256") {
        return Err("JWKS key is not P-256".into());
    }
    let point = [&[4u8][..], &field(&k.x)?, &field(&k.y)?].concat();
    let key = VerifyingKey::from_sec1_bytes(&point).map_err(|_| "bad EC key in JWKS")?;
    let sig = Signature::from_slice(sig).map_err(|_| "ID token signature is invalid")?;
    key.verify(input, &sig)
        .map_err(|_| "ID token signature is invalid".into())
}

pub fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Verify `token` and return its claims, or say why it's refused.
pub fn verify_id_token(
    token: &str,
    jwks: &Jwks,
    issuer: &str,
    client_id: &str,
    now: u64,
) -> Result<Claims, String> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    let [h, p, s] = parts[..] else {
        return Err("malformed ID token".into());
    };
    let header: Header =
        serde_json::from_slice(&b64(h)?).map_err(|_| "malformed ID token header")?;
    let kty = match header.alg.as_str() {
        "RS256" => "RSA",
        "ES256" => "EC",
        other => return Err(format!("ID token algorithm {other} is not accepted")),
    };
    let candidates: Vec<&Jwk> = jwks
        .keys
        .iter()
        .filter(|k| k.kty == kty && k.alg.as_deref().is_none_or(|a| a == header.alg))
        .filter(|k| header.kid.is_none() || k.kid == header.kid)
        .collect();
    let input = format!("{h}.{p}");
    let sig = b64(s)?;
    let ok = candidates.iter().any(|k| match kty {
        "RSA" => verify_rs256(k, input.as_bytes(), &sig).is_ok(),
        _ => verify_es256(k, input.as_bytes(), &sig).is_ok(),
    });
    if candidates.is_empty() {
        return Err("no matching key in the IdP's JWKS".into());
    }
    if !ok {
        return Err("ID token signature is invalid".into());
    }
    let c: Claims = serde_json::from_slice(&b64(p)?).map_err(|_| "malformed ID token claims")?;
    if !same_issuer(&c.iss, issuer) {
        return Err(format!("ID token issuer {} is not {issuer}", c.iss));
    }
    let auds = match &c.aud {
        Aud::One(a) => vec![a.as_str()],
        Aud::Many(v) => v.iter().map(String::as_str).collect(),
    };
    let azp_ok = auds.len() == 1 || c.azp.as_deref() == Some(client_id);
    if !auds.contains(&client_id) || !azp_ok {
        return Err("ID token was issued for another client".into());
    }
    if c.exp + LEEWAY <= now {
        return Err("ID token has expired".into());
    }
    if c.nbf.is_some_and(|t| t > now + LEEWAY) || c.iat.is_some_and(|t| t > now + LEEWAY) {
        return Err("ID token is not valid yet".into());
    }
    Ok(c)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) const ISS: &str = "https://idp.example";
    pub(crate) const CLIENT: &str = "kepr-cli";
    pub(crate) const NOW: u64 = 1_800_000_000;

    pub(crate) fn claims() -> serde_json::Value {
        json!({"iss": ISS, "sub": "u-42", "aud": CLIENT, "exp": NOW + 600,
               "iat": NOW - 10, "email": "ana@example.com"})
    }

    fn jws(
        header: serde_json::Value,
        claims: &serde_json::Value,
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> String {
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = sign(input.as_bytes());
        format!("{input}.{}", B64.encode(sig))
    }

    fn rsa_fixture() -> (ring::rsa::KeyPair, Jwks) {
        use ring::signature::RsaPublicKeyComponents;
        let der = base64::engine::general_purpose::STANDARD
            .decode(include_str!("testdata/rsa2048-test-only.der.b64").trim())
            .unwrap();
        let key = ring::rsa::KeyPair::from_der(&der).unwrap();
        let pk = RsaPublicKeyComponents::<Vec<u8>>::from(key.public());
        let jwk = json!({"kty": "RSA", "kid": "r1", "alg": "RS256",
            "n": B64.encode(&pk.n), "e": B64.encode(&pk.e)});
        (
            key,
            serde_json::from_value(json!({ "keys": [jwk] })).unwrap(),
        )
    }

    fn rs256(key: &ring::rsa::KeyPair, c: &serde_json::Value) -> String {
        jws(json!({"alg": "RS256", "kid": "r1"}), c, |m| {
            let mut sig = vec![0u8; key.public().modulus_len()];
            key.sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                m,
                &mut sig,
            )
            .unwrap();
            sig
        })
    }

    pub(crate) fn es_fixture() -> (p256::ecdsa::SigningKey, Jwks) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pt = sk.verifying_key().to_sec1_point(false);
        let jwk = json!({"kty": "EC", "crv": "P-256", "kid": "e1",
            "x": B64.encode(pt.x().unwrap()), "y": B64.encode(pt.y().unwrap())});
        (
            sk,
            serde_json::from_value(json!({ "keys": [jwk] })).unwrap(),
        )
    }

    pub(crate) fn es256(sk: &p256::ecdsa::SigningKey, c: &serde_json::Value) -> String {
        use p256::ecdsa::signature::Signer;
        jws(json!({"alg": "ES256", "kid": "e1"}), c, |m| {
            let s: p256::ecdsa::Signature = sk.sign(m);
            s.to_bytes().to_vec()
        })
    }

    #[test]
    fn rs256_and_es256_tokens_verify_against_the_jwks() {
        let (rk, rjwks) = rsa_fixture();
        let c = verify_id_token(&rs256(&rk, &claims()), &rjwks, ISS, CLIENT, NOW).unwrap();
        assert_eq!(
            (c.sub.as_str(), c.email.as_deref()),
            ("u-42", Some("ana@example.com"))
        );
        let (ek, ejwks) = es_fixture();
        let c = verify_id_token(
            &es256(&ek, &claims()),
            &ejwks,
            "https://idp.example/",
            CLIENT,
            NOW,
        )
        .unwrap();
        assert_eq!(c.sub, "u-42");
        // Each key only verifies its own algorithm's tokens.
        assert!(verify_id_token(&es256(&ek, &claims()), &rjwks, ISS, CLIENT, NOW).is_err());
    }

    #[test]
    fn expired_wrong_audience_and_wrong_issuer_are_refused() {
        let (ek, jwks) = es_fixture();
        let mut c = claims();
        c["exp"] = json!(NOW - LEEWAY - 1);
        let e = verify_id_token(&es256(&ek, &c), &jwks, ISS, CLIENT, NOW).unwrap_err();
        assert!(e.contains("expired"), "{e}");
        let mut c = claims();
        c["aud"] = json!("someone-else");
        let e = verify_id_token(&es256(&ek, &c), &jwks, ISS, CLIENT, NOW).unwrap_err();
        assert!(e.contains("another client"), "{e}");
        let mut c = claims();
        c["aud"] = json!([CLIENT, "other"]); // multiple audiences need azp
        assert!(verify_id_token(&es256(&ek, &c), &jwks, ISS, CLIENT, NOW).is_err());
        c["azp"] = json!(CLIENT);
        assert!(verify_id_token(&es256(&ek, &c), &jwks, ISS, CLIENT, NOW).is_ok());
        let mut c = claims();
        c["iss"] = json!("https://evil.example");
        let e = verify_id_token(&es256(&ek, &c), &jwks, ISS, CLIENT, NOW).unwrap_err();
        assert!(e.contains("issuer"), "{e}");
        let mut c = claims();
        c["nbf"] = json!(NOW + 3600);
        assert!(verify_id_token(&es256(&ek, &c), &jwks, ISS, CLIENT, NOW).is_err());
    }

    #[test]
    fn forged_and_unsigned_tokens_are_refused() {
        let (rk, jwks) = rsa_fixture();
        let good = rs256(&rk, &claims());
        // Claims swapped under the same signature.
        let mut evil = claims();
        evil["sub"] = json!("admin");
        let parts: Vec<&str> = good.split('.').collect();
        let forged = format!("{}.{}.{}", parts[0], B64.encode(evil.to_string()), parts[2]);
        assert!(verify_id_token(&forged, &jwks, ISS, CLIENT, NOW).is_err());
        // alg none / HS256 are never accepted.
        for alg in ["none", "HS256"] {
            let t = jws(json!({ "alg": alg }), &claims(), |_| vec![]);
            assert!(verify_id_token(&t, &jwks, ISS, CLIENT, NOW).is_err());
        }
        // Unknown kid.
        let t = jws(json!({"alg": "RS256", "kid": "zz"}), &claims(), |_| vec![1]);
        assert!(verify_id_token(&t, &jwks, ISS, CLIENT, NOW).is_err());
        assert!(verify_id_token("a.b", &jwks, ISS, CLIENT, NOW).is_err());
    }
}
