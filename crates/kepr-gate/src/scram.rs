//! SCRAM-SHA-256 client (RFC 5802 / RFC 7677) for the gate's PostgreSQL
//! login (P7.1). Pure functions: the caller supplies the nonce and moves
//! the messages. Channel binding is not used (`n,,`).

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// PBKDF2-HMAC-SHA256 with one 32-byte block (RFC 8018 §5.2).
fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut block = salt.to_vec();
    block.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac(password, &block);
    let mut out = Zeroizing::new(u);
    for _ in 1..iterations {
        u = hmac(password, &u);
        for (o, b) in out.iter_mut().zip(u.iter()) {
            *o ^= b;
        }
    }
    out
}

/// One login in progress.
pub struct Scram {
    client_first_bare: String,
    nonce: String,
    password: Zeroizing<String>,
    server_signature: Option<[u8; 32]>,
}

impl Scram {
    /// `nonce`: printable, no commas (base64 of random bytes).
    pub fn new(password: &str, nonce: &str) -> Self {
        Self {
            // PostgreSQL ignores the SCRAM user name and uses the startup one.
            client_first_bare: format!("n=,r={nonce}"),
            nonce: nonce.to_string(),
            password: Zeroizing::new(password.to_string()),
            server_signature: None,
        }
    }

    pub fn client_first(&self) -> String {
        format!("n,,{}", self.client_first_bare)
    }

    /// From the server-first message, the client-final message.
    pub fn client_final(&mut self, server_first: &str) -> Result<String, String> {
        let attr = |k: &str| {
            server_first
                .split(',')
                .find_map(|a| a.strip_prefix(k))
                .ok_or_else(|| format!("SCRAM: server-first lacks {k}"))
        };
        let r = attr("r=")?;
        if !r.starts_with(&self.nonce) || r.len() == self.nonce.len() {
            return Err("SCRAM: server nonce does not extend ours".into());
        }
        let salt = B64.decode(attr("s=")?).map_err(|_| "SCRAM: bad salt")?;
        let iterations: u32 = attr("i=")?
            .parse()
            .map_err(|_| "SCRAM: bad iteration count")?;
        if !(1..=10_000_000).contains(&iterations) {
            return Err("SCRAM: iteration count out of range".into());
        }
        let salted = pbkdf2(self.password.as_bytes(), &salt, iterations);
        let client_key = Zeroizing::new(hmac(salted.as_ref(), b"Client Key"));
        let stored_key: [u8; 32] = Sha256::digest(client_key.as_ref()).into();
        let without_proof = format!("c=biws,r={r}");
        let auth = format!("{},{server_first},{without_proof}", self.client_first_bare);
        let sig = hmac(&stored_key, auth.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(sig.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let server_key = hmac(salted.as_ref(), b"Server Key");
        self.server_signature = Some(hmac(&server_key, auth.as_bytes()));
        Ok(format!("{without_proof},p={}", B64.encode(proof)))
    }

    /// Check the server-final message (mutual authentication).
    pub fn verify_server(&self, server_final: &str) -> Result<(), String> {
        let v = server_final
            .strip_prefix("v=")
            .and_then(|v| B64.decode(v.trim()).ok())
            .ok_or("SCRAM: malformed server-final")?;
        match self.server_signature {
            Some(expected) if v == expected => Ok(()),
            _ => Err("SCRAM: the server could not prove it knows the password".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7677 §3 example exchange (user name blanked: `n=` instead of
    /// `n=user` changes the AuthMessage, so recompute with the RFC's user).
    #[test]
    fn rfc7677_vector() {
        let mut s = Scram::new("pencil", "rOprNGfwEbeRWgbNEkqO");
        s.client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO".into();
        let server_first =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        assert_eq!(
            s.client_final(server_first).unwrap(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert!(s
            .verify_server("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .is_ok());
        assert!(s.verify_server("v=AAAA").is_err());
    }

    #[test]
    fn refuses_a_server_that_does_not_extend_the_nonce() {
        let mut s = Scram::new("pw", "abc");
        assert!(s.client_final("r=xyz,s=AAAA,i=4096").is_err());
        assert!(s.client_final("r=abc,s=AAAA,i=4096").is_err());
        assert!(s.client_final("r=abcd,s=AAAA,i=0").is_err());
    }
}
