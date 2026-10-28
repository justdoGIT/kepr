//! SCRAM-SHA-256 client (RFC 5802 / RFC 7677) for the gate's PostgreSQL
//! login (P7.1). Pure functions: the caller supplies the nonce and moves
//! the messages. Channel binding is not used (`n,,`).

use base64::Engine;
use std::num::NonZeroU32;

use kepr_core::mac;
use zeroize::Zeroizing;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    *mac::hmac_sha256(key, &[data])
}

/// The SCRAM-SHA-256 verifier PostgreSQL stores for `password`
/// (`SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>`). Sending this in
/// `ALTER ROLE … PASSWORD` keeps the password itself off the wire and out
/// of server logs.
pub fn verifier(password: &str, salt: &[u8], iterations: NonZeroU32) -> String {
    let salted = mac::pbkdf2_sha256(password.as_bytes(), salt, iterations);
    let client_key = Zeroizing::new(hmac(salted.as_ref(), b"Client Key"));
    let stored = mac::sha256(&[client_key.as_ref()]);
    let server = hmac(salted.as_ref(), b"Server Key");
    format!(
        "SCRAM-SHA-256${}:{}${}:{}",
        iterations,
        B64.encode(salt),
        B64.encode(stored),
        B64.encode(server)
    )
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
        let iterations = NonZeroU32::new(iterations)
            .filter(|n| n.get() <= 10_000_000)
            .ok_or("SCRAM: iteration count out of range")?;
        let salted = mac::pbkdf2_sha256(self.password.as_bytes(), &salt, iterations);
        let client_key = Zeroizing::new(hmac(salted.as_ref(), b"Client Key"));
        let stored_key = mac::sha256(&[client_key.as_ref()]);
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

    /// A verifier made here must let the SCRAM client log in: replay the
    /// server side of the exchange from the verifier's own keys.
    #[test]
    fn verifier_matches_the_client_proof() {
        let v = verifier(
            "pencil",
            b"0123456789abcdef",
            NonZeroU32::new(4096).unwrap(),
        );
        let parts: Vec<&str> = v.split(['$', ':']).collect();
        assert_eq!((parts[0], parts[1]), ("SCRAM-SHA-256", "4096"));
        let (salt, stored, server_key) = (parts[2], parts[3], parts[4]);
        let mut s = Scram::new("pencil", "abc");
        let first = format!("r=abcXYZ,s={salt},i=4096");
        let fin = s.client_final(&first).unwrap();
        let proof = B64.decode(fin.rsplit_once("p=").unwrap().1).unwrap();
        let auth = format!("n=,r=abc,{first},c=biws,r=abcXYZ");
        let stored = B64.decode(stored).unwrap();
        let sig = hmac(&stored, auth.as_bytes());
        let client_key: Vec<u8> = proof.iter().zip(sig.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(mac::sha256(&[&client_key]).as_slice(), stored.as_slice());
        let server_sig = hmac(&B64.decode(server_key).unwrap(), auth.as_bytes());
        assert!(s
            .verify_server(&format!("v={}", B64.encode(server_sig)))
            .is_ok());
    }

    #[test]
    fn refuses_a_server_that_does_not_extend_the_nonce() {
        let mut s = Scram::new("pw", "abc");
        assert!(s.client_final("r=xyz,s=AAAA,i=4096").is_err());
        assert!(s.client_final("r=abc,s=AAAA,i=4096").is_err());
        assert!(s.client_final("r=abcd,s=AAAA,i=0").is_err());
    }
}
