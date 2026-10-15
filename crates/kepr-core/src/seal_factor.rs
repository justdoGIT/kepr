// seal_factor.rs — a passphrase plus a FIDO2 `hmac-secret` output in one
// secret (T4.09), so every place that sends the store passphrase (`Lock`,
// `Unlock`, `RecoveryKitCreate`, …) carries the second factor unchanged:
//
//     U+0001 "fido2:" cred_id ":" salt ":" hmac_secret U+0001 passphrase
//
// with the three fields in standard base64. The CLI composes it after
// touching the key; the daemon's envelope code splits it. Neither part is
// ever logged; `Fido2Factor`'s Debug output is redacted.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

use crate::generate::ZeroString;

/// The relying-party id of the store's security-key credential.
pub const FIDO2_RP_ID: &str = "kepr";
const TAG: &str = "\u{1}fido2:";
const END: u8 = 1;

pub struct Fido2Factor {
    pub credential_id: Vec<u8>,
    /// The `hmac-secret` salt (public, stored in the envelope).
    pub salt: [u8; 32],
    /// The key's `hmac-secret` output for `salt` (secret).
    pub hmac: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Fido2Factor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fido2Factor(<redacted>)")
    }
}

/// `passphrase` and `factor` as one secret.
pub fn compose_factor(passphrase: &str, factor: &Fido2Factor) -> ZeroString {
    let hmac = Zeroizing::new(STANDARD.encode(factor.hmac.as_ref()));
    let mut s = String::with_capacity(TAG.len() + 200 + passphrase.len());
    s.push_str(TAG);
    s.push_str(&STANDARD.encode(&factor.credential_id));
    s.push(':');
    s.push_str(&STANDARD.encode(factor.salt));
    s.push(':');
    s.push_str(&hmac);
    s.push(char::from(END));
    s.push_str(passphrase);
    ZeroString::from_string(s)
}

/// `(factor, passphrase)`; a plain passphrase has no factor.
pub fn split_factor(secret: &[u8]) -> Result<(Option<Fido2Factor>, &[u8]), String> {
    let Some(rest) = secret.strip_prefix(TAG.as_bytes()) else {
        return Ok((None, secret));
    };
    let bad = || "malformed security-key factor".to_string();
    let end = rest.iter().position(|b| *b == END).ok_or_else(bad)?;
    let (fields, passphrase) = (&rest[..end], &rest[end + 1..]);
    let mut it = fields.split(|b| *b == b':');
    let mut next = || -> Result<Zeroizing<Vec<u8>>, String> {
        let f = it.next().ok_or_else(bad)?;
        STANDARD.decode(f).map(Zeroizing::new).map_err(|_| bad())
    };
    let credential_id = next()?.to_vec();
    let salt: [u8; 32] = next()?.as_slice().try_into().map_err(|_| bad())?;
    let hmac: [u8; 32] = next()?.as_slice().try_into().map_err(|_| bad())?;
    if it.next().is_some() || credential_id.is_empty() {
        return Err(bad());
    }
    let factor = Fido2Factor {
        credential_id,
        salt,
        hmac: Zeroizing::new(hmac),
    };
    Ok((Some(factor), passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn factor() -> Fido2Factor {
        Fido2Factor {
            credential_id: vec![1, 2, 3],
            salt: [4; 32],
            hmac: Zeroizing::new([5; 32]),
        }
    }

    #[test]
    fn composes_and_splits() {
        let s = compose_factor("pass: with\u{1}odd chars", &factor());
        let (f, p) = split_factor(s.as_bytes()).unwrap();
        let f = f.unwrap();
        assert_eq!(p, "pass: with\u{1}odd chars".as_bytes());
        assert_eq!(
            (f.credential_id, f.salt, *f.hmac),
            (vec![1, 2, 3], [4; 32], [5; 32])
        );
        assert_eq!(format!("{:?}", factor()), "Fido2Factor(<redacted>)");
    }

    #[test]
    fn plain_passphrases_pass_through_and_junk_is_refused() {
        let (f, p) = split_factor(b"correct horse").unwrap();
        assert!(f.is_none());
        assert_eq!(p, b"correct horse");
        assert!(split_factor(b"\x01fido2:AQID:BAQE\x01pw").is_err());
        assert!(split_factor(b"\x01fido2:no-end").is_err());
        let s = compose_factor("pw", &factor());
        let extra = s.as_str().replacen("\u{1}pw", ":AAAA\u{1}pw", 1);
        assert!(split_factor(extra.as_bytes()).is_err());
    }
}
