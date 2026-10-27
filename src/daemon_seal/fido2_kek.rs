// daemon_seal/fido2_kek.rs — a FIDO2 security key as a second factor for
// the passphrase-wrapped master key (T4.09).
//
// `kepr lock --fido2` makes a credential with the `hmac-secret` extension
// and reads its output for a random 32-byte salt (the CLI drives the
// device, cli_seal/fido2.rs). The wrapping key is then
//
//     KEK = HKDF-SHA256(salt = argon_salt,
//                       ikm  = Argon2id(passphrase, argon_salt) ‖ hmac_secret,
//                       info = "kepr-fido2-kek-v1")
//
// so neither the passphrase nor the key alone opens the envelope:
//
//     "kepr_pw2\n" | argon_salt (16) | cred_id_len (u16 BE) | cred_id
//                  | hmac_salt (32) | nonce (12) | AES-256-GCM(master key)
//
// Everything before the nonce is the AEAD's associated data. The
// credential id and salt are public: `kepr unlock` asks for them
// (`Fido2UnlockParams`) to run the assertion, then sends the passphrase
// and the `hmac-secret` output together (kepr_core::seal_factor), which
// key_unlock.rs splits before choosing the envelope version.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use kepr_core::protocol::Response;
use kepr_core::protocol_seal::SealResponse;
use kepr_core::seal_factor::{Fido2Factor, FIDO2_RP_ID};

use crate::daemon_eco::cipher;

pub const MAGIC: &[u8; 9] = b"kepr_pw2\n";
const ARGON_SALT: usize = 16;
const HMAC_SALT: usize = 32;
const NONCE: usize = 12;
const KEY: usize = 32;
const TAG: usize = 16;
const MAX_CRED_ID: usize = 1024;
const INFO: &[u8] = b"kepr-fido2-kek-v1";

/// Argon2id(passphrase, salt) — `key_unlock`'s KDF; tests pass a cheap one.
pub type Kdf = fn(&[u8], &[u8; ARGON_SALT]) -> Result<Zeroizing<[u8; KEY]>, String>;

pub fn is_fido2(envelope: &[u8]) -> bool {
    envelope.starts_with(MAGIC)
}

/// The KEK from the passphrase's Argon2id output and the key's
/// `hmac-secret` output.
pub fn combine(
    argon: &[u8; KEY],
    hmac: &[u8; KEY],
    argon_salt: &[u8; ARGON_SALT],
) -> Zeroizing<[u8; KEY]> {
    let mut ikm = Zeroizing::new([0u8; 2 * KEY]);
    ikm[..KEY].copy_from_slice(argon);
    ikm[KEY..].copy_from_slice(hmac);
    let mut kek = Zeroizing::new([0u8; KEY]);
    Hkdf::<Sha256>::new(Some(argon_salt), ikm.as_ref())
        .expand(INFO, kek.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    kek
}

struct Parsed<'a> {
    header: &'a [u8],
    argon_salt: [u8; ARGON_SALT],
    cred_id: &'a [u8],
    hmac_salt: [u8; HMAC_SALT],
    nonce: [u8; NONCE],
    ciphertext: &'a [u8],
}

fn parse(envelope: &[u8]) -> Result<Parsed<'_>, String> {
    let bad = || "invalid protected master-key envelope".to_string();
    let rest = envelope.strip_prefix(MAGIC.as_slice()).ok_or_else(bad)?;
    if rest.len() < ARGON_SALT + 2 {
        return Err(bad());
    }
    let (argon_salt, rest) = rest.split_at(ARGON_SALT);
    let id_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
    let rest = &rest[2..];
    if id_len == 0 || rest.len() != id_len + HMAC_SALT + NONCE + KEY + TAG {
        return Err(bad());
    }
    let (cred_id, rest) = rest.split_at(id_len);
    let (hmac_salt, rest) = rest.split_at(HMAC_SALT);
    let (nonce, ciphertext) = rest.split_at(NONCE);
    let header_len = envelope.len() - NONCE - ciphertext.len();
    Ok(Parsed {
        header: &envelope[..header_len],
        argon_salt: argon_salt.try_into().map_err(|_| bad())?,
        cred_id,
        hmac_salt: hmac_salt.try_into().map_err(|_| bad())?,
        nonce: nonce.try_into().map_err(|_| bad())?,
        ciphertext,
    })
}

/// Wrap `master` under the passphrase and the security key's output.
pub fn wrap_with(
    master: &[u8; KEY],
    passphrase: &[u8],
    factor: &Fido2Factor,
    kdf: Kdf,
) -> Result<Vec<u8>, String> {
    if passphrase.is_empty() {
        return Err("password cannot be empty".to_string());
    }
    if factor.credential_id.is_empty() || factor.credential_id.len() > MAX_CRED_ID {
        return Err("invalid security-key credential id".to_string());
    }
    let mut argon_salt = [0u8; ARGON_SALT];
    let mut nonce = [0u8; NONCE];
    getrandom::fill(&mut argon_salt).map_err(|e| format!("CSPRNG failure: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&argon_salt);
    out.extend_from_slice(&(factor.credential_id.len() as u16).to_be_bytes());
    out.extend_from_slice(&factor.credential_id);
    out.extend_from_slice(&factor.salt);
    let kek = combine(&*kdf(passphrase, &argon_salt)?, &factor.hmac, &argon_salt);
    let ct = cipher::seal(kek.as_ref(), &nonce, &out, master.as_ref())
        .map_err(|_| "master-key wrapping failed".to_string())?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap; without the security key's output this always fails.
pub fn unwrap_with(
    envelope: &[u8],
    passphrase: &[u8],
    factor: Option<&Fido2Factor>,
    kdf: Kdf,
) -> Result<Zeroizing<[u8; KEY]>, String> {
    let p = parse(envelope)?;
    let Some(factor) = factor else {
        return Err("this store also needs its security key: unlock with `kepr unlock`".into());
    };
    if passphrase.is_empty() {
        return Err("password cannot be empty".to_string());
    }
    let kek = combine(
        &*kdf(passphrase, &p.argon_salt)?,
        &factor.hmac,
        &p.argon_salt,
    );
    let plain = cipher::open(kek.as_ref(), &p.nonce, p.header, p.ciphertext)
        .map_err(|_| "invalid password, security key or protected master-key envelope")?;
    let key: [u8; KEY] = plain
        .as_slice()
        .try_into()
        .map_err(|_| "invalid protected master-key plaintext")?;
    Ok(Zeroizing::new(key))
}

/// `(credential id, hmac salt)` of a FIDO2-protected envelope.
pub fn params(envelope: &[u8]) -> Option<(Vec<u8>, [u8; HMAC_SALT])> {
    parse(envelope)
        .ok()
        .map(|p| (p.cred_id.to_vec(), p.hmac_salt))
}

/// `Fido2UnlockParams`: what `kepr unlock` needs to run the assertion.
/// Same callers as unlock: root in system mode, the owner in user mode.
pub fn handle_params(uid: u32, username: &str) -> Response {
    let allowed = if !crate::user_mode() && uid != 0 {
        Err("only root may unlock the shared credential store".to_string())
    } else {
        Ok(())
    };
    super::audit_result("fido2-unlock-params", uid, username, &allowed);
    if let Err(e) = allowed {
        return Response::fail(e);
    }
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let found = std::fs::read(crate::protected_master_key_path())
        .ok()
        .and_then(|e| params(&e));
    Response::Seal(SealResponse::Fido2UnlockParamsOk {
        rp_id: FIDO2_RP_ID.to_string(),
        credential_id: found.as_ref().map(|(id, _)| b64.encode(id)),
        salt: found.as_ref().map(|(_, s)| b64.encode(s)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in for Argon2id (seconds per call in a debug build).
    fn cheap_kdf(p: &[u8], salt: &[u8; ARGON_SALT]) -> Result<Zeroizing<[u8; KEY]>, String> {
        let d = cipher::sha256(&[b"test-kdf", salt, p]);
        let mut k = Zeroizing::new([0u8; KEY]);
        k.copy_from_slice(&d[..KEY]);
        Ok(k)
    }

    fn factor(hmac: u8) -> Fido2Factor {
        Fido2Factor {
            credential_id: vec![0xc1; 64],
            salt: [0x5a; 32],
            hmac: Zeroizing::new([hmac; 32]),
        }
    }

    #[test]
    fn kek_is_deterministic_and_differs_from_passphrase_only() {
        let argon = [1u8; KEY];
        let salt = [2u8; ARGON_SALT];
        let a = combine(&argon, &[3u8; KEY], &salt);
        assert_eq!(*a, *combine(&argon, &[3u8; KEY], &salt));
        assert_ne!(*a, argon, "the factor must change the key");
        assert_ne!(*a, *combine(&argon, &[4u8; KEY], &salt));
        assert_ne!(*a, *combine(&[9u8; KEY], &[3u8; KEY], &salt));
    }

    #[test]
    fn round_trip_needs_passphrase_and_key() {
        let master = [7u8; KEY];
        let env = wrap_with(&master, b"pw", &factor(3), cheap_kdf).unwrap();
        assert!(is_fido2(&env));
        let ok = unwrap_with(&env, b"pw", Some(&factor(3)), cheap_kdf).unwrap();
        assert_eq!(*ok, master);
        // Unlock without the factor fails, as do a wrong key or passphrase.
        let e = unwrap_with(&env, b"pw", None, cheap_kdf).unwrap_err();
        assert!(e.contains("security key"), "{e}");
        assert!(unwrap_with(&env, b"pw", Some(&factor(4)), cheap_kdf).is_err());
        assert!(unwrap_with(&env, b"pw2", Some(&factor(3)), cheap_kdf).is_err());
        // The stored credential id and salt come back, and are authenticated.
        let (id, salt) = params(&env).unwrap();
        assert_eq!((id, salt), (vec![0xc1; 64], [0x5a; 32]));
        let mut tampered = env.clone();
        tampered[MAGIC.len() + ARGON_SALT + 2] ^= 1;
        assert!(unwrap_with(&tampered, b"pw", Some(&factor(3)), cheap_kdf).is_err());
        assert!(params(b"kepr_pw1\nxxxx").is_none());
        assert!(params(&env[..env.len() - 1]).is_none());
    }

    #[test]
    fn wrap_rejects_empty_passphrase_and_bad_ids() {
        assert!(wrap_with(&[0; KEY], b"", &factor(1), cheap_kdf).is_err());
        let mut f = factor(1);
        f.credential_id.clear();
        assert!(wrap_with(&[0; KEY], b"pw", &f, cheap_kdf).is_err());
    }
}
