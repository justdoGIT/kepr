// daemon_share.rs — sharing a credential with another kepr user
// (agent vault P6.1 / P6.2), with no server in between.
//
//   ShareKey      create (once) / show this user's X25519 public key
//                 `kepr-pub1-<base64>`. The private key is stored like an
//                 SSH key: `.meta` `share_key`, `Get` refuses it.
//   ShareSend     encrypt one credential to a recipient's public key:
//                 ephemeral X25519 → HKDF-SHA256 → AES-256-GCM, AAD binds
//                 the format and the recipient. The envelope carries an
//                 expiry and a random id. Sealed values, SSH keys and the
//                 share key itself are refused.
//   ShareReceive  decrypt with this user's key, check expiry, refuse an id
//                 already received (single use), store the value.
//
// The value is never shown to either CLI: the sender's daemon encrypts,
// the recipient's daemon decrypts and stores.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use hkdf::Hkdf;
use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_handlers::{handle_set, SetFlags};
use crate::store::{cred_path, validate_name};
use crate::{crypto, expiry};

const KEY_NAME: &str = "KEPR_SHARE_KEY";
const PUB_PREFIX: &str = "kepr-pub1-";
const ENV_PREFIX: &str = "kepr-share1-";
const DEFAULT_TTL: u64 = 24 * 3600;
const MAX_TTL: u64 = 30 * 24 * 3600;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(serde::Serialize, serde::Deserialize)]
struct Payload1 {
    id: String,
    name: String,
    value: ZeroString,
    expires: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_type: Option<String>,
}

/// A fresh X25519 secret from the OS CSPRNG.
fn new_secret() -> Result<StaticSecret, String> {
    let mut b = Zeroizing::new([0u8; 32]);
    getrandom::fill(b.as_mut()).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(StaticSecret::from(*b))
}

fn kdf(shared: &[u8; 32], eph: &[u8; 32], to: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph);
    salt[32..].copy_from_slice(to);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(b"kepr-share-v1", key.as_mut())
        .expect("32 bytes is a valid HKDF length");
    key
}

fn aad(to: &[u8; 32]) -> Vec<u8> {
    [ENV_PREFIX.as_bytes(), to].concat()
}

pub fn parse_public(text: &str) -> Result<[u8; 32], String> {
    let raw = text
        .trim()
        .strip_prefix(PUB_PREFIX)
        .and_then(|b| B64.decode(b).ok())
        .ok_or("not a kepr public key (kepr-pub1-…)")?;
    raw.try_into()
        .map_err(|_| "not a kepr public key".to_string())
}

/// Encrypt `payload` to `to` (pure; the ephemeral key is random).
fn seal(to: &[u8; 32], payload: &[u8]) -> Result<String, String> {
    let eph = new_secret()?;
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = Zeroizing::new(eph.diffie_hellman(&PublicKey::from(*to)).to_bytes());
    let key = kdf(&shared, &eph_pub, to);
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let ct = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| "bad key")?
        .encrypt(
            &nonce.into(),
            Payload {
                msg: payload,
                aad: &aad(to),
            },
        )
        .map_err(|_| "encryption failed")?;
    Ok(format!(
        "{ENV_PREFIX}{}",
        B64.encode([&eph_pub[..], &nonce, &ct].concat())
    ))
}

/// Decrypt an envelope with our secret key (pure).
fn open(secret: &StaticSecret, envelope: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let raw = envelope
        .trim()
        .strip_prefix(ENV_PREFIX)
        .and_then(|b| B64.decode(b).ok())
        .filter(|r| r.len() > 32 + 12 + 16)
        .ok_or("not a kepr share (kepr-share1-…)")?;
    let eph_pub: [u8; 32] = raw[..32].try_into().expect("32-byte slice");
    let nonce: [u8; 12] = raw[32..44].try_into().expect("12-byte slice");
    let me = PublicKey::from(secret).to_bytes();
    let shared = Zeroizing::new(secret.diffie_hellman(&PublicKey::from(eph_pub)).to_bytes());
    let key = kdf(&shared, &eph_pub, &me);
    Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| "bad key")?
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &raw[44..],
                aad: &aad(&me),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| "this share is not for you, or it was altered".into())
}

fn load_secret(uid: u32) -> Result<StaticSecret, String> {
    let v = crypto::default_backend()
        .decrypt(uid, KEY_NAME)
        .map_err(|_| "no share key yet: run `kepr share key`")?;
    let raw = Zeroizing::new(B64.decode(v.as_str()).map_err(|_| "share key is damaged")?);
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "share key is damaged")?;
    Ok(StaticSecret::from(bytes))
}

fn audit_r(op: &'static str, uid: u32, username: &str, name: Option<&str>, r: &Result<(), String>) {
    audit::log(&AuditEvent {
        op,
        name,
        uid,
        username,
        result: match r {
            Ok(()) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}

pub fn handle_key(uid: u32, username: &str, create: bool) -> Response {
    if create && !cred_path(uid, KEY_NAME).exists() {
        let secret = match new_secret() {
            Ok(s) => s,
            Err(e) => return Response::fail(e),
        };
        let value = Zeroizing::new(B64.encode(secret.to_bytes()));
        let flags = SetFlags {
            share_key: Some(true),
            ..Default::default()
        };
        if let r @ Response::Err { .. } =
            handle_set(uid, username, KEY_NAME, Some(&value), None, flags)
        {
            return r;
        }
    }
    match load_secret(uid) {
        Ok(s) => Response::ShareKeyOk {
            public: format!("{PUB_PREFIX}{}", B64.encode(PublicKey::from(&s).to_bytes())),
        },
        Err(e) => Response::fail(e),
    }
}

pub fn handle_send(
    (uid, peer_pid): (u32, i32),
    username: &str,
    name: &str,
    to: &str,
    ttl: Option<u64>,
) -> Response {
    let upper = name.to_uppercase();
    let mut out = (String::new(), 0u64);
    let r = (|| {
        validate_name(name)?;
        let to = parse_public(to)?;
        let ttl = ttl.unwrap_or(DEFAULT_TTL);
        if ttl == 0 || ttl > MAX_TTL {
            return Err("--ttl must be 1 second to 30 days".into());
        }
        // The same policy as Get, fail-closed: sealed, SSH and share
        // keys, expired values, an unreadable .meta and FIDO2-gated
        // values are refused; consent-gated ones ask first.
        crate::daemon_handlers_get::precheck_meta(uid, peer_pid, &upper)
            .map_err(|_| "this credential can't be shared".to_string())?;
        let meta = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, &upper)))
            .and_then(Result::ok)
            .unwrap_or_default();
        let value = crypto::default_backend()
            .decrypt(uid, &upper)
            .map_err(|e| crypto::sanitize_lookup_error(&e))?;
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|e| format!("CSPRNG failure: {e}"))?;
        let expires = expiry::now_unix() + ttl;
        let payload = Payload1 {
            id: hex::encode(id),
            name: upper.clone(),
            value,
            expires,
            record_type: meta.record_type,
        };
        let json = Zeroizing::new(serde_json::to_vec(&payload).map_err(|e| e.to_string())?);
        out = (seal(&to, &json)?, expires);
        Ok(())
    })();
    audit_r("share-send", uid, username, Some(&upper), &r);
    match r {
        Ok(()) => Response::ShareOk {
            envelope: out.0,
            expires_at: expiry::format_expires_at(out.1),
        },
        Err(e) => Response::fail(e),
    }
}

pub fn handle_receive(uid: u32, username: &str, envelope: &str, rename: Option<&str>) -> Response {
    let r = (|| {
        let secret = load_secret(uid)?;
        let plain = open(&secret, envelope)?;
        let p: Payload1 = serde_json::from_slice(&plain).map_err(|_| "malformed share")?;
        if expiry::now_unix() >= p.expires {
            return Err("this share has expired".to_string());
        }
        // Everything that can refuse runs before the share is used up.
        let name = rename.map(str::to_uppercase).unwrap_or(p.name);
        validate_name(&name)?;
        if name == KEY_NAME {
            return Err("this name is reserved".into());
        }
        // Never let a sender's choice of name replace an existing
        // credential (a sealed key, an SSH key, …).
        if cred_path(uid, &name).exists() {
            return Err(format!(
                "{name} already exists; receive it --as ANOTHER_NAME"
            ));
        }
        crate::daemon_share_seen::claim(uid, &p.id, p.expires)?;
        let flags = SetFlags {
            record_type: p.record_type,
            ..Default::default()
        };
        match handle_set(uid, username, &name, Some(p.value.as_str()), None, flags) {
            r @ Response::SetOk { .. } => Ok((name, r)),
            Response::Err { error } => {
                crate::daemon_share_seen::release(uid, &p.id);
                Err(error)
            }
            _ => Err("unexpected store reply".into()),
        }
    })();
    match r {
        Ok((name, resp)) => {
            audit_r("share-receive", uid, username, Some(&name), &Ok(()));
            resp
        }
        Err(e) => {
            audit_r("share-receive", uid, username, None, &Err(e.clone()));
            Response::fail(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_for_one_recipient_only() {
        let alice = new_secret().unwrap();
        let bob = new_secret().unwrap();
        let bob_pub = PublicKey::from(&bob).to_bytes();
        let env = seal(&bob_pub, b"hello").unwrap();
        assert!(env.starts_with(ENV_PREFIX));
        assert_eq!(&**open(&bob, &env).unwrap(), b"hello");
        assert!(open(&alice, &env).is_err());
        // A flipped byte anywhere fails the tag.
        let raw = B64.decode(env.strip_prefix(ENV_PREFIX).unwrap()).unwrap();
        for i in [0, 40, raw.len() - 1] {
            let mut r = raw.clone();
            r[i] ^= 1;
            assert!(open(&bob, &format!("{ENV_PREFIX}{}", B64.encode(r))).is_err());
        }
        // Two shares of the same value differ (fresh ephemeral key + nonce).
        assert_ne!(env, seal(&bob_pub, b"hello").unwrap());
    }

    #[test]
    fn public_key_text() {
        let s = new_secret().unwrap();
        let text = format!("{PUB_PREFIX}{}", B64.encode(PublicKey::from(&s).to_bytes()));
        assert_eq!(parse_public(&text).unwrap(), PublicKey::from(&s).to_bytes());
        assert!(parse_public("kepr-pub1-AAAA").is_err());
        assert!(parse_public("ssh-ed25519 AAAA").is_err());
    }
}
