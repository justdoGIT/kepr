// daemon_share.rs — sharing a credential with another kepr user
// (agent vault P6.1 / P6.2), with no server in between.
//
//   ShareKey      create (once) / show this user's public key
//                 `kepr-pk2-<base64>` (X25519 + ML-KEM-768, T6.01). The
//                 private key is stored like an SSH key: `.meta`
//                 `share_key`, `Get` refuses it.
//   ShareSend     encrypt one credential to a recipient's public key (the
//                 envelope formats live in daemon_sharing/kem.rs: v2 hybrid
//                 for v2 keys, v1 X25519 for v1 keys). The envelope carries an
//                 expiry and a random id. Sealed values, SSH keys and the
//                 share key itself are refused.
//   ShareReceive  decrypt with this user's key, check expiry, refuse an id
//                 already received (single use), store the value.
//
// The value is never shown to either CLI: the sender's daemon encrypts,
// the recipient's daemon decrypts and stores.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use zeroize::Zeroizing;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_handlers::{handle_set, SetFlags};
use crate::daemon_sharing::kem::{self, Recipient, ShareSecret};
use crate::store::{cred_path, validate_name};
use crate::{crypto, expiry};

pub(crate) const KEY_NAME: &str = "KEPR_SHARE_KEY";
const DEFAULT_TTL: u64 = 24 * 3600;
const MAX_TTL: u64 = 30 * 24 * 3600;

/// What every share carries (envelopes and one-time links alike).
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct Payload1 {
    pub id: String,
    pub name: String,
    pub value: ZeroString,
    pub expires: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
}

pub(crate) fn load_secret(uid: u32) -> Result<ShareSecret, String> {
    let v = crypto::default_backend()
        .decrypt(uid, KEY_NAME)
        .map_err(|_| "no share key yet: run `kepr share key`")?;
    ShareSecret::decode(v.as_str())
}

/// Store `secret` as this user's share key (never readable by `Get`).
fn store_secret(uid: u32, username: &str, secret: &ShareSecret) -> Result<(), String> {
    let flags = SetFlags {
        share_key: Some(true),
        ..Default::default()
    };
    match handle_set(uid, username, KEY_NAME, Some(&secret.encode()), None, flags) {
        Response::Err { error } => Err(error),
        _ => Ok(()),
    }
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
    // T6.01: a missing key is made as v2 (X25519 + ML-KEM-768); a v1 key
    // is upgraded in place, keeping its X25519 half (old shares still open).
    let r = (|| -> Result<String, String> {
        if create && !crate::store::cred_exists(uid, KEY_NAME) {
            store_secret(uid, username, &ShareSecret::generate()?)?;
        }
        let mut secret = load_secret(uid)?;
        if create && secret.upgrade()? {
            store_secret(uid, username, &secret)?;
        }
        Ok(secret.recipient().text())
    })();
    match r {
        Ok(public) => Response::ShareKeyOk { public },
        Err(e) => Response::fail(e),
    }
}

/// A fresh single-use payload holding NAME's value, under the same
/// policy as Get, fail-closed: sealed, SSH and share keys, expired
/// values, an unreadable .meta and FIDO2-gated values are refused;
/// consent-gated ones ask first. Also used by one-time links (T6.04).
pub(crate) fn new_payload(
    (uid, peer_pid): (u32, i32),
    name: &str,
    ttl: Option<u64>,
) -> Result<Payload1, String> {
    validate_name(name)?;
    let upper = &name.to_uppercase();
    let ttl = ttl.unwrap_or(DEFAULT_TTL);
    if ttl == 0 || ttl > MAX_TTL {
        return Err("--ttl must be 1 second to 30 days".into());
    }
    let _lock = crate::daemon_credlock::lock(uid, upper);
    crate::daemon_handlers_get::precheck_meta(uid, peer_pid, upper).map_err(|e| {
        crate::daemon_session::reauth::refusal(&e, upper, "this credential can't be shared")
    })?;
    let meta = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper)))
        .and_then(Result::ok)
        .unwrap_or_default();
    let value = crypto::default_backend()
        .decrypt(uid, upper)
        .map_err(|e| crypto::sanitize_lookup_error(&e))?;
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(Payload1 {
        id: hex::encode(id),
        name: upper.to_string(),
        value,
        expires: expiry::now_unix() + ttl,
        record_type: meta.record_type,
    })
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
        let to = Recipient::parse(to)?;
        let payload = new_payload((uid, peer_pid), name, ttl)?;
        let json = Zeroizing::new(serde_json::to_vec(&payload).map_err(|e| e.to_string())?);
        out = (kem::seal(&to, &json)?, payload.expires);
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

/// Store a received payload under its name (or `rename`): refuses an
/// expired share, a reserved or existing name, and an id already
/// received (single use). Also used by one-time links (T6.04).
pub(crate) fn store_payload(
    uid: u32,
    username: &str,
    p: Payload1,
    rename: Option<&str>,
) -> Result<(String, Response), String> {
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
    if crate::store::cred_exists(uid, &name) {
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
        r @ Response::SetOk { .. } => {
            // T6.05: the sender's ledger row (and a self-destruct).
            crate::daemon_sharing::sent::on_received(&p.id, expiry::now_unix());
            Ok((name, r))
        }
        Response::Err { error } => {
            crate::daemon_share_seen::release(uid, &p.id);
            Err(error)
        }
        _ => Err("unexpected store reply".into()),
    }
}

/// Audit a receive-like operation and turn it into the reply.
pub(crate) fn received(
    op: &'static str,
    uid: u32,
    username: &str,
    r: Result<(String, Response), String>,
) -> Response {
    match r {
        Ok((name, resp)) => {
            audit_r(op, uid, username, Some(&name), &Ok(()));
            resp
        }
        Err(e) => {
            audit_r(op, uid, username, None, &Err(e.clone()));
            Response::fail(e)
        }
    }
}

pub fn handle_receive(uid: u32, username: &str, envelope: &str, rename: Option<&str>) -> Response {
    let r = (|| {
        let secret = load_secret(uid)?;
        let plain = kem::open(&secret, envelope)?;
        let p: Payload1 = serde_json::from_slice(&plain).map_err(|_| "malformed share")?;
        store_payload(uid, username, p, rename)
    })();
    received("share-receive", uid, username, r)
}
