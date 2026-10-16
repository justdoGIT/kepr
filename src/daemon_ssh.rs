// daemon_ssh.rs — SSH keys that never leave the daemon (agent vault
// P2.4). A key's 32-byte secret (an Ed25519 seed, or since T12.11 a
// P-256 scalar) is stored like any credential (AES-GCM, base64 value)
// with `.meta` `ssh: {public_b64, comment}`; the public blob's type says
// which algorithm signs, so keys from before T12.11 keep working. `Get`
// refuses it, and the only operation on it is `SshSign`.
// `kepr ssh-agent` relays ssh-agent requests here.

mod ecdsa;

use ed25519_dalek::{Signer, SigningKey};
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response, SshKeyInfo};
use kepr_core::ssh_wire::{self, KeyKind};
use kepr_core::ssh_wire_ecdsa;
use zeroize::Zeroizing;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_handlers::{handle_set, SetFlags};
use crate::store::{cred_path, validate_name};
use crate::{crypto, daemon_cache, expiry};

#[derive(Clone, Copy)]
enum Alg {
    Ed25519,
    EcdsaP256,
}

/// `--type`: `ed25519` (the default) or `ecdsa`.
fn alg_for(key_type: Option<&str>) -> Result<Alg, String> {
    match key_type {
        None | Some("ed25519") => Ok(Alg::Ed25519),
        Some("ecdsa") => Ok(Alg::EcdsaP256),
        Some(_) => Err("unknown key type".into()),
    }
}

fn valid_comment(c: &str) -> Result<(), String> {
    if c.chars().count() > 256 || c.chars().any(char::is_control) {
        return Err("comment must be at most 256 printable characters".into());
    }
    Ok(())
}

/// The public blob and authorized_keys line of `secret`.
fn public_of(alg: Alg, secret: &[u8; 32], comment: &str) -> Result<(Vec<u8>, String), String> {
    match alg {
        Alg::Ed25519 => {
            let pk = SigningKey::from_bytes(secret).verifying_key().to_bytes();
            Ok((
                ssh_wire::ed25519_public_blob(&pk),
                ssh_wire::public_line(&pk, comment),
            ))
        }
        Alg::EcdsaP256 => {
            let q = ecdsa::public_q(secret)?;
            Ok((
                ssh_wire_ecdsa::public_blob(&q),
                ssh_wire_ecdsa::public_line(&q, comment),
            ))
        }
    }
}

struct NewKey<'a> {
    alg: Alg,
    secret: &'a [u8; 32],
    comment: &'a str,
    consent: Option<bool>,
}

fn store_key(uid: u32, username: &str, name: &str, k: NewKey<'_>) -> Response {
    if let Err(e) = validate_name(name).and_then(|_| valid_comment(k.comment)) {
        return Response::fail(e);
    }
    let (blob, public_line) = match public_of(k.alg, k.secret, k.comment) {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
    let meta = expiry::SshMeta {
        public_b64: ssh_wire::b64(&blob),
        comment: k.comment.to_string(),
    };
    let value = Zeroizing::new(ssh_wire::b64(k.secret));
    let flags = SetFlags {
        requires_consent: k.consent,
        ssh: Some(meta),
        ..Default::default()
    };
    match handle_set(uid, username, name, Some(value.as_str()), None, flags) {
        Response::SetOk { name, .. } => Response::SshKeyOk { name, public_line },
        other => other,
    }
}

fn generate(
    uid: u32,
    username: &str,
    name: &str,
    key_type: Option<&str>,
    comment: &str,
    consent: Option<bool>,
) -> Response {
    let alg = match alg_for(key_type) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    let secret = match alg {
        Alg::Ed25519 => {
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(seed.as_mut())
                .map(|_| seed)
                .map_err(|e| format!("CSPRNG failure: {e}"))
        }
        Alg::EcdsaP256 => crate::daemon_platform::pki_sign::new_scalar(),
    };
    let secret = match secret {
        Ok(s) => s,
        Err(e) => return Response::fail(e),
    };
    let k = NewKey {
        alg,
        secret: &secret,
        comment,
        consent,
    };
    store_key(uid, username, name, k)
}

fn import(
    uid: u32,
    username: &str,
    name: &str,
    pem: &ZeroString,
    consent: Option<bool>,
) -> Response {
    let parsed = match ssh_wire::parse_openssh_private(pem.as_str()) {
        Ok(k) => k,
        Err(e) => return Response::fail(e),
    };
    let (alg, secret) = match &parsed.kind {
        KeyKind::Ed25519 { seed } => (Alg::Ed25519, seed),
        KeyKind::EcdsaP256 { scalar, q } => {
            // The file's public point must be the scalar's.
            if ecdsa::public_q(scalar).ok().as_ref() != Some(q) {
                return Response::fail("malformed OpenSSH key: the public key does not match");
            }
            (Alg::EcdsaP256, scalar)
        }
    };
    let k = NewKey {
        alg,
        secret,
        comment: &parsed.comment,
        consent,
    };
    store_key(uid, username, name, k)
}

fn list(uid: u32) -> Response {
    let keys = daemon_cache::list_for_uid(uid)
        .into_iter()
        .filter_map(|(name, path)| {
            let meta = expiry::read_meta(&expiry::meta_path_for(&path))?.ok()?;
            let ssh = meta.ssh?;
            Some(SshKeyInfo {
                name,
                public_b64: ssh.public_b64,
                comment: ssh.comment,
            })
        })
        .collect();
    Response::SshListOk { keys }
}

/// The signature blob over `data`, by the algorithm `public_b64` names.
fn sign_blob(public_b64: &str, secret: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    let blob = ssh_wire::unb64(public_b64).unwrap_or_default();
    match ssh_wire_ecdsa::blob_type(&blob) {
        Some(ssh_wire::ED25519) => {
            let sig = SigningKey::from_bytes(secret).sign(data).to_bytes();
            Ok(ssh_wire::ed25519_signature_blob(&sig))
        }
        Some(ssh_wire_ecdsa::ECDSA_P256) => {
            let (r, s) = ecdsa::sign(secret, data)?;
            Ok(ssh_wire_ecdsa::signature_blob(&r, &s))
        }
        _ => Err("unknown key type".into()),
    }
}

fn sign(uid: u32, peer_pid: i32, username: &str, name: &str, data_b64: &str) -> Response {
    let upper = name.to_uppercase();
    let fail = |reason: String| {
        audit::log(&AuditEvent {
            op: "ssh-sign",
            name: Some(&upper),
            uid,
            username,
            result: AuditResult::Fail(reason),
        });
        Response::fail("ssh key unavailable")
    };
    if validate_name(&upper).is_err() {
        return fail("invalid name".into());
    }
    let (meta, ssh) = match expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, &upper))) {
        Some(Ok(m)) => match m.ssh.clone() {
            Some(ssh) => (m, ssh),
            None => return fail("not an ssh key".into()),
        },
        _ => return fail("not an ssh key".into()),
    };
    if meta
        .expires_at_unix
        .is_some_and(|e| expiry::now_unix() >= e)
    {
        return fail("expired".into());
    }
    if meta.requires_consent == Some(true)
        && !crate::daemon_policy::consent(uid, peer_pid, &upper, &meta)
    {
        return fail("consent denied".into());
    }
    let Some(data) = ssh_wire::unb64(data_b64) else {
        return fail("bad data".into());
    };
    let secret_b64 = match crypto::default_backend().decrypt(uid, &upper) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let secret: Zeroizing<Vec<u8>> =
        Zeroizing::new(ssh_wire::unb64(secret_b64.as_str()).unwrap_or_default());
    let Ok(secret) = <[u8; 32]>::try_from(secret.as_slice()).map(Zeroizing::new) else {
        return fail("stored key is malformed".into());
    };
    let blob = match sign_blob(&ssh.public_b64, &secret, &data) {
        Ok(b) => b,
        Err(e) => return fail(e),
    };
    audit::log(&AuditEvent {
        op: "ssh-sign",
        name: Some(&upper),
        uid,
        username,
        result: AuditResult::Ok,
    });
    Response::SshSignOk {
        signature_b64: ssh_wire::b64(&blob),
    }
}

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, req: Request) -> Response {
    match req {
        Request::SshGenerate {
            name,
            comment,
            requires_consent,
            key_type,
        } => generate(
            uid,
            username,
            &name,
            key_type.as_deref(),
            &comment,
            requires_consent,
        ),
        Request::SshImport {
            name,
            private_key,
            requires_consent,
        } => import(uid, username, &name, &private_key, requires_consent),
        Request::SshList => list(uid),
        Request::SshSign { name, data_b64 } => sign(uid, peer_pid, username, &name, &data_b64),
        _ => Response::fail("not an ssh request"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn signature_blob_verifies_with_the_stored_public_key() {
        // RFC 8032 test 1 seed.
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let sk = SigningKey::from_bytes(&seed);
        assert_eq!(
            hex::encode(sk.verifying_key().to_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = sk.sign(b"data");
        let blob = ssh_wire::ed25519_signature_blob(&sig.to_bytes());
        let mut b: &[u8] = &blob;
        assert_eq!(ssh_wire::take_string(&mut b), Some(&b"ssh-ed25519"[..]));
        let raw: [u8; 64] = ssh_wire::take_string(&mut b).unwrap().try_into().unwrap();
        assert!(sk
            .verifying_key()
            .verify(b"data", &Signature::from_bytes(&raw))
            .is_ok());
    }

    #[test]
    fn comment_rules() {
        assert!(valid_comment("me@laptop").is_ok());
        assert!(valid_comment("bad\nline").is_err());
        assert!(valid_comment(&"x".repeat(300)).is_err());
    }
}
