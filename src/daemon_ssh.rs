// daemon_ssh.rs — SSH keys that never leave the daemon (agent vault
// P2.4). A key's 32-byte Ed25519 seed is stored like any credential
// (AES-GCM, base64 value) with `.meta` `ssh: {public_b64, comment}`;
// `Get` refuses it, and the only operation on it is `SshSign`.
// `kepr ssh-agent` relays ssh-agent requests here.

use ed25519_dalek::{Signer, SigningKey};
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response, SshKeyInfo};
use kepr_core::ssh_wire;
use zeroize::Zeroizing;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_handlers::{handle_set, SetFlags};
use crate::store::{cred_path, validate_name};
use crate::{crypto, daemon_cache, expiry};

fn valid_comment(c: &str) -> Result<(), String> {
    if c.chars().count() > 256 || c.chars().any(char::is_control) {
        return Err("comment must be at most 256 printable characters".into());
    }
    Ok(())
}

fn store_key(
    uid: u32,
    username: &str,
    name: &str,
    seed: &[u8; 32],
    comment: &str,
    consent: Option<bool>,
) -> Response {
    if let Err(e) = validate_name(name).and_then(|_| valid_comment(comment)) {
        return Response::fail(e);
    }
    let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    let meta = expiry::SshMeta {
        public_b64: ssh_wire::b64(&ssh_wire::ed25519_public_blob(&public)),
        comment: comment.to_string(),
    };
    let value = Zeroizing::new(ssh_wire::b64(seed));
    let flags = SetFlags {
        requires_consent: consent,
        ssh: Some(meta),
        ..Default::default()
    };
    match handle_set(uid, username, name, Some(value.as_str()), None, flags) {
        Response::SetOk { name, .. } => Response::SshKeyOk {
            name,
            public_line: ssh_wire::public_line(&public, comment),
        },
        other => other,
    }
}

fn generate(
    uid: u32,
    username: &str,
    name: &str,
    comment: &str,
    consent: Option<bool>,
) -> Response {
    let mut seed = Zeroizing::new([0u8; 32]);
    if let Err(e) = getrandom::fill(seed.as_mut()) {
        return Response::fail(format!("CSPRNG failure: {e}"));
    }
    store_key(uid, username, name, &seed, comment, consent)
}

fn import(
    uid: u32,
    username: &str,
    name: &str,
    pem: &ZeroString,
    consent: Option<bool>,
) -> Response {
    match ssh_wire::parse_openssh_private(pem.as_str()) {
        Ok(k) => store_key(uid, username, name, &k.seed, &k.comment, consent),
        Err(e) => Response::fail(e),
    }
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
    let meta = match expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, &upper))) {
        Some(Ok(m)) if m.ssh.is_some() => m,
        _ => return fail("not an ssh key".into()),
    };
    if meta
        .expires_at_unix
        .is_some_and(|e| expiry::now_unix() >= e)
    {
        return fail("expired".into());
    }
    if meta.requires_consent == Some(true) && !crate::daemon_polkit::consent_granted(peer_pid) {
        return fail("consent denied".into());
    }
    let Some(data) = ssh_wire::unb64(data_b64) else {
        return fail("bad data".into());
    };
    let seed_b64 = match crypto::default_backend().decrypt(uid, &upper) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let seed: Zeroizing<Vec<u8>> =
        Zeroizing::new(ssh_wire::unb64(seed_b64.as_str()).unwrap_or_default());
    let Ok(seed) = <[u8; 32]>::try_from(seed.as_slice()).map(Zeroizing::new) else {
        return fail("stored key is malformed".into());
    };
    let sig = SigningKey::from_bytes(&seed).sign(&data).to_bytes();
    audit::log(&AuditEvent {
        op: "ssh-sign",
        name: Some(&upper),
        uid,
        username,
        result: AuditResult::Ok,
    });
    Response::SshSignOk {
        signature_b64: ssh_wire::b64(&ssh_wire::ed25519_signature_blob(&sig)),
    }
}

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, req: Request) -> Response {
    match req {
        Request::SshGenerate {
            name,
            comment,
            requires_consent,
        } => generate(uid, username, &name, &comment, requires_consent),
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
