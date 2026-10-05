// daemon_recovery.rs — emergency recovery kit (agent vault P6.3).
//
// `kepr recovery-kit create` splits the master key into k-of-n Shamir
// shares (kepr_core::shamir) for printing and storing apart.
// `kepr recovery-kit restore` rebuilds it on a machine whose master key
// is gone (lost TPM, new disk with the old credential files).
//
// This is the one deliberate exception to "no path returns key material"
// (AGENTS.md). It is fenced in accordingly:
//   - create works only on a passphrase-protected store, and the
//     passphrase is checked again here (Argon2id unwrap must match the
//     live key);
//   - system mode: root only; user mode: the daemon's owner only;
//   - refused while any agent gate of the caller is running;
//   - every attempt is audited (`recovery-kit`, `recovery-restore`).
// Restore must prove the rebuilt key against the credential files on
// disk (AEAD tag check) and refuses while the current key still opens
// them, so it can't be used to swap the key of a working store. The
// restored key is written under a new passphrase (Argon2id envelope).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::shamir;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::{crypto, key_unlock, store};

/// Same layout as crypto_inproc's files: magic(8) | nonce(12) | ct+tag.
const HEADER: usize = 8 + 12;

/// Short public identifier of a master key, carried by every share.
pub fn fingerprint(key: &[u8; 32]) -> String {
    let d = Sha256::new_with_prefix(b"kepr-recovery-v1")
        .chain_update(key)
        .finalize();
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Does `key` open the credential file `blob` stored for (uid, name)?
fn opens(key: &[u8; 32], uid: u32, name: &str, blob: &[u8]) -> bool {
    if blob.len() < HEADER + 16 || !blob.starts_with(b"kepr_v") {
        return false;
    }
    let Ok(cipher) = Aes256Gcm::new_from_slice(key) else {
        return false;
    };
    let mut aad = uid.to_le_bytes().to_vec();
    aad.extend_from_slice(name.as_bytes());
    let nonce: [u8; 12] = blob[8..HEADER].try_into().expect("12-byte slice");
    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &blob[HEADER..],
                aad: &aad,
            },
        )
        .map(|p| drop(Zeroizing::new(p)))
        .is_ok()
}

/// (files the key opens, files checked) over the whole store.
fn probe(key: &[u8; 32]) -> (usize, usize) {
    // T4.06: the vault image, if there is one, counts as one more file.
    let (mut ok, mut total) = crate::daemon_vault::probe_image(key);
    let Ok(dir) = std::fs::read_dir(store::store_dir()) else {
        return (ok, total);
    };
    for e in dir.flatten() {
        let fname = e.file_name().to_string_lossy().to_string();
        let Some((uid, name)) = store::from_cred_name(&fname) else {
            continue;
        };
        if let Ok(blob) = std::fs::read(e.path()) {
            total += 1;
            ok += usize::from(opens(key, uid, &name, &blob));
        }
    }
    (ok, total)
}

fn audit_result(op: &'static str, uid: u32, username: &str, r: &Result<(), String>) {
    audit::log(&AuditEvent {
        op,
        name: None,
        uid,
        username,
        result: match r {
            Ok(()) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}

fn allowed(uid: u32) -> Result<(), String> {
    if !crate::user_mode() && uid != 0 {
        return Err("only root may manage the recovery kit of the shared store".into());
    }
    Ok(())
}

pub fn handle_create(uid: u32, username: &str, password: &[u8], k: u8, n: u8) -> Response {
    let mut shares = Vec::new();
    let mut fp = String::new();
    let r = (|| {
        allowed(uid)?;
        if crate::daemon_gate_registry::gates_for(uid) > 0 {
            return Err("stop running agent sessions first (kepr panic)".into());
        }
        let envelope = std::fs::read(crate::protected_master_key_path())
            .map_err(|_| "set a passphrase first (kepr lock), then retry")?;
        let key = key_unlock::unwrap(&envelope, password)?;
        let live = crypto::snapshot_key()?;
        if *key != *live {
            return Err("the passphrase does not match the running store".into());
        }
        fp = fingerprint(&key);
        for s in shamir::split(key.as_ref(), k, n)? {
            shares.push(ZeroString::from_string(shamir::encode(&s, &fp).to_string()));
        }
        Ok(())
    })();
    audit_result("recovery-kit", uid, username, &r);
    match r {
        Ok(()) => Response::RecoveryKitOk {
            fingerprint: fp,
            shares,
        },
        Err(e) => Response::fail(e),
    }
}

pub fn handle_restore(
    uid: u32,
    username: &str,
    shares: &[ZeroString],
    new_password: &[u8],
) -> Response {
    let mut summary = (String::new(), 0usize);
    let r = (|| {
        allowed(uid)?;
        if new_password.is_empty() {
            return Err("a new passphrase is required".into());
        }
        let mut parsed = Vec::new();
        let mut fps = Vec::new();
        for s in shares {
            let (share, fp) = shamir::decode(s.as_str())?;
            parsed.push(share);
            fps.push(fp);
        }
        if fps.windows(2).any(|w| w[0] != w[1]) {
            return Err("the shares come from different recovery kits".into());
        }
        let bytes = shamir::combine(&parsed)?;
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| "shares do not hold a master key")?,
        );
        let fp = fingerprint(&key);
        if fps.first() != Some(&fp) {
            return Err("the shares do not rebuild the key they were made from".into());
        }
        let (opened, total) = probe(&key);
        if opened == 0 {
            return Err(format!(
                "the rebuilt key opens none of the {total} credential file(s) here; \
                 copy the old credential store into place first"
            ));
        }
        // Never re-key a store whose loaded key still works: restore is
        // for a lost key. A locked store (forgotten passphrase) has no
        // loaded key, so restore goes ahead: k shares are the key itself,
        // so this grants nothing the shares don't already.
        if let Ok(live) = crypto::snapshot_key() {
            if probe(&live).0 > 0 {
                return Err("this store's current key still works; nothing to restore".into());
            }
        }
        let envelope = key_unlock::wrap(&key, new_password)?;
        crate::daemon_lock::install_protected_key(&envelope)?;
        let _ = crypto::lock_backend();
        crypto::unlock_backend(*key)?;
        summary = (fp, opened);
        Ok(())
    })();
    audit_result("recovery-restore", uid, username, &r);
    match r {
        Ok(()) => Response::RecoveryRestoreOk {
            fingerprint: summary.0,
            credentials_opened: summary.1,
        },
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_only_with_the_right_key_and_binding() {
        let key = [7u8; 32];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = [1u8; 12];
        let mut aad = 1000u32.to_le_bytes().to_vec();
        aad.extend_from_slice(b"API_KEY");
        let ct = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: b"\0\0\0\0\0\0\0\x01secret",
                    aad: &aad,
                },
            )
            .unwrap();
        let mut blob = b"kepr_v2\n".to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        assert!(opens(&key, 1000, "API_KEY", &blob));
        assert!(!opens(&[8u8; 32], 1000, "API_KEY", &blob));
        assert!(!opens(&key, 1001, "API_KEY", &blob));
        assert!(!opens(&key, 1000, "OTHER", &blob));
        assert!(!opens(&key, 1000, "API_KEY", &blob[..10]));
    }

    #[test]
    fn fingerprint_is_stable_and_short() {
        let a = fingerprint(&[1u8; 32]);
        assert_eq!(a.len(), 16);
        assert_eq!(a, fingerprint(&[1u8; 32]));
        assert_ne!(a, fingerprint(&[2u8; 32]));
    }
}
