// daemon_sharing/escrow.rs — T6.14 account-transfer escrow.
//
//   kepr escrow enable ADMIN_KEY   wrap the master key to an administrator's
//                                  share key (a key or a pinned contact) in
//                                  `escrow.bin` in the state directory
//   kepr escrow disable | status   (`kepr status` shows it too)
//   kepr escrow open FILE          on the admin's machine: unwrap with the
//                                  admin's share key → a 2-of-2 recovery kit
//                                  for `kepr recovery-kit restore` next to
//                                  the old credential files
//
// escrow.bin is JSON: who it is for, the master key's fingerprint, and a
// v2 share envelope (kem.rs) over "kepr-escrow-v1\0" ‖ key. Only the
// admin's share key opens it; it is not a share (`share receive` can't
// store it).
//
// Enabling hands key material to someone else, so it is fenced like the
// recovery kit (AGENTS.md): passphrase-protected store and the passphrase
// checked again, the owner only (root in system mode), refused while any
// agent gate runs, audited (`escrow-enable`, `escrow-disable`,
// `escrow-open`). Opening needs the admin's own share key, no running
// gate of theirs, and the key fingerprint to match.

use std::path::PathBuf;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::SharingResponse;
use kepr_core::shamir;
use zeroize::Zeroizing;

use super::contacts::{fingerprint as key_fp, resolve};
use super::kem::{self, Recipient, ShareSecret};
use super::{audit_r, load, save, state_root};
use crate::daemon_recovery::fingerprint;
use crate::expiry::{format_expires_at, now_unix};

const FILE: &str = "escrow.bin";
const MAGIC: &[u8] = b"kepr-escrow-v1\0";

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub(crate) struct EscrowFile {
    pub v: u8,
    /// The admin's contact name (or `key:<fingerprint>`).
    pub admin: String,
    pub admin_public: String,
    /// `daemon_recovery::fingerprint` of the escrowed master key.
    pub key_fingerprint: String,
    pub created: u64,
    pub envelope: String,
}

pub(crate) fn path() -> PathBuf {
    state_root().join(FILE)
}

pub(crate) fn wrap(
    key: &[u8; 32],
    admin: &Recipient,
    label: &str,
    now: u64,
) -> Result<EscrowFile, String> {
    let payload = Zeroizing::new([MAGIC, key].concat());
    Ok(EscrowFile {
        v: 1,
        admin: label.to_string(),
        admin_public: admin.text(),
        key_fingerprint: fingerprint(key),
        created: now,
        envelope: kem::seal(admin, &payload)?,
    })
}

pub(crate) fn unwrap(f: &EscrowFile, me: &ShareSecret) -> Result<Zeroizing<[u8; 32]>, String> {
    let plain = kem::open(me, &f.envelope).map_err(|_| "this escrow is not for your share key")?;
    let raw = plain
        .strip_prefix(MAGIC)
        .filter(|k| k.len() == 32)
        .ok_or("not a kepr escrow")?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(raw);
    if fingerprint(&key) != f.key_fingerprint {
        return Err("the escrow file was altered".into());
    }
    Ok(key)
}

/// The enable fences, apart from the passphrase check.
pub(crate) fn fences(
    uid: u32,
    user_mode: bool,
    gate_running: bool,
    protected: bool,
) -> Result<(), String> {
    if !user_mode && uid != 0 {
        return Err("only root may escrow the shared store's key".into());
    }
    if gate_running {
        return Err("stop running agent sessions first (kepr panic)".into());
    }
    if !protected {
        return Err("set a passphrase first (kepr lock), then retry".into());
    }
    Ok(())
}

fn gates_running() -> bool {
    crate::daemon_gate_registry::GATES
        .lock()
        .map_or(true, |g| !g.is_empty())
}

/// Write the escrow for `key` (already checked to be the live key).
pub(crate) fn enable_with(
    uid: u32,
    admin_key: &str,
    key: &[u8; 32],
    now: u64,
) -> Result<String, String> {
    let (admin, label) = resolve(uid, admin_key)?;
    let file = wrap(key, &admin, &label, now)?;
    save(&path(), &file)?;
    Ok(format!(
        "escrow on: give {} to {label} ({}); they recover this store's key with \
         `kepr escrow open FILE`",
        path().display(),
        key_fp(&file.admin_public)
    ))
}

pub fn handle_enable(uid: u32, username: &str, admin_key: &str, password: &[u8]) -> Response {
    let r = (|| {
        let protected = crate::protected_master_key_path().exists();
        fences(uid, crate::user_mode(), gates_running(), protected)?;
        // Rate-limited like `kepr unlock`.
        let key = crate::daemon_session::unlock_guard::unwrap_guarded(password, uid, username)?;
        let live = crate::crypto::snapshot_key()?;
        if *key != *live {
            return Err("the passphrase does not match the running store".into());
        }
        enable_with(uid, admin_key, &live, now_unix())
    })();
    audit_r("escrow-enable", uid, username, None, &r);
    super::reply(r)
}

pub fn handle_disable(uid: u32, username: &str) -> Response {
    let r = (|| {
        fences(uid, crate::user_mode(), false, true)?;
        match std::fs::remove_file(path()) {
            Ok(()) => Ok("escrow off: escrow.bin deleted".to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err("escrow is not on".into()),
            Err(e) => Err(format!("cannot delete escrow.bin: {e}")),
        }
    })();
    audit_r("escrow-disable", uid, username, None, &r);
    super::reply(r)
}

pub fn handle_status() -> Response {
    let on = path().exists();
    let f: EscrowFile = if on {
        load(&path())
    } else {
        EscrowFile::default()
    };
    SharingResponse::EscrowState {
        enabled: on,
        admin: on.then(|| f.admin.clone()),
        admin_fingerprint: on.then(|| key_fp(&f.admin_public)),
        since: on.then(|| format_expires_at(f.created)),
    }
    .into()
}

/// Admin side: the escrowed key as a 2-of-2 recovery kit.
pub(crate) fn open_with(uid: u32, text: &str, gate_running: bool) -> Result<Response, String> {
    if gate_running {
        return Err("stop running agent sessions first (kepr panic)".into());
    }
    let f: EscrowFile = serde_json::from_str(text.trim()).map_err(|_| "not a kepr escrow file")?;
    let key = unwrap(&f, &crate::daemon_share::load_secret(uid)?)?;
    let fp = fingerprint(&key);
    let shares = shamir::split(key.as_ref(), 2, 2)?
        .iter()
        .map(|s| ZeroString::from_string(shamir::encode(s, &fp).to_string()))
        .collect();
    Ok(Response::RecoveryKitOk {
        fingerprint: fp,
        shares,
    })
}

pub fn handle_open(uid: u32, username: &str, text: &str) -> Response {
    let gate = crate::daemon_gate_registry::gates_for(uid) > 0;
    let r = open_with(uid, text, gate);
    audit_r("escrow-open", uid, username, None, &r);
    r.unwrap_or_else(Response::fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn key_of(uid: u32) -> String {
        match crate::daemon_share::handle_key(uid, "t", true) {
            Response::ShareKeyOk { public } => public,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn wrap_unwrap_round_trip_and_another_key_cant_open() {
        let (admin, other) = (
            ShareSecret::generate().unwrap(),
            ShareSecret::generate().unwrap(),
        );
        let key = [0x42u8; 32];
        let f = wrap(&key, &admin.recipient(), "it", 7).unwrap();
        assert!(!f.envelope.contains(&hex::encode(key)));
        assert_eq!(*unwrap(&f, &admin).unwrap(), key);
        assert!(unwrap(&f, &other)
            .unwrap_err()
            .contains("not for your share key"));
        let mut altered = EscrowFile {
            key_fingerprint: "0000000000000000".into(),
            ..f
        };
        assert!(unwrap(&altered, &admin).is_err());
        altered.envelope = "kepr-share2-AAAA".into();
        assert!(unwrap(&altered, &admin).is_err());
    }

    #[test]
    fn enable_status_open_disable() {
        let (owner, admin, other) = (testkit::uid(), testkit::uid(), testkit::uid());
        let (ka, _) = (key_of(admin), key_of(other));
        let key = [0x17u8; 32];
        assert!(
            enable_with(owner, "it-admin", &key, 1).is_err(),
            "not pinned"
        );
        assert!(super::super::contacts::handle_add(owner, "t", "it-admin", &ka).is_success());
        enable_with(owner, "it-admin", &key, 86_400).unwrap();
        let Response::Sharing(SharingResponse::EscrowState {
            enabled,
            admin: who,
            since,
            ..
        }) = handle_status()
        else {
            panic!("no status");
        };
        assert!(enabled);
        assert_eq!(who.as_deref(), Some("it-admin"));
        assert_eq!(since.as_deref(), Some("1970-01-02 00:00"));
        // The admin opens it into a 2-of-2 kit that rebuilds the key.
        let text = std::fs::read_to_string(path()).unwrap();
        let Ok(Response::RecoveryKitOk {
            fingerprint: fp,
            shares,
        }) = open_with(admin, &text, false)
        else {
            panic!("admin can't open");
        };
        assert_eq!(fp, fingerprint(&key));
        let parsed: Vec<_> = shares
            .iter()
            .map(|s| shamir::decode(s.as_str()).unwrap().0)
            .collect();
        assert_eq!(shamir::combine(&parsed).unwrap().as_slice(), &key);
        // Another user's key can't, nor the admin while a gate runs.
        assert!(open_with(other, &text, false).is_err());
        assert!(open_with(admin, &text, true).is_err());
        // Disabling deletes the file.
        assert!(handle_disable(0, "root").is_success());
        assert!(!path().exists());
        assert!(!handle_disable(0, "root").is_success());
        let Response::Sharing(SharingResponse::EscrowState { enabled, .. }) = handle_status()
        else {
            panic!("no status");
        };
        assert!(!enabled);
    }

    #[test]
    fn enable_is_fenced_like_the_recovery_kit() {
        assert!(fences(0, false, false, true).is_ok());
        assert!(fences(1000, true, false, true).is_ok());
        assert!(fences(1000, false, false, true)
            .unwrap_err()
            .contains("only root"));
        assert!(fences(0, false, true, true)
            .unwrap_err()
            .contains("agent sessions"));
        assert!(fences(0, false, false, false)
            .unwrap_err()
            .contains("passphrase"));
    }
}
