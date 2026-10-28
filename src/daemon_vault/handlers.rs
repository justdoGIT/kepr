// daemon_vault/handlers.rs — `kepr vault init|migrate|verify|status`
// (T4.07), routed here from daemon_extra.rs.
//
// init and migrate change the store for every user, so only its owner
// runs them: the user in user mode, root for the shared store; migrate
// also waits until no agent gate runs and the image store is active
// (moving into an image the daemon doesn't read would hide them). verify
// and status are open to everyone, but what spans other users (record
// and slot counts, the exact fill, the epoch) goes to the owner only;
// others see the fill rounded up to 10 %. No reply carries a name or a
// value. Every call is audited (`vault-init`, `vault-migrate`, ...).

use std::sync::{Mutex, TryLockError};

use kepr_core::protocol::Response;
use kepr_core::protocol_vault::{VaultRequest, VaultResponse};

use super::admin::Usage;
use super::backend::ImageBackend;
use crate::audit::{self, AuditEvent, AuditResult};

pub fn dispatch(uid: u32, _peer_pid: i32, username: &str, r: VaultRequest) -> Response {
    let (op, r) = match r {
        VaultRequest::VaultInit { size_mib } => ("vault-init", init(uid, size_mib)),
        VaultRequest::VaultMigrate => ("vault-migrate", migrate(uid)),
        VaultRequest::VaultVerify => ("vault-verify", verify(uid)),
        VaultRequest::VaultStatus => ("vault-status", Ok(status(uid))),
    };
    audit::log(&AuditEvent {
        op,
        name: None,
        uid,
        username,
        result: match &r {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
    match r {
        Ok(v) => Response::Vault(v),
        Err(e) => Response::fail(e),
    }
}

fn is_owner(uid: u32) -> bool {
    crate::user_mode() || uid == 0
}

fn owner_only(uid: u32) -> Result<(), String> {
    if is_owner(uid) {
        Ok(())
    } else {
        Err("only root may manage the vault image of the shared store".into())
    }
}

/// The active image backend, or (per-file store active) a backend over
/// the image file, so init / verify / status work in both modes, and an
/// image made by `init` is anchored to the counter either way.
fn with_backend<T>(f: impl FnOnce(&ImageBackend) -> T) -> T {
    match super::active() {
        Some(b) => f(b),
        None => f(&super::backend_at(super::image_path())),
    }
}

fn init(uid: u32, size_mib: u32) -> Result<VaultResponse, String> {
    owner_only(uid)?;
    with_backend(|b| b.create(size_mib))?;
    Ok(VaultResponse::VaultInitOk { size_mib })
}

/// Any user's agent gate: migrate moves every user's credentials, and a
/// gate resolving a sealed value mid-move would see it vanish.
fn gates_running() -> bool {
    // A poisoned registry can't say: assume one runs.
    crate::daemon_gate_registry::GATES
        .lock()
        .map_or(true, |g| !g.is_empty())
}

/// One migrate at a time: a second would find the first's files half gone.
static MIGRATING: Mutex<()> = Mutex::new(());

fn migrate(uid: u32) -> Result<VaultResponse, String> {
    owner_only(uid)?;
    if gates_running() {
        return Err("stop running agent sessions first (kepr panic)".into());
    }
    let image = super::active()
        .ok_or("the per-file store is active: start the daemon with KEPR_STORE=image first")?;
    let _one = match MIGRATING.try_lock() {
        Ok(g) => g,
        Err(TryLockError::Poisoned(p)) => p.into_inner(),
        Err(TryLockError::WouldBlock) => return Err("a vault migrate is already running".into()),
    };
    let files = crate::crypto::file_backend().ok_or("credential backend is not initialized")?;
    let r = super::migrate::migrate_from(image, files, &crate::store::store_dir());
    // Gates re-fetch: values now resolve from the image.
    crate::daemon_gate::bump_generation();
    let (migrated, skipped) = r?;
    Ok(VaultResponse::VaultMigrateOk { migrated, skipped })
}

fn verify(uid: u32) -> Result<VaultResponse, String> {
    let (records, slots) =
        with_backend(|b| b.check())?.ok_or("there is no vault image (kepr vault init)")?;
    let owner = is_owner(uid);
    Ok(VaultResponse::VaultVerifyOk {
        records: owner.then_some(records),
        slots: owner.then_some(slots),
    })
}

/// Fill in percent, rounded up to 10 % unless `exact`.
fn percent(u: &Usage, exact: bool) -> u8 {
    let p = (u.used_slots * 100).div_ceil(u.data_slots.max(1)).min(100) as u8;
    if exact {
        p
    } else {
        p.div_ceil(10) * 10
    }
}

fn status(uid: u32) -> VaultResponse {
    let owner = is_owner(uid);
    let dir = crate::store::store_dir();
    let legacy = super::migrate::legacy_files(&dir, (!owner).then_some(uid)).len();
    let image = super::image_path().exists();
    // Needs the key: while the store is locked only the rest shows.
    let usage = image
        .then(|| with_backend(|b| b.usage()).ok().flatten())
        .flatten();
    let own = usage.as_ref().filter(|_| owner);
    VaultResponse::VaultStatusOk {
        backend: if super::active().is_some() {
            "image"
        } else {
            "file"
        }
        .into(),
        image,
        size_mib: usage.as_ref().map(|u| u.size_mib),
        used_percent: usage.as_ref().map(|u| percent(u, owner)),
        used_slots: own.map(|u| u.used_slots),
        epoch: own.map(|u| u.epoch),
        legacy_files: legacy,
        rollback_guard: Some(super::rollback_guard().into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(used: u64, data: u64) -> Usage {
        Usage {
            size_mib: 1,
            used_slots: used,
            data_slots: data,
            epoch: 1,
        }
    }

    #[test]
    fn migrate_is_refused_while_any_agent_gate_runs() {
        use crate::daemon_gate_registry::{track_gate, Handle};
        let (conn, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        // Another user's gate: migrate moves every user's credentials.
        track_gate(-3_999_001, 3_999_001, Some(Handle::Conn(conn)));
        let r = migrate(0);
        track_gate(-3_999_001, 3_999_001, None);
        let err = r.expect_err("refused");
        assert!(err.contains("agent session"), "{err}");
    }

    #[test]
    fn others_see_the_fill_rounded_up_to_ten_percent() {
        assert_eq!(percent(&usage(0, 254), true), 0);
        assert_eq!(percent(&usage(3, 254), true), 2);
        assert_eq!(percent(&usage(3, 254), false), 10);
        assert_eq!(percent(&usage(0, 254), false), 0);
        assert_eq!(percent(&usage(254, 254), false), 100);
        assert_eq!(percent(&usage(127, 254), false), 50);
        assert_eq!(percent(&usage(128, 254), false), 60);
    }
}
