// daemon_store/wipe.rs — T11.9 `kepr delete --all --yes`: remove every
// credential of the caller (sealed, SSH and share keys included), their
// history slots, the trash and the aliases, as one `delete-all` audit
// event. Only entries named for the caller's SO_PEERCRED uid are touched
// (files, or the vault image's records with KEPR_STORE=image).

use kepr_core::protocol::Response;
use kepr_core::protocol_store::StoreResponse;

use super::files;
use crate::audit::{self, AuditEvent, AuditResult};
use crate::{crypto, daemon_cache, expiry};

pub fn handle_delete_all(uid: u32, username: &str, confirm: bool) -> Response {
    if !confirm {
        return Response::fail("delete-all needs explicit confirmation (--yes)");
    }
    let r = wipe(uid);
    daemon_cache::invalidate(uid);
    crate::daemon_gate::bump_generation();
    audit::log(&AuditEvent {
        op: "delete-all",
        name: None,
        uid,
        username,
        result: match &r {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
    match r {
        Ok(deleted) => Response::Store(StoreResponse::DeleteAllOk { deleted }),
        Err(e) => Response::fail(e),
    }
}

/// Returns how many credentials and aliases were removed.
fn wipe(uid: u32) -> Result<usize, String> {
    // A locked image lists nothing: never report that as an empty store.
    if crate::daemon_vault::active().is_some() && crypto::backend_is_locked() {
        return Err("credential store is locked; unlock it first".into());
    }
    let deleted = daemon_cache::list_for_uid(uid).len() + super::alias::aliases_of_uid(uid).len();
    let mut failed = 0;
    for (name, _) in files::all_of(uid) {
        let base = name.split('~').next().unwrap_or(&name).to_string();
        let _lock = crate::daemon_credlock::lock(uid, &base);
        if let Err(e) = crypto::default_backend().delete(uid, &name) {
            eprintln!("[kepr-daemon] delete-all: {e}");
            failed += 1;
        }
    }
    // Sidecars: credential, alias, trash and orphan metas (in the image,
    // what is left once the values are gone: meta-only records).
    for p in files::meta_paths_of(uid) {
        expiry::delete_meta(&p);
    }
    if failed > 0 {
        return Err(format!("{failed} stored value(s) could not be deleted"));
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    #[test]
    fn refuses_without_confirmation() {
        let uid = testkit::uid();
        testkit::set(uid, "WIPE_KEEP", "v");
        assert!(!handle_delete_all(uid, "t", false).is_success());
        assert!(testkit::value(uid, "WIPE_KEEP").is_some());
    }

    #[test]
    fn deletes_everything_of_the_caller_only() {
        let (me, other) = (testkit::uid(), testkit::uid());
        testkit::set(me, "W_A", "1");
        testkit::set(me, "W_A", "2"); // a history slot
        testkit::set_sealed(me, "W_S", "sk");
        testkit::set(me, "W_T", "t");
        crate::daemon_store::handle_rm(me, "t", "W_T"); // a trash entry
        super::super::alias::handle_link(me, "t", "W_L", "W_A");
        testkit::set(other, "W_A", "theirs");

        match handle_delete_all(me, "t", true) {
            Response::Store(StoreResponse::DeleteAllOk { deleted }) => assert_eq!(deleted, 3),
            other => panic!("unexpected {other:?}"),
        }
        assert!(files::all_of(me).is_empty());
        let prefix = format!("kepr-{me}-");
        let left: Vec<_> = std::fs::read_dir(crate::store::store_dir())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
            .collect();
        assert!(left.is_empty(), "left behind: {left:?}");
        assert_eq!(testkit::value(other, "W_A").as_deref(), Some("theirs"));
    }
}
