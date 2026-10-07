// daemon_store/alias.rs — T11.5 aliases: `kepr ln ALIAS NAME`. An alias
// is a `.meta` with `alias_of` and no value file. `Get` resolves it to
// its target before any policy check (daemon_handlers_get.rs), so the
// target's seal / consent / FIDO2 / expiry apply unchanged and the alias
// never holds a copy of the value. One hop only: an alias of an alias is
// refused. `rm ALIAS` removes just the alias.

use kepr_core::protocol::{CredInfo, Response};
use kepr_core::protocol_store::StoreResponse;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry::{self, CredMeta};
use crate::store::{self, cred_exists, cred_path, validate_name};

fn meta_path(uid: u32, upper: &str) -> std::path::PathBuf {
    expiry::meta_path_for(&cred_path(uid, upper))
}

/// The target `upper` is an alias of, if it is one (no value file).
pub fn target_of(uid: u32, upper: &str) -> Option<String> {
    if cred_exists(uid, upper) {
        return None;
    }
    let target = expiry::read_meta(&meta_path(uid, upper))?.ok()?.alias_of?;
    validate_name(&target).ok().map(|_| target)
}

/// `Get`'s hook: the name to read for `upper`.
pub fn resolve(uid: u32, upper: &str) -> String {
    target_of(uid, upper).unwrap_or_else(|| upper.to_string())
}

pub fn handle_link(uid: u32, username: &str, alias: &str, target: &str) -> Response {
    let (alias, target) = (alias.to_uppercase(), target.to_uppercase());
    let _lock = crate::daemon_credlock::lock(uid, &alias);
    let r = link(uid, &alias, &target);
    audit::log(&AuditEvent {
        op: "link",
        name: Some(&alias),
        uid,
        username,
        result: match &r {
            Ok(()) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
    match r {
        Ok(()) => {
            crate::daemon_cache::invalidate(uid);
            Response::Store(StoreResponse::LinkOk { alias, target })
        }
        Err(e) => Response::fail(e),
    }
}

/// Make `alias` (locked by the caller) an alias of `target`.
pub fn link(uid: u32, alias: &str, target: &str) -> Result<(), String> {
    validate_name(alias)?;
    validate_name(target)?;
    if alias == target {
        return Err("an alias can't point at itself".into());
    }
    if cred_exists(uid, alias) {
        return Err(format!("{alias} already holds a value; kepr rm it first"));
    }
    if let Some(t) = target_of(uid, alias) {
        return Err(format!("{alias} is already an alias of {t}"));
    }
    if let Some(t) = target_of(uid, target) {
        return Err(format!(
            "{target} is itself an alias (of {t}); aliases of aliases are refused"
        ));
    }
    if !cred_exists(uid, target) {
        return Err(crate::crypto::SANITIZED_LOOKUP_ERROR.into());
    }
    let meta = CredMeta {
        alias_of: Some(target.to_string()),
        ..Default::default()
    };
    expiry::write_meta(&meta_path(uid, alias), &meta)
}

/// `rm` / `rm --force` on an alias: drop the alias, never the target.
pub fn remove_if_alias(uid: u32, username: &str, name: &str) -> Option<Response> {
    let upper = name.to_uppercase();
    validate_name(&upper).ok()?;
    let _lock = crate::daemon_credlock::lock(uid, &upper);
    target_of(uid, &upper)?;
    expiry::delete_meta(&meta_path(uid, &upper));
    crate::daemon_cache::invalidate(uid);
    audit::log(&AuditEvent {
        op: "unlink",
        name: Some(&upper),
        uid,
        username,
        result: AuditResult::Ok,
    });
    Some(Response::DeleteOk { name: upper })
}

/// The caller's aliases as `kepr ls` entries: `(name, meta)`.
pub fn aliases_of_uid(uid: u32) -> Vec<(String, CredMeta, std::path::PathBuf)> {
    let mut out: Vec<_> = super::files::meta_paths_of(uid)
        .into_iter()
        .filter_map(|p| {
            let base = p.file_name()?.to_str()?.strip_suffix(".meta")?;
            let (_, name) = store::from_cred_name(base)?;
            let meta = expiry::read_meta(&p)?.ok()?;
            (meta.alias_of.is_some() && !cred_exists(uid, &name)).then_some((name, meta, p))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

pub fn infos(uid: u32) -> Vec<CredInfo> {
    aliases_of_uid(uid)
        .into_iter()
        .map(|(name, meta, path)| CredInfo {
            cred_name: store::to_cred_name(uid, &name),
            name,
            size: 0,
            modified: store::file_mtime_str(&path),
            expires_at: None,
            requires_consent: None,
            requires_fido2: None,
            sealed: None,
            bound_hosts: None,
            record_type: None,
            tags: meta.tags,
            folder: meta.folder,
            alias_of: meta.alias_of,
            db_kind: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_handlers_get::handle_get;
    use crate::daemon_store::testkit;

    fn get(uid: u32, name: &str) -> Response {
        handle_get(uid, 0, "t", name, None)
    }

    #[test]
    fn get_via_alias_reads_the_target() {
        let uid = testkit::uid();
        testkit::set(uid, "AL_T", "the-value");
        assert!(handle_link(uid, "t", "al_a", "al_t").is_success());
        match get(uid, "AL_A") {
            Response::GetOk { name, value } => {
                assert_eq!(name, "AL_A");
                assert_eq!(value.as_str(), "the-value");
            }
            other => panic!("unexpected {other:?}"),
        }
        // The alias has no value of its own.
        assert!(!cred_exists(uid, "AL_A"));
        let ls = infos(uid);
        assert_eq!(ls.len(), 1);
        assert_eq!(ls[0].alias_of.as_deref(), Some("AL_T"));
        // A new value under the target shows through the alias.
        testkit::set(uid, "AL_T", "v2");
        assert!(
            matches!(get(uid, "AL_A"), Response::GetOk { value, .. } if value.as_str() == "v2")
        );
    }

    #[test]
    fn alias_of_alias_and_clashes_refused() {
        let uid = testkit::uid();
        testkit::set(uid, "AL_X", "v");
        testkit::set(uid, "AL_Y", "w");
        assert!(handle_link(uid, "t", "AL_1", "AL_X").is_success());
        let r = handle_link(uid, "t", "AL_2", "AL_1");
        assert!(r.err_msg().unwrap().contains("aliases of aliases"), "{r:?}");
        assert!(!handle_link(uid, "t", "AL_Y", "AL_X").is_success()); // holds a value
        assert!(!handle_link(uid, "t", "AL_1", "AL_Y").is_success()); // already an alias
        assert!(!handle_link(uid, "t", "AL_X", "AL_X").is_success());
        assert_eq!(
            handle_link(uid, "t", "AL_3", "NOPE").err_msg(),
            Some("credential unavailable")
        );
        assert!(!handle_link(uid, "t", "AL~1", "AL_X").is_success());
    }

    #[test]
    fn alias_to_a_sealed_cred_obeys_the_seal() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "AL_S", "sk-secret");
        assert!(handle_link(uid, "t", "AL_SA", "AL_S").is_success());
        assert_eq!(get(uid, "AL_SA").err_msg(), Some("credential unavailable"));
    }

    #[test]
    fn rm_alias_keeps_target_and_dangling_alias_is_unavailable() {
        let uid = testkit::uid();
        testkit::set(uid, "AL_K", "v");
        handle_link(uid, "t", "AL_KA", "AL_K");
        handle_link(uid, "t", "AL_KB", "AL_K");
        let r = crate::daemon_store::handle_rm(uid, "t", "AL_KA");
        assert!(matches!(r, Response::DeleteOk { .. }), "{r:?}");
        assert!(target_of(uid, "AL_KA").is_none());
        assert_eq!(testkit::value(uid, "AL_K").as_deref(), Some("v"));
        // Target trashed: the remaining alias stops resolving...
        crate::daemon_store::handle_rm(uid, "t", "AL_K");
        assert_eq!(get(uid, "AL_KB").err_msg(), Some("credential unavailable"));
        // ...and a restore of a name held by an alias is refused.
        crate::daemon_store::handle_rm(uid, "t", "AL_KB");
        handle_link(uid, "t", "AL_K", "AL_X_NONE"); // refused: no target
        testkit::set(uid, "AL_O", "o");
        handle_link(uid, "t", "AL_K", "AL_O");
        let r = super::super::trash::handle_restore(uid, "t", "AL_K");
        assert!(r.err_msg().unwrap().contains("exists again"), "{r:?}");
    }
}
