// daemon_store/dupes.rs — T11.4 duplicate finder. The daemon decrypts the
// caller's values, compares SHA-256 digests in memory and returns only
// groups of names. Gated values (`CredMeta::gated`: sealed, SSH, share
// key, prompts, windows, exe binding, approvals) and expired ones are left
// out, so the finder can't be used to test a guess against them.
// `--merge KEEP` moves the other members of KEEP's group to the trash and
// makes each an alias of KEEP (T11.5), keeping its tags and folder.

use std::collections::BTreeMap;

use kepr_core::protocol::Response;
use kepr_core::protocol_store::StoreResponse;
use sha2::{Digest, Sha256};

use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};
use crate::{crypto, daemon_cache};

type Digest32 = [u8; 32];

fn meta_of(uid: u32, name: &str) -> Option<CredMeta> {
    match expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, name))) {
        None => Some(CredMeta::default()),
        Some(Ok(m)) => Some(m),
        Some(Err(_)) => None,
    }
}

/// The digest of `name`'s value, if it may take part.
fn digest(uid: u32, name: &str, now: u64) -> Option<Digest32> {
    let meta = meta_of(uid, name)?;
    if !super::files::readable_without_prompt(&meta, now) {
        return None;
    }
    let _lock = crate::daemon_credlock::lock(uid, name);
    let v = crypto::default_backend().decrypt(uid, name).ok()?;
    Some(Sha256::digest(v.as_bytes()).into())
}

/// Groups of two or more names with the same value, sorted.
fn groups(uid: u32) -> Vec<Vec<String>> {
    let now = expiry::now_unix();
    let mut by: BTreeMap<Digest32, Vec<String>> = BTreeMap::new();
    for (name, _) in daemon_cache::list_for_uid(uid) {
        if let Some(d) = digest(uid, &name, now) {
            by.entry(d).or_default().push(name);
        }
    }
    let mut out: Vec<Vec<String>> = by.into_values().filter(|g| g.len() > 1).collect();
    for g in &mut out {
        g.sort();
    }
    out.sort();
    out
}

fn log(op: &str, uid: u32, username: &str, name: Option<&str>, r: &Result<(), String>) {
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

pub fn handle_dupes(uid: u32, username: &str) -> Response {
    let groups = groups(uid);
    log("dupes", uid, username, None, &Ok(()));
    Response::Store(StoreResponse::DupesOk { groups })
}

pub fn handle_merge(uid: u32, username: &str, keep: &str) -> Response {
    let keep = keep.to_uppercase();
    let r = merge(uid, &keep);
    log(
        "dupes-merge",
        uid,
        username,
        Some(&keep),
        &r.as_ref().map(|_| ()).map_err(Clone::clone),
    );
    match r {
        Ok(aliased) => {
            daemon_cache::invalidate(uid);
            crate::daemon_gate::bump_generation();
            Response::Store(StoreResponse::DupesMergeOk { keep, aliased })
        }
        Err(e) => Response::fail(e),
    }
}

fn merge(uid: u32, keep: &str) -> Result<Vec<String>, String> {
    validate_name(keep)?;
    let group = groups(uid)
        .into_iter()
        .find(|g| g.iter().any(|n| n == keep))
        .ok_or_else(|| format!("{keep} has no duplicates (see: kepr dupes)"))?;
    let now = expiry::now_unix();
    let want = digest(uid, keep, now).ok_or("credential unavailable")?;
    let mut aliased = Vec::new();
    for other in group.iter().filter(|n| *n != keep) {
        let _lock = crate::daemon_credlock::lock(uid, other);
        // Re-check under the lock: the value may have changed since.
        if digest(uid, other, now) != Some(want) {
            continue;
        }
        let old = meta_of(uid, other).unwrap_or_default();
        let kept = match super::trash::days() {
            0 => None,
            _ => super::trash::move_to_trash(uid, other, now)?,
        };
        if kept.is_none() {
            crypto::default_backend().delete(uid, other)?;
            expiry::delete_meta(&expiry::meta_path_for(&cred_path(uid, other)));
            crate::daemon_history::purge(uid, other);
        }
        super::alias::link(uid, other, keep)?;
        let alias = CredMeta {
            alias_of: Some(keep.to_string()),
            tags: old.tags,
            folder: old.folder,
            ..Default::default()
        };
        expiry::write_meta(&expiry::meta_path_for(&cred_path(uid, other)), &alias)?;
        aliased.push(other.clone());
    }
    Ok(aliased)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn groups_of(uid: u32) -> Vec<Vec<String>> {
        match handle_dupes(uid, "t") {
            Response::Store(StoreResponse::DupesOk { groups }) => groups,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn groups_same_values_and_leaves_sealed_out() {
        let uid = testkit::uid();
        testkit::set(uid, "D_A", "same");
        testkit::set(uid, "D_B", "same");
        testkit::set(uid, "D_C", "other");
        testkit::set(uid, "D_D", "other");
        testkit::set(uid, "D_E", "unique");
        testkit::set_sealed(uid, "D_S", "same");
        let consent = crate::daemon_handlers::SetFlags {
            requires_consent: Some(true),
            ..Default::default()
        };
        let r = crate::daemon_handlers::handle_set(uid, "t", "D_G", Some("same"), None, consent);
        assert!(r.is_success());
        assert_eq!(
            groups_of(uid),
            vec![
                vec!["D_A".to_string(), "D_B".into()],
                vec!["D_C".into(), "D_D".into()]
            ]
        );
    }

    #[test]
    fn merge_leaves_aliases_resolving_to_keep() {
        let uid = testkit::uid();
        testkit::set(uid, "M_KEEP", "dup");
        testkit::set(uid, "M_X", "dup");
        testkit::set(uid, "M_Y", "dup");
        super::super::organize::handle_organize(uid, "t", "M_X", (&["ci".into()], &[]), None);
        match handle_merge(uid, "t", "m_keep") {
            Response::Store(StoreResponse::DupesMergeOk { aliased, .. }) => {
                assert_eq!(aliased, vec!["M_X".to_string(), "M_Y".into()])
            }
            other => panic!("unexpected {other:?}"),
        }
        for n in ["M_X", "M_Y"] {
            assert_eq!(
                super::super::alias::target_of(uid, n).as_deref(),
                Some("M_KEEP")
            );
            match crate::daemon_handlers_get::handle_get(uid, 0, "t", n, None) {
                Response::GetOk { value, .. } => assert_eq!(value.as_str(), "dup"),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(testkit::meta(uid, "M_X").tags, Some(vec!["ci".to_string()]));
        assert!(groups_of(uid).is_empty());
        // The old values are in the trash, not lost.
        assert_eq!(super::super::files::all_of(uid).len(), 3);
        assert!(!handle_merge(uid, "t", "M_KEEP").is_success());
    }
}
