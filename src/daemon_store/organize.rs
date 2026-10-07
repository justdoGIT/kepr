// daemon_store/organize.rs — T5.01 tags and folders. They live in the
// credential's `.meta` (`tags`, `folder`); `Organize` is a read-modify-
// write of that file under the credential lock, so every other flag
// (seal, bindings, TTL, consent) is kept as it is. `handle_set` rewrites
// `.meta` from its flags, so it calls `carry_over` to keep them.

use kepr_core::protocol::Response;
use kepr_core::protocol_store::StoreResponse;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry::{self, CredMeta};
use crate::store::{cred_exists, cred_path, validate_name};

pub const MAX_TAGS: usize = 16;
const MAX_TAG_LEN: usize = 32;
const MAX_FOLDER_LEN: usize = 128;

fn alphabet(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
}

pub fn validate_tag(t: &str) -> Result<(), String> {
    if (1..=MAX_TAG_LEN).contains(&t.len()) && t.bytes().all(alphabet) {
        Ok(())
    } else {
        Err(format!("invalid tag {t:?}: use 1-32 of a-z, 0-9, _ and -"))
    }
}

/// `"/a/b/"` → `Some("a/b")`; `"/"` or `""` → `None` (no folder).
pub fn normalize_folder(f: &str) -> Result<Option<String>, String> {
    let trimmed = f.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(None);
    }
    let ok = trimmed.len() <= MAX_FOLDER_LEN
        && trimmed
            .split('/')
            .all(|seg| !seg.is_empty() && seg.bytes().all(alphabet));
    if ok {
        Ok(Some(trimmed.to_string()))
    } else {
        Err(format!(
            "invalid folder {f:?}: /-separated a-z, 0-9, _ and -, at most 128 chars"
        ))
    }
}

/// Apply tag additions / removals and an optional folder change to
/// `meta`. Pure; idempotent (tags are a sorted set).
pub fn apply(
    meta: &mut CredMeta,
    add: &[String],
    remove: &[String],
    folder: Option<&str>,
) -> Result<(), String> {
    for t in add.iter().chain(remove) {
        validate_tag(t)?;
    }
    let mut tags: std::collections::BTreeSet<String> =
        meta.tags.take().unwrap_or_default().into_iter().collect();
    tags.extend(add.iter().cloned());
    for t in remove {
        tags.remove(t);
    }
    if tags.len() > MAX_TAGS {
        return Err(format!("at most {MAX_TAGS} tags per credential"));
    }
    meta.tags = (!tags.is_empty()).then(|| tags.into_iter().collect());
    if let Some(f) = folder {
        meta.folder = normalize_folder(f)?;
    }
    Ok(())
}

/// Keep the tags and folder of the credential being replaced (`set`).
pub fn carry_over(uid: u32, upper: &str, meta: &mut CredMeta) {
    if let Some(Ok(old)) = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))) {
        meta.tags = old.tags;
        meta.folder = old.folder;
    }
}

pub fn handle_organize(
    uid: u32,
    username: &str,
    name: &str,
    (add, remove): (&[String], &[String]),
    folder: Option<&str>,
) -> Response {
    let upper = name.to_uppercase();
    let _lock = crate::daemon_credlock::lock(uid, &upper);
    let r = organize(uid, &upper, add, remove, folder);
    audit::log(&AuditEvent {
        op: "organize",
        name: Some(&upper),
        uid,
        username,
        result: match &r {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
    match r {
        Ok(m) => Response::Store(StoreResponse::OrganizeOk {
            name: upper,
            tags: m.tags.unwrap_or_default(),
            folder: m.folder,
        }),
        Err(e) => Response::fail(e),
    }
}

fn organize(
    uid: u32,
    upper: &str,
    add: &[String],
    remove: &[String],
    folder: Option<&str>,
) -> Result<CredMeta, String> {
    validate_name(upper)?;
    let mp = expiry::meta_path_for(&cred_path(uid, upper));
    let meta = match expiry::read_meta(&mp) {
        None => CredMeta::default(),
        Some(Ok(m)) => m,
        // Never rewrite a meta this daemon can't read: it may hold a
        // seal written by a newer version.
        Some(Err(_)) => return Err("credential metadata unreadable".into()),
    };
    if !cred_exists(uid, upper) && meta.alias_of.is_none() {
        return Err(crate::crypto::SANITIZED_LOOKUP_ERROR.into());
    }
    let mut new = meta.clone();
    apply(&mut new, add, remove, folder)?;
    if new != meta {
        if new.is_empty() {
            expiry::delete_meta(&mp);
        } else {
            expiry::write_meta(&mp, &new)?;
        }
    }
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn tags_of(r: &Response) -> Vec<String> {
        match r {
            Response::Store(StoreResponse::OrganizeOk { tags, .. }) => tags.clone(),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn tag_and_folder_validation() {
        assert!(validate_tag("work").is_ok());
        assert!(validate_tag("ci-2_x").is_ok());
        for bad in ["", "Work", "a b", "a/b", &"x".repeat(33), "ü"] {
            assert!(validate_tag(bad).is_err(), "{bad:?}");
        }
        assert_eq!(normalize_folder("/").unwrap(), None);
        assert_eq!(normalize_folder("").unwrap(), None);
        assert_eq!(normalize_folder("/a/b-c/").unwrap(), Some("a/b-c".into()));
        assert!(normalize_folder("a//b").is_err());
        assert!(normalize_folder("A").is_err());
        assert!(normalize_folder("a/..").is_err());
        assert!(normalize_folder(&"a".repeat(129)).is_err());
    }

    #[test]
    fn add_and_remove_are_idempotent_and_capped() {
        let mut m = CredMeta::default();
        apply(&mut m, &s(&["b", "a", "a"]), &[], None).unwrap();
        apply(&mut m, &s(&["a"]), &s(&["zz"]), None).unwrap();
        assert_eq!(m.tags, Some(s(&["a", "b"])));
        apply(&mut m, &[], &s(&["a", "b"]), None).unwrap();
        assert_eq!(m.tags, None);
        assert!(m.is_empty());
        let many: Vec<String> = (0..17).map(|i| format!("t{i}")).collect();
        assert!(apply(&mut m, &many, &[], None).is_err());
        assert!(apply(&mut m, &s(&["Bad"]), &[], None).is_err());
    }

    #[test]
    fn mv_sets_and_slash_clears_the_folder() {
        let uid = testkit::uid();
        testkit::set(uid, "ORG_A", "v");
        let r = handle_organize(uid, "t", "org_a", (&[], &[]), Some("work/ci"));
        assert!(r.is_success(), "{r:?}");
        assert_eq!(
            testkit::meta(uid, "ORG_A").folder.as_deref(),
            Some("work/ci")
        );
        handle_organize(uid, "t", "ORG_A", (&[], &[]), Some("/"));
        assert_eq!(testkit::meta(uid, "ORG_A").folder, None);
        // Nothing left: no meta file at all.
        assert!(!expiry::meta_path_for(&cred_path(uid, "ORG_A")).exists());
    }

    #[test]
    fn invalid_tag_refused_and_unknown_name_unavailable() {
        let uid = testkit::uid();
        testkit::set(uid, "ORG_B", "v");
        let r = handle_organize(uid, "t", "ORG_B", (&s(&["Nope"]), &[]), None);
        assert!(!r.is_success());
        assert!(testkit::meta(uid, "ORG_B").tags.is_none());
        let r = handle_organize(uid, "t", "MISSING", (&s(&["a"]), &[]), None);
        assert_eq!(r.err_msg(), Some("credential unavailable"));
        let r = handle_organize(uid, "t", "../X", (&s(&["a"]), &[]), None);
        assert!(!r.is_success());
    }

    #[test]
    fn tags_survive_set_restore_and_seal() {
        let uid = testkit::uid();
        testkit::set(uid, "ORG_C", "one");
        let r = handle_organize(uid, "t", "ORG_C", (&s(&["work"]), &[]), Some("team"));
        assert_eq!(tags_of(&r), s(&["work"]));
        testkit::set(uid, "ORG_C", "two"); // saves "one" as history version 1
        assert_eq!(testkit::meta(uid, "ORG_C").tags, Some(s(&["work"])));
        assert_eq!(testkit::meta(uid, "ORG_C").folder.as_deref(), Some("team"));
        let r = crate::daemon_history::handle_restore(uid, "t", "ORG_C", 1);
        assert!(r.is_success(), "{r:?}");
        assert_eq!(testkit::value(uid, "ORG_C").as_deref(), Some("one"));
        assert_eq!(testkit::meta(uid, "ORG_C").tags, Some(s(&["work"])));

        testkit::set_sealed(uid, "ORG_S", "sk-1");
        handle_organize(uid, "t", "ORG_S", (&s(&["prod"]), &[]), None);
        testkit::set_sealed(uid, "ORG_S", "sk-2");
        let m = testkit::meta(uid, "ORG_S");
        assert_eq!(m.tags, Some(s(&["prod"])));
        assert_eq!(m.sealed, Some(true));
        assert!(m.bindings.is_some());
    }
}
