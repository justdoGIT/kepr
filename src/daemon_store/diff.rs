// daemon_store/diff.rs — T11.3 `kepr history NAME --diff A B`: which
// record fields changed between two versions (0 = the current value,
// 1 = the newest saved one). Field names only, never values; for a plain
// value just "changed". Both versions stay in the daemon.
//
// Refused for credentials `get` protects (sealed, SSH, share key,
// consent / FIDO2-gated, expired) and for versions saved while sealed:
// `set` needs no prompt, so set-a-guess-then-diff would otherwise tell
// whether a protected value equals the guess.

use std::collections::BTreeMap;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_store::{FieldChange, StoreResponse};

use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry;
use crate::store::{cred_path, validate_name};

pub fn handle_diff(uid: u32, username: &str, name: &str, from: u32, to: u32) -> Response {
    let upper = name.to_uppercase();
    let _lock = crate::daemon_credlock::lock(uid, &upper);
    let r = diff(uid, &upper, from, to);
    audit::log(&AuditEvent {
        op: "history-diff",
        name: Some(&upper),
        uid,
        username,
        result: match &r {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
    match r {
        Ok(changes) => Response::Store(StoreResponse::HistoryDiffOk {
            name: upper,
            from,
            to,
            changes,
        }),
        Err(e) => Response::fail(e),
    }
}

fn diff(uid: u32, upper: &str, from: u32, to: u32) -> Result<Vec<FieldChange>, String> {
    validate_name(upper)?;
    if !cred_path(uid, upper).exists() {
        return Err(crate::crypto::SANITIZED_LOOKUP_ERROR.into());
    }
    let meta = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper)))
        .transpose()
        .map_err(|_| "credential metadata unreadable")?
        .unwrap_or_default();
    if !super::files::readable_without_prompt(&meta, expiry::now_unix()) {
        return Err("history diff is not available for sealed, SSH, share-key, \
                    consent- or FIDO2-gated credentials"
            .into());
    }
    let (a, sealed_a) = crate::daemon_history::version_value(uid, upper, from)?;
    let (b, sealed_b) = crate::daemon_history::version_value(uid, upper, to)?;
    if sealed_a || sealed_b {
        return Err("that version was sealed; diff refused".into());
    }
    Ok(compare(a.as_str(), b.as_str()))
}

fn record(v: &str) -> Option<BTreeMap<String, ZeroString>> {
    serde_json::from_str(v).ok()
}

fn change(field: &str, change: &str) -> FieldChange {
    FieldChange {
        field: field.into(),
        change: change.into(),
    }
}

/// Changes from `a` to `b`: per field for two records (JSON objects of
/// strings), else one `value changed`.
fn compare(a: &str, b: &str) -> Vec<FieldChange> {
    let (Some(ra), Some(rb)) = (record(a), record(b)) else {
        return if a == b {
            Vec::new()
        } else {
            vec![change("value", "changed")]
        };
    };
    let mut out = Vec::new();
    for (k, va) in &ra {
        match rb.get(k) {
            None => out.push(change(k, "removed")),
            Some(vb) if vb.as_str() != va.as_str() => out.push(change(k, "changed")),
            Some(_) => {}
        }
    }
    for k in rb.keys().filter(|k| !ra.contains_key(*k)) {
        out.push(change(k, "added"));
    }
    out.sort_by(|x, y| x.field.cmp(&y.field));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn names(c: &[FieldChange]) -> Vec<(String, String)> {
        c.iter()
            .map(|c| (c.field.clone(), c.change.clone()))
            .collect()
    }

    #[test]
    fn field_added_removed_changed() {
        let a = r#"{"username":"a","password":"p1","url":"u"}"#;
        let b = r#"{"username":"a","password":"p2","totp":"t"}"#;
        assert_eq!(
            names(&compare(a, b)),
            vec![
                ("password".into(), "changed".into()),
                ("totp".into(), "added".into()),
                ("url".into(), "removed".into()),
            ]
        );
        assert!(compare(a, a).is_empty());
        assert_eq!(
            names(&compare("x", "y")),
            vec![("value".into(), "changed".into())]
        );
        assert!(compare("x", "x").is_empty());
    }

    #[test]
    fn diff_between_versions_never_carries_values() {
        let uid = testkit::uid();
        let rec = |f: &str| {
            let r = crate::daemon_records::handle_record_set(
                uid,
                "t",
                "HD_R",
                ("login", &f.into()),
                (None, false),
            );
            assert!(r.is_success());
        };
        rec(r#"{"username":"alice","password":"old-secret-pw"}"#);
        rec(r#"{"username":"alice","password":"new-secret-pw","url":"https://x"}"#);
        let r = handle_diff(uid, "t", "HD_R", 1, 0);
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("secret-pw") && !json.contains("alice"),
            "{json}"
        );
        match r {
            Response::Store(StoreResponse::HistoryDiffOk { changes, .. }) => assert_eq!(
                names(&changes),
                vec![
                    ("password".into(), "changed".into()),
                    ("url".into(), "added".into())
                ]
            ),
            other => panic!("unexpected {other:?}"),
        }
        assert!(!handle_diff(uid, "t", "HD_R", 0, 7).is_success());
    }

    #[test]
    fn protected_credentials_are_refused() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "HD_S", "a");
        testkit::set_sealed(uid, "HD_S", "b");
        assert!(handle_diff(uid, "t", "HD_S", 0, 1)
            .err_msg()
            .unwrap()
            .contains("not available"));
        // A sealed version can't be compared from an unsealed credential.
        testkit::set(uid, "HD_S", "c");
        let r = handle_diff(uid, "t", "HD_S", 0, 1);
        assert!(r.err_msg().unwrap().contains("sealed"), "{r:?}");
        assert_eq!(
            handle_diff(uid, "t", "HD_NONE", 0, 1).err_msg(),
            Some("credential unavailable")
        );
    }
}
