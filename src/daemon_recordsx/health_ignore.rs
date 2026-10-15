// daemon_recordsx/health_ignore.rs — T11.23 `kepr health --ignore
// NAME:KIND` / `--unignore NAME[:KIND]`: finding kinds the owner accepts
// for one credential, kept in its `.meta` (`health_ignore`). `kepr
// health` then lists them as ignored instead of as issues
// (daemon_health.rs, `apply`). A new value starts with none: handle_set
// writes a fresh `.meta` and does not carry the field over.

use kepr_core::health_policy::{finding_kind, FINDING_KINDS};
use kepr_core::protocol::{KeyHealth, Response};
use kepr_core::protocol_records::RecordsResponse;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry;
use crate::store::{cred_exists, cred_path, validate_name};

fn update(uid: u32, upper: &str, kinds: &[String], clear: bool) -> Result<Vec<String>, String> {
    if let Some(k) = kinds.iter().find(|k| !FINDING_KINDS.contains(&k.as_str())) {
        return Err(format!(
            "unknown finding {k:?}; use: {}",
            FINDING_KINDS.join(", ")
        ));
    }
    if kinds.is_empty() && !clear {
        return Err("name the findings to ignore (NAME:weak,old)".into());
    }
    let _lock = crate::daemon_credlock::lock(uid, upper);
    if !cred_exists(uid, upper) {
        return Err("credential unavailable".into());
    }
    let path = expiry::meta_path_for(&cred_path(uid, upper));
    // A meta that doesn't parse is never rewritten: it may hold a seal.
    let mut meta = expiry::read_meta(&path)
        .transpose()
        .map_err(|_| "credential unavailable".to_string())?
        .unwrap_or_default();
    let mut ignored = meta.health_ignore.take().unwrap_or_default();
    match (clear, kinds.is_empty()) {
        (true, true) => ignored.clear(),
        (true, false) => ignored.retain(|k| !kinds.contains(k)),
        (false, _) => {
            ignored.extend(kinds.iter().cloned());
            ignored.sort_unstable();
            ignored.dedup();
        }
    }
    meta.health_ignore = (!ignored.is_empty()).then(|| ignored.clone());
    if meta.is_empty() {
        expiry::delete_meta(&path);
    } else {
        expiry::write_meta(&path, &meta)?;
    }
    Ok(ignored)
}

pub fn handle_ignore(
    uid: u32,
    username: &str,
    name: &str,
    kinds: &[String],
    clear: bool,
) -> Response {
    let upper = name.to_uppercase();
    let r = validate_name(name).and_then(|()| update(uid, &upper, kinds, clear));
    audit::log(&AuditEvent {
        op: "health-ignore",
        name: Some(&upper),
        uid,
        username,
        result: match &r {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
    match r {
        Ok(ignored) => Response::Records(RecordsResponse::HealthIgnoreOk {
            name: upper,
            ignored,
        }),
        Err(e) => Response::fail(e),
    }
}

/// Move `item`'s issues of a kind in `item.ignore` to `item.ignored`.
pub fn apply(item: &mut KeyHealth) {
    let (hidden, kept): (Vec<String>, Vec<String>) = std::mem::take(&mut item.issues)
        .into_iter()
        .partition(|i| item.ignore.iter().any(|k| k == finding_kind(i)));
    item.issues = kept;
    item.ignored.extend(hidden);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn kinds(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn health(uid: u32, name: &str) -> KeyHealth {
        match crate::daemon_health::handle_health(uid, "t", None, None) {
            Response::HealthOk { items } => items.into_iter().find(|i| i.name == name).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ignored_findings_move_out_of_issues_until_the_value_changes() {
        let uid = testkit::uid();
        testkit::set(uid, "WEAK", "password1");
        let before = health(uid, "WEAK");
        assert!(
            before.issues.iter().any(|i| i.contains("common")),
            "{before:?}"
        );
        let r = handle_ignore(uid, "t", "weak", &kinds(&["common", "short"]), false);
        assert!(r.is_success(), "{r:?}");
        let after = health(uid, "WEAK");
        assert!(after.issues.is_empty(), "{after:?}");
        assert_eq!(after.ignored.len(), before.issues.len());
        assert_eq!(after.ignore, ["common", "short"]);
        // --unignore one kind.
        handle_ignore(uid, "t", "WEAK", &kinds(&["short"]), true);
        assert!(health(uid, "WEAK")
            .issues
            .iter()
            .any(|i| i.starts_with("short")));
        // A new value starts without ignores.
        testkit::set(uid, "WEAK", "password2");
        assert_eq!(testkit::meta(uid, "WEAK").health_ignore, None);
        assert!(health(uid, "WEAK").ignored.is_empty());
    }

    #[test]
    fn ignores_keep_the_rest_of_the_meta_and_check_their_input() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "SEALED", "v");
        let r = handle_ignore(uid, "t", "SEALED", &kinds(&["old"]), false);
        assert!(r.is_success(), "{r:?}");
        let m = testkit::meta(uid, "SEALED");
        assert_eq!(m.sealed, Some(true));
        assert!(m.bindings.is_some());
        assert_eq!(m.health_ignore, Some(kinds(&["old"])));
        handle_ignore(uid, "t", "SEALED", &[], true);
        assert_eq!(testkit::meta(uid, "SEALED").health_ignore, None);
        assert_eq!(testkit::meta(uid, "SEALED").sealed, Some(true));
        for (name, k, what) in [
            ("SEALED", "nope", "unknown finding"),
            ("MISSING", "weak", "credential unavailable"),
            ("../x", "weak", "invalid character"),
        ] {
            let r = handle_ignore(uid, "t", name, &kinds(&[k]), false);
            let Response::Err { error } = r else {
                panic!("{name}: {r:?}");
            };
            assert!(error.contains(what), "{name}: {error}");
        }
        assert!(!handle_ignore(uid, "t", "SEALED", &[], false).is_success());
    }
}
