// daemon_store/verify.rs — T11.10 `kepr doctor --verify`: a deep check of
// the caller's part of the store. Every value file (credentials, history
// slots, trash entries) is decrypted to check its tag and dropped at once,
// sealed ones included (nothing is returned). Every `.meta` must parse;
// history slots must belong to an existing value; a `.meta` with no value
// must be an alias whose target exists. Answered with `Response::CheckOk`
// (name → "ok" or the problems), so `all_ok` drives the exit code. With
// `KEPR_STORE=image` the same checks run over the image's records (T4.14).
//
// Attachment manifests (T5.03) are not checked: attachments are not part
// of this tree yet.

use std::collections::HashMap;

use kepr_core::protocol::Response;

use super::files;
use crate::audit::{self, AuditEvent, AuditResult};
use crate::crypto;
use crate::expiry::{self, CredMeta};
use crate::store;

/// `name → problems` for `uid` (an empty list = ok).
fn check(uid: u32) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let values: Vec<String> = files::all_of(uid).into_iter().map(|(n, _)| n).collect();
    for name in &values {
        let problems = out.entry(name.clone()).or_default();
        if crypto::default_backend().decrypt(uid, name).is_err() {
            problems.push("does not decrypt".into());
        }
        // `X~3` belongs to `X`; `X~t17~3` to the trash entry `X~t17`.
        if let Some((owner, slot)) = name.rsplit_once('~') {
            if !slot.starts_with('t') && !values.iter().any(|v| v == owner) {
                problems.push("orphan history slot".into());
            }
        }
    }
    for p in files::meta_paths_of(uid) {
        let f = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let base = f.strip_suffix(".meta").unwrap_or(&f);
        let Some((_, name)) = files::parse_file_name(base) else {
            out.entry(f.clone())
                .or_default()
                .push("unexpected meta file".into());
            continue;
        };
        let problems = out.entry(name.clone()).or_default();
        match expiry::read_meta(&p) {
            Some(Ok(meta)) if !values.contains(&name) => problems.extend(no_value(uid, &meta)),
            Some(Ok(_)) | None => {}
            Some(Err(_)) => problems.push("meta does not parse".into()),
        }
    }
    out
}

/// A meta without a value file: fine only for an alias with a target.
fn no_value(uid: u32, meta: &CredMeta) -> Option<String> {
    let Some(target) = &meta.alias_of else {
        return Some("meta without a value".into());
    };
    if store::validate_name(target).is_err() || !store::cred_exists(uid, target) {
        return Some(format!("alias target {target} is missing"));
    }
    None
}

pub fn handle_verify(uid: u32, username: &str) -> Response {
    if crypto::backend_is_locked() {
        return Response::fail("credential store is locked");
    }
    let results: HashMap<String, String> = check(uid)
        .into_iter()
        .map(|(n, p)| {
            let status = if p.is_empty() {
                "ok".to_string()
            } else {
                p.join("; ")
            };
            (n, status)
        })
        .collect();
    let bad = results.values().filter(|s| *s != "ok").count();
    audit::log(&AuditEvent {
        op: "verify",
        name: None,
        uid,
        username,
        result: if bad == 0 {
            AuditResult::Ok
        } else {
            AuditResult::Fail(format!("{bad} problem(s)"))
        },
    });
    Response::CheckOk {
        count: results.len(),
        all_ok: bad == 0,
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;
    use crate::store::cred_path;

    fn results(uid: u32) -> (HashMap<String, String>, bool) {
        match handle_verify(uid, "t") {
            Response::CheckOk {
                results, all_ok, ..
            } => (results, all_ok),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_healthy_store_verifies() {
        let uid = testkit::uid();
        testkit::set(uid, "V_A", "1");
        testkit::set(uid, "V_A", "2");
        testkit::set_sealed(uid, "V_S", "sk");
        testkit::set(uid, "V_T", "t");
        testkit::set(uid, "V_T", "t2");
        crate::daemon_store::handle_rm(uid, "t", "V_T"); // trash + its slot
        super::super::alias::handle_link(uid, "t", "V_L", "V_A");
        let (r, ok) = results(uid);
        assert!(ok, "{r:?}");
        assert_eq!(r.len(), 6, "{r:?}"); // V_A, V_A~0, V_S, V_T~t…, its slot, V_L
    }

    #[test]
    fn orphan_slot_corrupt_meta_and_bad_values_are_reported() {
        let uid = testkit::uid();
        testkit::set(uid, "V_O", "1");
        testkit::set(uid, "V_O", "2"); // slot V_O~0
        crypto::default_backend().delete(uid, "V_O").unwrap(); // slot left behind
        testkit::set(uid, "V_M", "m");
        let mp = expiry::meta_path_for(&cred_path(uid, "V_M"));
        std::fs::write(&mp, b"{not json").unwrap();
        testkit::set(uid, "V_X", "x");
        std::fs::write(cred_path(uid, "V_X"), b"kepr_v2\ngarbage-garbage-garbage").unwrap();
        testkit::set(uid, "V_D", "d");
        super::super::alias::handle_link(uid, "t", "V_DL", "V_D");
        crypto::default_backend().delete(uid, "V_D").unwrap(); // dangling alias

        let (r, ok) = results(uid);
        assert!(!ok);
        assert_eq!(r["V_O~0"], "orphan history slot");
        assert_eq!(r["V_M"], "meta does not parse");
        assert_eq!(r["V_X"], "does not decrypt");
        assert_eq!(r["V_DL"], "alias target V_D is missing");
    }
}
