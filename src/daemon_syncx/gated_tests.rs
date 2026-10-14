// daemon_syncx/gated_tests.rs — security review regression tests: a
// value whose `get` is held by an executable binding (T10.09) or M-of-N
// approvals (T7.12) is never compared, analysed or put in a bundle
// (`CredMeta::gated`), not even for a caller the binding allows or while
// an approval window is open: a window is for `get`, not for copies.

use kepr_core::protocol::Response;
use kepr_core::protocol_store::{StoreRequest, StoreResponse};
use kepr_core::protocol_syncx::{SyncxRequest, SyncxResponse};
use sha1::{Digest, Sha1};

use super::quorum_cmd::{handle_approve, handle_request, handle_set, handle_sign};
use super::testutil::{pair, public};
use crate::daemon_store::testkit;
use crate::expiry::{self, now_unix};
use crate::store::cred_path;

/// This test process: the peer every request below comes from.
fn me() -> i32 {
    std::process::id() as i32
}

/// `name` = `value` in `folder`, bound to this test binary, so a `get`
/// by this process passes the binding.
fn bound(uid: u32, name: &str, value: &str, folder: &str) {
    filed(uid, name, value, folder);
    let exe = std::fs::File::open("/proc/self/exe").unwrap();
    let mut m = testkit::meta(uid, name);
    m.exe_digests = Some(vec![kepr_core::exe_digest::sha256_of(&exe).unwrap()]);
    expiry::write_meta(&expiry::meta_path_for(&cred_path(uid, name)), &m).unwrap();
    assert!(crate::daemon_handlers_get::precheck_meta(uid, me(), name).is_ok());
}

/// `name` = `value` in `folder` behind 2 approvals, with a window open.
fn approved(a: u32, b: u32, name: &str, value: &str, folder: &str) {
    let now = now_unix();
    filed(a, name, value, folder);
    let set = handle_set(a, "t", name, 2, now);
    assert!(matches!(
        set,
        Response::Syncx(SyncxResponse::QuorumSetOk { .. })
    ));
    let Response::Syncx(SyncxResponse::QuorumStatus(q)) = handle_request(a, "t", name, 3600, now)
    else {
        panic!("no request");
    };
    let Response::Syncx(SyncxResponse::QuorumApproval { approval }) =
        handle_sign(b, "t", &q.request, || true, now)
    else {
        panic!("no approval");
    };
    assert!(handle_approve(a, "t", (&q.id, None), || true, now).is_success());
    assert!(handle_approve(a, "t", (&q.id, Some(&approval)), || false, now).is_success());
    assert!(crate::daemon_handlers_get::precheck_meta(a, me(), name).is_ok());
}

fn filed(uid: u32, name: &str, value: &str, folder: &str) {
    testkit::set(uid, name, value);
    let req = StoreRequest::Organize {
        name: name.into(),
        add_tags: vec![],
        remove_tags: vec![],
        folder: Some(folder.into()),
    };
    assert!(crate::daemon_store::dispatch(uid, me(), "t", req).is_success());
}

const GATED: [&str; 2] = ["GT_BOUND", "GT_QUORUM"];

#[test]
fn gated_values_are_never_compared_or_analysed() {
    let (a, b) = pair();
    bound(a, "GT_BOUND", "hunter22", "f");
    approved(a, b, "GT_QUORUM", "hunter22", "f");
    testkit::set(a, "GT_GUESS", "hunter22");
    match crate::daemon_store::dispatch(a, me(), "t", StoreRequest::Dupes) {
        Response::Store(StoreResponse::DupesOk { groups }) => {
            assert!(groups
                .iter()
                .flatten()
                .all(|n| !GATED.contains(&n.as_str())));
        }
        other => panic!("{other:?}"),
    }
    let full = hex::encode_upper(Sha1::digest(b"hunter22"));
    for name in GATED {
        let r = crate::daemon_health::handle_breach_check(a, "t", name, &[full[5..].into()]);
        assert_eq!(r.err_msg(), Some("credential unavailable"), "{name}: {r:?}");
    }
    let Response::HealthOk { items } = crate::daemon_health::handle_health(a, "t", None, None)
    else {
        panic!("no health");
    };
    for i in items.iter().filter(|i| GATED.contains(&i.name.as_str())) {
        assert_eq!(i.hibp_prefix, None, "{}", i.name);
        assert!(i.issues.iter().all(|s| !s.contains("same value")), "{i:?}");
    }
    let guess = items.iter().find(|i| i.name == "GT_GUESS").unwrap();
    assert!(
        guess.issues.iter().all(|s| !s.contains("same value")),
        "{guess:?}"
    );
}

/// The `(name, reason)` rows a bundle left out.
fn omitted(r: Response) -> Vec<(String, String)> {
    match r {
        Response::Syncx(SyncxResponse::BundleReady { omitted, .. }) => {
            omitted.into_iter().map(|o| (o.name, o.omitted)).collect()
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn gated_values_never_go_into_a_bundle() {
    let (a, b) = pair();
    bound(a, "GT_BOUND", "v-bound", "team");
    approved(a, b, "GT_QUORUM", "v-quorum", "team");
    let want = |rows: &[(String, String)]| {
        assert!(
            rows.contains(&("GT_BOUND".into(), "exe_bound".into())),
            "{rows:?}"
        );
        assert!(
            rows.contains(&("GT_QUORUM".into(), "approvals".into())),
            "{rows:?}"
        );
    };
    let export = SyncxRequest::ExportBundle {
        passphrase: "bundle passphrase 1".into(),
    };
    want(&omitted(super::dispatch(a, me(), "t", export)));
    let folder = SyncxRequest::FolderExport {
        folder: "team".into(),
        recipients: vec![public(b)],
        sealed: false,
    };
    want(&omitted(super::dispatch(a, me(), "t", folder)));
    // What a sync bundle to the enrolled devices carries.
    let synced = super::sync_state::local((a, me()), "t");
    assert!(
        GATED.iter().all(|n| !synced.contains_key(*n)),
        "sent to devices"
    );
}
