// daemon_syncx/testutil.rs — test helpers shared by the sync batch's
// daemon tests: users with share keys, enrolled as each other's devices.

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{EnrolRequest, SharingRequest, SharingResponse};

use crate::daemon_store::testkit;

/// A device: a uid with a share key.
pub fn device() -> u32 {
    let uid = testkit::uid();
    assert!(crate::daemon_share::handle_key(uid, "t", true).is_success());
    uid
}

pub fn public(uid: u32) -> String {
    crate::daemon_share::load_secret(uid)
        .unwrap()
        .recipient()
        .text()
}

/// `kepr device add` on `on`, `kepr device enroll` from `other`.
pub fn enroll(on: u32, other: u32) {
    let sharing = |r| crate::daemon_sharing::dispatch(on, 0, "t", r);
    let add = SharingRequest::DeviceAdd {
        label: format!("d{other}"),
        oidc_issuer: None,
    };
    let Response::Sharing(SharingResponse::DeviceToken { token, .. }) = sharing(add) else {
        panic!("no token");
    };
    let req = EnrolRequest::new(token.as_str(), "host", &public(other), None);
    let enrol = SharingRequest::DeviceEnroll {
        request: serde_json::to_string(&req).unwrap(),
        oidc: None,
    };
    assert!(sharing(enrol).is_success());
}

pub fn pair() -> (u32, u32) {
    let (a, b) = (device(), device());
    enroll(a, b);
    enroll(b, a);
    (a, b)
}
