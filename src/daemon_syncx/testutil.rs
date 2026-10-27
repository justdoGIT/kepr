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

/// `kepr device add` on `on`, then `other`'s enrolment request.
fn request(on: u32, other: u32) -> String {
    let add = SharingRequest::DeviceAdd {
        label: format!("d{other}"),
        oidc_issuer: None,
    };
    let Response::Sharing(SharingResponse::DeviceToken { token, .. }) =
        crate::daemon_sharing::dispatch(on, 0, "t", add)
    else {
        panic!("no token");
    };
    let req = EnrolRequest::new(token.as_str(), "host", &public(other), None);
    serde_json::to_string(&req).unwrap()
}

/// `kepr device enroll --from` on `on` for `other`, sent as a client with
/// `peer_pid` would: the daemon asks polkit about that pid.
pub fn try_enroll(on: u32, other: u32, peer_pid: i32) -> Response {
    let enrol = SharingRequest::DeviceEnroll {
        request: request(on, other),
        oidc: None,
    };
    crate::daemon_sharing::dispatch(on, peer_pid, "t", enrol)
}

/// `other` enrolled on `on`, the human at `on` approving (polkit stubbed).
pub fn enroll(on: u32, other: u32) {
    let req = request(on, other);
    let r = crate::daemon_sharing::devices::handle_enroll(on, "t", &req, None, || true);
    assert!(r.is_success(), "{r:?}");
}

pub fn pair() -> (u32, u32) {
    let (a, b) = (device(), device());
    enroll(a, b);
    enroll(b, a);
    (a, b)
}
