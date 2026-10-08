// daemon_platform/ — the `platform` ticket batch (P10), daemon side.
// batch: platform
//
//   fingerprint   quick unlock after an idle / sleep lock (T10.03)
//   exe           binary-identity bindings: the Get gate, ExeBind (T10.09)

pub mod exe;
pub mod fingerprint;

use kepr_core::protocol::Response;
use kepr_core::protocol_platform::PlatformRequest;

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, r: PlatformRequest) -> Response {
    match r {
        PlatformRequest::FingerprintUnlock => fingerprint::handle_unlock(uid, peer_pid, username),
        PlatformRequest::ExeBind { name, digests } => {
            exe::handle_bind(uid, peer_pid, username, &name, &digests)
        }
        PlatformRequest::ExeShow { name } => exe::handle_show(uid, username, &name),
    }
}
