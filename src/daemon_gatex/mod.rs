// daemon_gatex/ — the gate batch's daemon side (P7 PAM-lite, P11.22).
// `Request::Gatex` arrives here from daemon_extra.rs; the uid is the
// caller's SO_PEERCRED uid, never one from the request.

pub mod logs;
pub mod recfile;
pub mod recording;
pub mod spawn;

use kepr_core::protocol::Response;
use kepr_core::protocol_gatex::GatexRequest;

pub fn dispatch(uid: u32, _peer_pid: i32, _username: &str, request: GatexRequest) -> Response {
    match request {
        GatexRequest::AgentRecordings => recording::handle_list(uid),
        GatexRequest::AgentReplay {
            session,
            frame,
            offset,
        } => recording::handle_replay(uid, &session, (frame, offset)),
        GatexRequest::AgentLogs {
            session,
            from,
            last,
        } => logs::handle_logs(uid, session, from, last),
    }
}
