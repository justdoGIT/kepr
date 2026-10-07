// daemon_policy/ — the `policy` ticket batch, daemon side: the access
// policy (T6.11), access reports (T6.12), the audit feed for the CLI-side
// forwarders and alerts (T7.14). Requests arrive as
// `Request::Policy` via daemon_extra.rs; `enforce` runs before every request in
// daemon_dispatch.rs, `init` once at start in daemon.rs.

mod caller;
mod enforce;
mod events;
mod report;

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{PolicyRequest, PolicyResponse};

use crate::audit::{self, AuditEvent, AuditResult};

/// Pre-dispatch hook: `Some(refusal)` stops the request.
pub use enforce::enforce;
/// Load the policy file; reload on SIGHUP.
pub use enforce::init;

pub fn dispatch(uid: u32, _peer_pid: i32, username: &str, r: PolicyRequest) -> Response {
    match r {
        PolicyRequest::PolicyStatus { reload } => status(uid, username, reload),
        PolicyRequest::ReportAccess { name } => report::handle_access(uid, username, &name),
        PolicyRequest::AuditTail { after } => events::handle_tail(uid, after.as_deref()),
    }
}

fn status(uid: u32, username: &str, reload: bool) -> Response {
    let loaded = if reload {
        enforce::reload()
    } else {
        enforce::current()
    };
    if reload {
        audit::log(&AuditEvent {
            op: "policy-reload",
            name: None,
            uid,
            username,
            result: AuditResult::Ok,
        });
    }
    let (active, rules, error) = match &*loaded {
        enforce::Loaded::Absent => (false, 0, None),
        enforce::Loaded::Active(p) => (true, p.rules.len(), None),
        enforce::Loaded::Broken(e) => (true, 0, Some(e.clone())),
    };
    Response::Policy(PolicyResponse::PolicyStatusOk {
        path: enforce::policy_path().display().to_string(),
        active,
        rules,
        error,
    })
}
