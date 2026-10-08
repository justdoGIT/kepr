// daemon_policy/ — the `policy` ticket batch, daemon side: the access
// policy (T6.11), access reports (T6.12), the audit feed for the CLI-side
// forwarders and alerts (T7.14), approval notifications (T9.04), per-day
// caps across gate sessions (T9.06), the usage report (T9.07).
// Requests arrive as
// `Request::Policy` via daemon_extra.rs; `enforce` runs before every request in
// daemon_dispatch.rs, `init` once at start in daemon.rs.

mod approvals;
mod approve;
mod caller;
mod daily;
mod enforce;
mod events;
mod report;
mod sessions;
mod usage;

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{PolicyRequest, PolicyResponse};

use crate::audit::{self, AuditEvent, AuditResult};

/// The consent check for consent-gated credentials (T9.04: approver or polkit).
pub use approve::consent;

/// T9.06: a gate reports usage of one of its session's credentials;
/// the reply carries the day's totals across the user's sessions.
pub fn day_usage(
    creds: &std::collections::HashSet<String>,
    uid: u32,
    id: u64,
    name: &str,
    (requests, tokens): (u64, u64),
) -> kepr_core::gate_protocol::GateResponse {
    use kepr_core::gate_protocol::GateResponse;
    if !creds.contains(name) {
        return GateResponse::Err {
            id,
            error: "credential unavailable".into(),
        };
    }
    let (requests, tokens) = daily::record(uid, name, requests, tokens);
    GateResponse::UsageToday {
        id,
        requests,
        tokens,
    }
}
/// Pre-dispatch hook: `Some(refusal)` stops the request.
pub use enforce::enforce;
/// Load the policy file; reload on SIGHUP.
pub use enforce::init;
/// T9.07: record a started gate session's routes (daemon_gate.rs).
pub use sessions::started as session_started;

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, r: PolicyRequest) -> Response {
    match r {
        PolicyRequest::PolicyStatus { reload } => status(uid, username, reload),
        PolicyRequest::ReportAccess { name } => report::handle_access(uid, username, &name),
        PolicyRequest::AuditTail { after } => events::handle_tail(uid, after.as_deref()),
        PolicyRequest::ApproveVia { name, via } => {
            approve::handle_via(uid, peer_pid, username, &name, via.as_deref())
        }
        PolicyRequest::ApproverRegister => approve::handle_register(uid, peer_pid, username),
        PolicyRequest::ApprovalPoll { key } => approve::handle_poll(uid, peer_pid, &key),
        PolicyRequest::ApprovalAnswer {
            key,
            id,
            token,
            allow,
        } => approve::handle_answer(uid, peer_pid, username, (&key, &id, &token), allow),
        PolicyRequest::SessionHarness { session, harness } => {
            sessions::handle_harness(uid, &session, &harness)
        }
        PolicyRequest::UsageReport { days, unused_days } => {
            usage::handle_report(uid, username, days, unused_days)
        }
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
