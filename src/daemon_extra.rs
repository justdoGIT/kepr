// daemon_extra.rs — routes the store-maintenance and reporting requests
// (history / restore, usage, health / breach check, leak response) to
// their modules,
// keeping daemon.rs's dispatch to one arm for all of them.

use kepr_core::protocol::{Request, Response};

use crate::{daemon_health, daemon_history, daemon_usage};

pub fn dispatch(uid: u32, username: &str, request: Request) -> Response {
    match request {
        Request::History { name } => daemon_history::handle_history(uid, username, &name),
        Request::Restore { name, version } => {
            daemon_history::handle_restore(uid, username, &name, version)
        }
        Request::Usage { days } => {
            daemon_usage::handle_usage(uid, username, &crate::audit_chain_path(), days)
        }
        Request::Health { max_age_days } => {
            daemon_health::handle_health(uid, username, max_age_days)
        }
        Request::BreachCheck { name, suffixes } => {
            daemon_health::handle_breach_check(uid, username, &name, &suffixes)
        }
        Request::Leaked { name } => {
            crate::daemon_gate_registry::handle_leaked(uid, username, &name)
        }
        _ => Response::fail("unsupported request"),
    }
}
