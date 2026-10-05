// daemon_extra.rs — routes the store-maintenance and reporting requests
// (history / restore, usage, health / breach check, leak response) to
// their modules,
// keeping daemon.rs's dispatch to one arm for all of them.

use kepr_core::protocol::{Request, Response};

use crate::{daemon_health, daemon_history, daemon_usage};

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, request: Request) -> Response {
    match request {
        Request::StartGate {
            routes,
            port,
            limits,
            tunnel,
        } => crate::daemon_gate::handle_start_gate(
            uid,
            peer_pid,
            username,
            &routes,
            (port, limits, tunnel),
        ),
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
        Request::RecoveryKitCreate {
            password,
            threshold,
            shares,
        } => crate::daemon_recovery::handle_create(
            uid,
            username,
            password.as_bytes(),
            threshold,
            shares,
        ),
        Request::RecoveryRestore {
            shares,
            new_password,
        } => {
            crate::daemon_recovery::handle_restore(uid, username, &shares, new_password.as_bytes())
        }
        Request::RecordSet {
            name,
            record_type,
            fields,
            requires_consent,
            seal,
        } => crate::daemon_records::handle_record_set(
            uid,
            username,
            &name,
            (&record_type, &fields),
            (requires_consent, seal),
        ),
        Request::ShareKey { create } => crate::daemon_share::handle_key(uid, username, create),
        Request::ShareSend { name, to, ttl_secs } => {
            crate::daemon_share::handle_send((uid, peer_pid), username, &name, &to, ttl_secs)
        }
        Request::ShareReceive { envelope, name } => {
            crate::daemon_share::handle_receive(uid, username, &envelope, name.as_deref())
        }
        Request::DbRotate { name, phase } => {
            crate::daemon_records::handle_db_rotate(uid, username, &name, &phase)
        }
        // ── P2–P11 ticket batches: one arm per batch, e.g.
        // `Request::Vault(r) => crate::daemon_vault::dispatch(uid, peer_pid, username, r),`
        // batch: vault
        // batch: seal
        // batch: store
        Request::Store(r) => crate::daemon_store::dispatch(uid, peer_pid, username, r),
        // batch: records
        // batch: share
        // batch: sync
        // batch: policy
        // batch: gate
        // batch: aws
        // batch: eco
        // batch: platform
        // batch: session
        // end of batches
        _ => Response::fail("unsupported request"),
    }
}
