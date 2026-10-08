// daemon_aws — daemon side of the `aws` ticket batch (2026-10-05).
// batch: aws
//
//   rotate_sched   scheduled rotation (T7.07): `.meta` schedule, the
//                  sweeper hook, `set` carry-over, `kepr list` fields

pub mod rotate_sched;

use kepr_core::protocol::{CredInfo, Response};
use kepr_core::protocol_aws::AwsRequest;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry::CredMeta;

pub fn dispatch(uid: u32, _peer_pid: i32, username: &str, request: AwsRequest) -> Response {
    match request {
        AwsRequest::AwsRotateSchedule {
            name,
            every_secs,
            via,
        } => rotate_sched::handle_schedule(uid, username, &name, every_secs, via.as_deref()),
    }
}

/// One audit line for an aws-batch operation (op and name only).
pub(crate) fn audit_op(
    op: &'static str,
    name: &str,
    uid: u32,
    username: &str,
    r: Result<(), &String>,
) {
    audit::log(&AuditEvent {
        op,
        name: Some(name),
        uid,
        username,
        result: match r {
            Ok(()) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}

/// Sweeper hook (daemon_expiry.rs).
pub fn sweep(now: u64) {
    rotate_sched::sweep(now);
}

/// `handle_set` hook: keep the rotation schedule across a new value.
pub fn carry_over(uid: u32, upper: &str, meta: &mut CredMeta) {
    rotate_sched::carry_over(uid, upper, meta, crate::expiry::now_unix());
}

/// `handle_list` hook: the batch's `CredInfo` fields from the `.meta`.
pub fn info(m: Option<&CredMeta>) -> CredInfo {
    let Some(m) = m else {
        return CredInfo::default();
    };
    CredInfo {
        rotate_every_secs: m.rotate_every_secs,
        rotate_via: m.rotate_via.clone(),
        rotate_next_at: m.rotate_next_at,
        rotate_failures: m.rotate_failures,
        ..CredInfo::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_copies_only_the_schedule() {
        assert_eq!(info(None).rotate_via, None);
        let m = CredMeta {
            rotate_every_secs: Some(3600),
            rotate_via: Some("db".into()),
            rotate_next_at: Some(9),
            rotate_failures: Some(2),
            sealed: Some(true),
            ..Default::default()
        };
        let c = info(Some(&m));
        assert_eq!(
            (
                c.rotate_every_secs,
                c.rotate_via.as_deref(),
                c.rotate_next_at,
                c.rotate_failures
            ),
            (Some(3600), Some("db"), Some(9), Some(2))
        );
        assert_eq!(c.sealed, None);
    }
}
