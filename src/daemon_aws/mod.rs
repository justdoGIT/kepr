// daemon_aws — daemon side of the `aws` ticket batch (2026-10-05).
// batch: aws
//
//   rotate_sched   scheduled rotation (T7.07): `.meta` schedule, the
//                  sweeper hook, `set` carry-over, `kepr list` fields
//   grant          just-in-time grants (T7.10): the window a sealed
//                  credential resolves in, checked by daemon_gate.rs
//   checkout       check-out / check-in (T7.11): one holder at a time

pub mod checkout;
pub mod grant;
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
        AwsRequest::AwsGrant { name, op } => grant::handle_grant(uid, username, &name, op),
        AwsRequest::AwsCheckout { name, for_secs } => {
            checkout::handle_checkout(uid, username, &name, for_secs)
        }
        AwsRequest::AwsCheckin {
            name,
            token,
            rotated,
        } => checkout::handle_checkin(uid, username, &name, &token, rotated),
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
    if crate::user_mode() {
        checkout::sweep(crate::daemon_socket::effective_uid(), now); // T7.11
    }
}

/// `handle_set` hook: keep the rotation schedule and the just-in-time
/// policy across a new value.
pub fn carry_over(uid: u32, upper: &str, meta: &mut CredMeta) {
    rotate_sched::carry_over(uid, upper, meta, crate::expiry::now_unix());
    grant::carry_over(uid, upper, meta);
    checkout::carry_over(uid, upper, meta);
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
        jit: m.jit,
        grants: m.grants.clone(),
        held_by_uid: m.checkout.as_ref().map(|h| h.uid),
        held_until: m.checkout.as_ref().map(|h| h.until),
        ..CredInfo::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_copies_only_this_batchs_fields() {
        assert_eq!(info(None).rotate_via, None);
        let m = CredMeta {
            rotate_every_secs: Some(3600),
            rotate_via: Some("db".into()),
            rotate_next_at: Some(9),
            rotate_failures: Some(2),
            jit: Some(true),
            checkout: Some(kepr_core::protocol_aws::Hold {
                uid: 7,
                token_sha256: "deadbeef".into(),
                until: 99,
            }),
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
        assert_eq!((c.jit, c.grants.as_ref()), (Some(true), None));
        assert_eq!((c.held_by_uid, c.held_until), (Some(7), Some(99)));
        let json = serde_json::to_string(&c).unwrap();
        assert!(
            !json.contains("deadbeef") && json.contains("held_by_uid"),
            "{json}"
        );
        assert_eq!(c.sealed, None);
    }
}
