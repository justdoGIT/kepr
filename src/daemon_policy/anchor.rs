// daemon_policy/anchor.rs — `AuditAnchorCheck` (T13.22): the audit log
// against chain heads published somewhere its writer cannot rewrite.
//
// The log is hash-chained, so editing or dropping an entry shows up in
// `AuditChain::verify`. Replacing the whole file with a fresh, valid chain
// does not; an old anchor does: the new chain either is shorter than the
// anchor's `seq` or holds another hash there.

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{AnchorPoint, PolicyResponse};

use crate::audit::{self, AuditEvent, AuditResult};
use crate::audit_chain::{AuditChain, ChainEntry};

/// Most anchors in one request (the frame limit allows about 700).
const MAX_ANCHORS: usize = 500;

/// Every anchor matches the entry at its `seq`. Entries are contiguous
/// from seq 1 (`AuditChain::verify` enforces that before this runs).
pub fn check(entries: &[ChainEntry], anchors: &[AnchorPoint]) -> Result<usize, String> {
    for a in anchors {
        let at = a
            .seq
            .checked_sub(1)
            .and_then(|i| entries.get(usize::try_from(i).ok()?))
            .ok_or_else(|| {
                format!(
                    "the log has {} entries but an anchor was published at {}: the log was truncated or replaced",
                    entries.len(),
                    a.seq
                )
            })?;
        if !kepr_core::http_lite::ct_eq(at.hash.as_bytes(), a.hash.as_bytes()) {
            return Err(format!(
                "entry {} differs from its published anchor: the log was rewritten",
                a.seq
            ));
        }
    }
    Ok(anchors.len())
}

pub fn handle_check(uid: u32, username: &str, anchors: &[AnchorPoint]) -> Response {
    let result = (|| {
        if anchors.is_empty() || anchors.len() > MAX_ANCHORS {
            return Err(format!("send between 1 and {MAX_ANCHORS} anchors"));
        }
        let path = crate::audit_chain_path();
        let report = AuditChain::verify(&path)?;
        let n = check(&super::events::read_chain(), anchors)?;
        Ok(format!(
            "chain intact ({} entries); {n} anchor(s) match",
            report.entries
        ))
    })();
    audit::log(&AuditEvent {
        op: "audit_anchor_check",
        name: None,
        uid,
        username,
        result: match &result {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
    match result {
        Ok(message) => Response::Policy(PolicyResponse::PolicyDone { message }),
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u64, hash: &str) -> ChainEntry {
        ChainEntry {
            seq,
            timestamp_unix: 1,
            op: "get".into(),
            name: None,
            uid: 1,
            username: "u".into(),
            result: "ok".into(),
            prev_hash: String::new(),
            hash: hash.into(),
        }
    }

    fn anchor(seq: u64, hash: &str) -> AnchorPoint {
        AnchorPoint {
            seq,
            hash: hash.into(),
        }
    }

    #[test]
    fn an_intact_log_matches_its_anchors() {
        let log = [entry(1, "a"), entry(2, "b"), entry(3, "c")];
        assert_eq!(check(&log, &[anchor(2, "b"), anchor(3, "c")]), Ok(2));
    }

    #[test]
    fn a_truncated_log_fails() {
        let log = [entry(1, "a"), entry(2, "b")];
        let e = check(&log, &[anchor(3, "c")]).unwrap_err();
        assert!(e.contains("truncated or replaced"), "{e}");
    }

    #[test]
    fn a_rewritten_log_fails() {
        let log = [entry(1, "x"), entry(2, "y"), entry(3, "z")];
        let e = check(&log, &[anchor(2, "b")]).unwrap_err();
        assert!(e.contains("rewritten"), "{e}");
    }

    #[test]
    fn seq_zero_is_not_an_anchor() {
        assert!(check(&[entry(1, "a")], &[anchor(0, "a")]).is_err());
    }
}
