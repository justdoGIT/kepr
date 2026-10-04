// daemon_audit.rs — handler for `Request::AuditVerify`.
//
// Phase 2 δ.3. The chain primitives live in `audit_chain.rs`; the
// audit::log tee from PR #75 wires the chain into every audit
// event. This module is the request-side: a CLI client calls
// `Request::AuditVerify`, the daemon walks the on-disk chain via
// `AuditChain::verify`, returns the entry count + head hash.
//
// Why a dedicated file: `daemon_handlers.rs` sits at the 357-LOC
// allowlist ceiling (set/get/list/delete/check), so adding even a
// small handler there would trip the per-file LOC test. The split
// isn't synthetic — `audit_verify` is genuinely a different concept
// (read-only, no per-uid namespacing, no rate limit interaction)
// from the cred-op handlers, and giving it its own file makes that
// distinction visible to maintainers.

use std::path::Path;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::audit_chain::AuditChain;
use kepr_core::protocol::Response;

/// Walk the audit chain at `chain_path` and return either
/// `Response::AuditOk { entries, last_hash }` on a clean
/// verification or `Response::Err` with a tamper reason that
/// names the offending line. Logs the verification itself to
/// the audit pipeline — operators get a paper trail of every
/// `kepr audit-verify` call, distinguishable in journald via
/// `KEPR_OP=audit_verify`.
pub fn handle_audit_verify(uid: u32, username: &str, chain_path: &Path) -> Response {
    match AuditChain::verify(chain_path) {
        Ok(report) => {
            audit::log(&AuditEvent {
                op: "audit_verify",
                name: None,
                uid,
                username,
                result: AuditResult::Ok,
            });
            Response::AuditOk {
                entries: report.entries,
                last_hash: report.last_hash,
            }
        }
        Err(e) => {
            // The reason is operator-actionable (line N: hash
            // mismatch / prev_hash mismatch / seq mismatch) and
            // doesn't leak any cred-store internals — pass it
            // through verbatim. The audit log records the same
            // reason so a future verifier can correlate.
            audit::log(&AuditEvent {
                op: "audit_verify",
                name: None,
                uid,
                username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_missing_chain_file_returns_err() {
        // Smoke-test the error path. The full chain semantics are
        // in audit_chain::tests; here we just confirm that the
        // handler propagates verify errors as `Response::Err`
        // rather than panicking.
        let resp = handle_audit_verify(0, "root", Path::new("/nonexistent/audit/chain"));
        match resp {
            Response::Err { error } => {
                assert!(
                    error.contains("open chain") || error.contains("verify"),
                    "msg: {error}"
                );
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }
}
