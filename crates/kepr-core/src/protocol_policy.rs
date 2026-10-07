// protocol_policy.rs — wire types for the `policy` ticket batch (access
// policy, reports, alerts, SIEM forwarding, approvals, caps, honeytokens).
// batch: policy
//
// Carried inside `Request::Policy` / `Response::Policy` (untagged), so the
// JSON stays flat: `{"cmd":"policy_status"}` → `{"kind":"policy_status_ok",…}`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum PolicyRequest {
    /// T6.11: which policy file the daemon enforces (`reload`: re-read it
    /// first, like SIGHUP).
    PolicyStatus {
        #[serde(default)]
        reload: bool,
    },
    /// T6.12: where a credential can go and where it went.
    ReportAccess { name: String },
    /// T7.14: the caller's audit-chain entries after the one whose hash
    /// is `after` (absent: from the first), oldest first, one page.
    AuditTail {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        after: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyResponse {
    PolicyStatusOk {
        path: String,
        /// False when the file is absent: no policy, everything allowed.
        active: bool,
        rules: usize,
        /// Parse error: every governed operation is denied until fixed.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        error: Option<String>,
    },
    /// A CLI-local command finished (`kepr audit forward --once`, …).
    PolicyDone {
        message: String,
    },
    /// `kepr policy test FILE` (CLI-local): one line per passing case.
    PolicyTestOk {
        lines: Vec<String>,
    },
    AccessReportOk {
        name: String,
        rows: Vec<AccessRow>,
    },
    AuditTailOk {
        events: Vec<AuditRecord>,
        /// More entries follow: ask again after the last one.
        more: bool,
        /// `after` is no longer in the log (it was reset or rotated):
        /// this page starts again from the first entry.
        #[serde(default)]
        reset: bool,
    },
}

/// One audit-chain entry as the forwarders see it: what happened, never
/// a value (the chain holds none).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    /// Unix seconds.
    pub time: u64,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    pub uid: u32,
    pub user: String,
    /// `ok` or `fail: …`.
    pub result: String,
    /// The entry's chain hash: the resume point.
    pub hash: String,
}

/// One path of a credential: `binding`, `share`, `agent`, `read`, `ssh`,
/// `alias`, `folder`, `sync` or `policy`, and a line about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRow {
    pub kind: String,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    fn round_trip_req(r: PolicyRequest, wire: &str) {
        let s = serde_json::to_string(&Request::Policy(r.clone())).unwrap();
        assert_eq!(s, wire);
        match serde_json::from_str::<Request>(&s).unwrap() {
            Request::Policy(back) => assert_eq!(back, r),
            other => panic!("decoded as {other:?}"),
        }
    }

    fn round_trip_resp(r: PolicyResponse) {
        let s = serde_json::to_string(&Response::Policy(r.clone())).unwrap();
        match serde_json::from_str::<Response>(&s).unwrap() {
            Response::Policy(back) => assert_eq!(back, r),
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn policy_status_round_trips() {
        round_trip_req(
            PolicyRequest::PolicyStatus { reload: true },
            r#"{"cmd":"policy_status","reload":true}"#,
        );
        assert_eq!(
            serde_json::from_str::<PolicyRequest>(r#"{"cmd":"policy_status"}"#).unwrap(),
            PolicyRequest::PolicyStatus { reload: false }
        );
        round_trip_resp(PolicyResponse::PolicyStatusOk {
            path: "/etc/kepr/policy.toml".into(),
            active: true,
            rules: 3,
            error: Some("rule 1: unknown op `read`".into()),
        });
    }

    #[test]
    fn access_report_round_trips() {
        round_trip_req(
            PolicyRequest::ReportAccess { name: "K".into() },
            r#"{"cmd":"report_access","name":"K"}"#,
        );
        round_trip_resp(PolicyResponse::AccessReportOk {
            name: "K".into(),
            rows: vec![AccessRow {
                kind: "share".into(),
                detail: "sent 1 time(s)".into(),
            }],
        });
    }

    #[test]
    fn audit_tail_round_trips() {
        round_trip_req(
            PolicyRequest::AuditTail { after: None },
            r#"{"cmd":"audit_tail"}"#,
        );
        round_trip_req(
            PolicyRequest::AuditTail {
                after: Some("ab12".into()),
            },
            r#"{"cmd":"audit_tail","after":"ab12"}"#,
        );
        round_trip_resp(PolicyResponse::AuditTailOk {
            events: vec![AuditRecord {
                seq: 4,
                time: 1_700_000_000,
                op: "get".into(),
                name: Some("K".into()),
                uid: 1000,
                user: "alice".into(),
                result: "ok".into(),
                hash: "ab12".into(),
            }],
            more: false,
            reset: true,
        });
        round_trip_resp(PolicyResponse::PolicyDone {
            message: "forwarded 3 audit event(s)".into(),
        });
    }

    #[test]
    fn core_requests_keep_their_meaning() {
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"status"}"#).unwrap(),
            Request::Status
        ));
        assert!(matches!(
            serde_json::from_str::<Response>(
                r#"{"kind":"status_ok","locked":false,"password_protected":false}"#
            )
            .unwrap(),
            Response::StatusOk { .. }
        ));
    }
}
