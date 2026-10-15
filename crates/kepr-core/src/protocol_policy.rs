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
    ReportAccess {
        name: String,
    },
    /// T7.14: the caller's audit-chain entries after the one whose hash
    /// is `after` (absent: from the first), oldest first, one page.
    AuditTail {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        after: Option<String>,
    },
    /// T9.04: let the registered approver answer consent prompts for
    /// `name` (`via`: desktop | ntfy | any); `None` clears it.
    ApproveVia {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        via: Option<String>,
    },
    /// T9.04: make the calling process the user's approver (polkit
    /// confirms it once); replies `ApproverKey`.
    ApproverRegister,
    /// T9.04: the requests waiting for the approver (`key` from
    /// `ApproverKey`; the same process must ask).
    ApprovalPoll {
        key: String,
    },
    /// T9.04: answer one waiting request with its one-time token.
    ApprovalAnswer {
        key: String,
        id: String,
        token: String,
        allow: bool,
    },
    /// T9.07: name the harness of one of the caller's gate sessions
    /// (`kepr agent run` sends it once; the first name stays).
    SessionHarness {
        session: String,
        harness: String,
    },
    /// T9.07: `kepr usage --report`: gate-journal counts per harness ×
    /// credential × host over `days` (everything kept when absent), and
    /// bound hosts no request reached in `unused_days`.
    UsageReport {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        days: Option<u32>,
        unused_days: u32,
    },
    /// T9.08: store a decoy key for `provider` as `name`, to be planted
    /// in `planted_in` (a path, recorded for `ls` / `rm`).
    CanaryPlant {
        name: String,
        provider: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        planted_in: Option<String>,
    },
    CanaryList,
    CanaryRemove {
        name: String,
    },
    /// T9.08: a provider-side webhook fired for the canary `trip_id`.
    CanaryTrip {
        trip_id: String,
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
    ApproverKey {
        key: String,
        /// How long a request waits for an answer.
        timeout_secs: u64,
    },
    ApprovalsPending {
        pending: Vec<PendingApproval>,
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
    UsageReportOk {
        /// Start of the window, `YYYY-MM-DD HH:MM` UTC; absent = all kept.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        since: Option<String>,
        rows: Vec<UsageRow>,
        /// Over-scoped bindings: bound hosts unused for `unused_days`.
        unused: Vec<UnusedBinding>,
        unused_days: u32,
        /// Rows beyond what one reply holds were left out.
        #[serde(default)]
        truncated: bool,
    },
    /// `value` is the decoy (never a working key), for the CLI to plant;
    /// `trip_id` names its webhook (`/kepr-canary/<trip_id>`).
    CanaryPlanted {
        name: String,
        value: String,
        trip_id: String,
    },
    CanaryListing {
        canaries: Vec<CanaryEntry>,
    },
    CanaryRemoved {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        planted_in: Option<String>,
    },
}

/// T9.08: one planted canary and how often it tripped (audit log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryEntry {
    pub name: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub planted_in: Option<String>,
    /// `YYYY-MM-DD HH:MM` UTC.
    pub created: String,
    pub trip_id: String,
    /// `kepr_core::canary::fingerprint` of the decoy, so import / discover
    /// / adopt can leave it alone without seeing the value.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub fingerprint: String,
    pub tripped: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_tripped: Option<String>,
}

/// T9.07: one harness × credential × host line of the usage report.
/// `cred` is `-` for traffic no credential was added to (tunnels).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRow {
    pub harness: String,
    pub cred: String,
    pub host: String,
    pub requests: u64,
    /// Refused by the gate (DLP, limits).
    pub blocked: u64,
    /// As the providers reported them.
    pub tokens: u64,
}

/// T9.07: a host a sealed credential is bound to that no request
/// reached in the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnusedBinding {
    pub cred: String,
    pub host: String,
    /// Last request in the journal kept, `YYYY-MM-DD HH:MM` UTC.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_used: Option<String>,
}

/// T9.04: a consent request waiting for the approver. `token` is the
/// one-time answer token; `requester` the program that asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingApproval {
    pub id: String,
    pub token: String,
    pub name: String,
    pub via: String,
    pub requester: String,
    /// Unix seconds; unanswered by then = denied.
    pub expires_at: u64,
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
    fn usage_report_round_trips() {
        round_trip_req(
            PolicyRequest::UsageReport {
                days: Some(7),
                unused_days: 30,
            },
            r#"{"cmd":"usage_report","days":7,"unused_days":30}"#,
        );
        round_trip_req(
            PolicyRequest::SessionHarness {
                session: "0123456789abcdef".into(),
                harness: "claude".into(),
            },
            r#"{"cmd":"session_harness","session":"0123456789abcdef","harness":"claude"}"#,
        );
        round_trip_resp(PolicyResponse::UsageReportOk {
            since: None,
            rows: vec![UsageRow {
                harness: "claude".into(),
                cred: "ANTHROPIC_API_KEY".into(),
                host: "api.anthropic.com".into(),
                requests: 3,
                blocked: 1,
                tokens: 900,
            }],
            unused: vec![UnusedBinding {
                cred: "GH".into(),
                host: "uploads.github.com".into(),
                last_used: None,
            }],
            unused_days: 30,
            truncated: false,
        });
    }

    #[test]
    fn canary_round_trips() {
        round_trip_req(
            PolicyRequest::CanaryPlant {
                name: "OPENAI_API_KEY".into(),
                provider: "openai".into(),
                planted_in: Some("/home/a/.env".into()),
            },
            r#"{"cmd":"canary_plant","name":"OPENAI_API_KEY","provider":"openai","planted_in":"/home/a/.env"}"#,
        );
        round_trip_req(PolicyRequest::CanaryList, r#"{"cmd":"canary_list"}"#);
        round_trip_req(
            PolicyRequest::CanaryTrip {
                trip_id: "ab".into(),
            },
            r#"{"cmd":"canary_trip","trip_id":"ab"}"#,
        );
        round_trip_resp(PolicyResponse::CanaryListing {
            canaries: vec![CanaryEntry {
                name: "K".into(),
                provider: "xai".into(),
                planted_in: None,
                created: "2026-10-08 00:00".into(),
                trip_id: "ab".into(),
                fingerprint: "f0".into(),
                tripped: 2,
                last_tripped: Some("2026-10-08 01:00".into()),
            }],
        });
        round_trip_resp(PolicyResponse::CanaryRemoved {
            name: "K".into(),
            planted_in: Some("/x/.env".into()),
        });
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
    fn approvals_round_trip() {
        round_trip_req(
            PolicyRequest::ApproveVia {
                name: "K".into(),
                via: Some("ntfy".into()),
            },
            r#"{"cmd":"approve_via","name":"K","via":"ntfy"}"#,
        );
        round_trip_req(
            PolicyRequest::ApproverRegister,
            r#"{"cmd":"approver_register"}"#,
        );
        round_trip_req(
            PolicyRequest::ApprovalPoll { key: "k".into() },
            r#"{"cmd":"approval_poll","key":"k"}"#,
        );
        round_trip_req(
            PolicyRequest::ApprovalAnswer {
                key: "k".into(),
                id: "i".into(),
                token: "t".into(),
                allow: true,
            },
            r#"{"cmd":"approval_answer","key":"k","id":"i","token":"t","allow":true}"#,
        );
        round_trip_resp(PolicyResponse::ApproverKey {
            key: "k".into(),
            timeout_secs: 60,
        });
        round_trip_resp(PolicyResponse::ApprovalsPending {
            pending: vec![PendingApproval {
                id: "i".into(),
                token: "t".into(),
                name: "K".into(),
                via: "any".into(),
                requester: "/usr/bin/x (pid 1)".into(),
                expires_at: 5,
            }],
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
