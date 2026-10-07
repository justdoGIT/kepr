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
    /// `kepr policy test FILE` (CLI-local): one line per passing case.
    PolicyTestOk { lines: Vec<String> },
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
