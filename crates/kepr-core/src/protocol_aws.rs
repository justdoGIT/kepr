// protocol_aws.rs — wire types of the `aws` ticket batch: scheduled
// rotation (T7.07), JIT grants (T7.10), check-out / check-in (T7.11). Wrapped by `Request::Aws` / `Response::Aws`, which are
// `#[serde(untagged)]` and tried after every tagged variant, so the `cmd`
// / `kind` names here must not repeat one in protocol.rs or another
// batch's file (they all start with `aws_`). Nothing here is secret.

use serde::{Deserialize, Serialize};

/// How a scheduled rotation runs (`.meta` `rotate_via`):
/// `aws-iam`, `db`, `provider`, `provider:<name>`,
/// `provider:<name>:<bootstrap credential>`, or
/// `hook:<generator>:<absolute path>`.
pub fn valid_rotate_via(via: &str) -> bool {
    match via {
        "aws-iam" | "db" | "provider" => true,
        _ if via.starts_with("provider:") => {
            let mut parts = via["provider:".len()..].split(':');
            let valid_part = |part: Option<&str>| {
                part.is_some_and(|p| {
                    !p.is_empty()
                        && p.len() <= 64
                        && p.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                })
            };
            valid_part(parts.next())
                && match parts.next() {
                    None => true,
                    Some(bootstrap) => valid_part(Some(bootstrap)) && parts.next().is_none(),
                }
        }
        _ => via
            .strip_prefix("hook:")
            .and_then(|r| r.split_once(':'))
            .is_some_and(|(kind, path)| {
                crate::generate::GenKind::from_str(kind).is_some()
                    && path.starts_with('/')
                    && path.len() <= 4096
                    && !path.chars().any(char::is_control)
            }),
    }
}

/// Shortest and longest `--every`.
pub const ROTATE_EVERY_MIN_SECS: u64 = 3600;
pub const ROTATE_EVERY_MAX_SECS: u64 = 10 * 365 * 86_400;

/// T7.10: a window in which agent sessions of `harness` may use a
/// just-in-time (`jit`) sealed credential. `until` is unix seconds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub harness: String,
    pub until: u64,
    /// T7.12: opened by an approved M-of-N request, not by the owner
    /// alone — which is what satisfies an `approvals` requirement.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub approved: bool,
}

/// A grant for every harness of the session. `valid_harness` rejects it,
/// so only the daemon writes one (T7.12's approved windows).
pub const ANY_HARNESS: &str = "*";

/// Longest `kepr grant --for`.
pub const GRANT_MAX_SECS: u64 = 7 * 86_400;

/// T7.11: who holds a credential checked out, in its `.meta`. Only the
/// daemon writes one; `token_sha256` never leaves it (a `CredInfo`
/// carries the uid and the deadline, never the hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hold {
    pub uid: u32,
    pub token_sha256: String,
    /// Unix seconds: a hold always runs out, so a lost token can't lock
    /// a credential for good.
    pub until: u64,
}

/// `kepr checkout --for`: the default and the longest hold.
pub const HOLD_SECS: u64 = 3600;
pub const HOLD_MAX_SECS: u64 = 24 * 3600;

/// A harness name as `kepr agent run` sends it (StartGate `harness`).
pub fn valid_harness(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 64
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// T7.10: what `kepr grant` does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantOp {
    /// Make the credential just-in-time (if it isn't) and let sessions
    /// of `harness` use it for `for_secs`.
    Open { harness: String, for_secs: u64 },
    /// End the windows of `harness`, or all of them.
    Revoke { harness: Option<String> },
    /// Just-in-time on (no session may use it without a grant) or off.
    Jit { on: bool },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum AwsRequest {
    /// T7.07: rotate `name` every `every_secs` the way `via` says
    /// (`valid_rotate_via`); both `None` stops the schedule.
    AwsRotateSchedule {
        name: String,
        every_secs: Option<u64>,
        via: Option<String>,
    },
    /// T7.10: `kepr grant`.
    AwsGrant { name: String, op: GrantOp },
    /// T7.11: take `name` for `for_secs`; the reply carries the token
    /// `AwsCheckin` needs back.
    AwsCheckout { name: String, for_secs: u64 },
    /// T7.11: release `name`. `rotated` only says whether the client
    /// rotated the value first (for the audit line).
    AwsCheckin {
        name: String,
        token: String,
        #[serde(default)]
        rotated: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AwsResponse {
    /// The schedule of `name`; `next_at` (unix seconds) is `None` once
    /// it is stopped.
    AwsRotateScheduled { name: String, next_at: Option<u64> },
    /// T7.10: the credential's grants after a `kepr grant`.
    AwsGrants {
        name: String,
        jit: bool,
        grants: Vec<Grant>,
    },
    /// T7.11: `name` is held until `until`; `token` releases it.
    AwsCheckedOut {
        name: String,
        token: String,
        until: u64,
    },
    /// T7.11: `name` is free again.
    AwsCheckedIn { name: String, rotated: bool },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    #[test]
    fn rotate_via_forms() {
        for ok in [
            "aws-iam",
            "db",
            "provider",
            "provider:openai",
            "provider:openrouter",
            "provider:openrouter:OPENROUTER_ADMIN",
            "provider:auto:ROTATION_ADMIN",
            "hook:hex:/home/u/bin/rotate.sh",
            "hook:words:/a:b",
        ] {
            assert!(valid_rotate_via(ok), "{ok}");
        }
        for bad in [
            "",
            "hook",
            "hook:/abs",
            "hook:hex:relative.sh",
            "hook:nope:/a",
            "hook:hex:/a\nb",
            "provider:openrouter:",
            "provider:openrouter:ADMIN:EXTRA",
            "provider:open router:ADMIN",
            "aws",
        ] {
            assert!(!valid_rotate_via(bad), "{bad}");
        }
    }

    #[test]
    fn harness_names_and_grant_ops() {
        for ok in ["claude", "codex-cli", "omp_1", "a.b"] {
            assert!(valid_harness(ok), "{ok}");
        }
        for bad in ["", "a b", "../x", "a/b", ANY_HARNESS, &"x".repeat(65)] {
            assert!(!valid_harness(bad), "{bad}");
        }
        let r = Request::Aws(AwsRequest::AwsGrant {
            name: "K".into(),
            op: GrantOp::Open {
                harness: "claude".into(),
                for_secs: 7200,
            },
        });
        let wire = serde_json::to_string(&r).unwrap();
        assert!(wire.contains(r#""cmd":"aws_grant""#), "{wire}");
        let back: Request = serde_json::from_str(&wire).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), wire);
        let resp = Response::Aws(AwsResponse::AwsGrants {
            name: "K".into(),
            jit: true,
            grants: vec![Grant {
                harness: "claude".into(),
                until: 9,
                approved: false,
            }],
        });
        let wire = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&wire).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), wire);
    }

    #[test]
    fn checkout_and_checkin_round_trip() {
        let r = Request::Aws(AwsRequest::AwsCheckout {
            name: "K".into(),
            for_secs: HOLD_SECS,
        });
        let wire = serde_json::to_string(&r).unwrap();
        assert!(wire.contains(r#""cmd":"aws_checkout""#), "{wire}");
        assert_eq!(
            serde_json::to_string(&serde_json::from_str::<Request>(&wire).unwrap()).unwrap(),
            wire
        );
        let old = r#"{"cmd":"aws_checkin","name":"K","token":"ab"}"#;
        assert!(matches!(
            serde_json::from_str::<Request>(old).unwrap(),
            Request::Aws(AwsRequest::AwsCheckin { rotated: false, .. })
        ));
        for resp in [
            Response::Aws(AwsResponse::AwsCheckedOut {
                name: "K".into(),
                token: "ab".into(),
                until: 9,
            }),
            Response::Aws(AwsResponse::AwsCheckedIn {
                name: "K".into(),
                rotated: true,
            }),
        ] {
            let wire = serde_json::to_string(&resp).unwrap();
            let back: Response = serde_json::from_str(&wire).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), wire);
            assert!(matches!(back, Response::Aws(_)));
        }
    }

    #[test]
    fn requests_and_responses_round_trip_through_the_core_enums() {
        let r = Request::Aws(AwsRequest::AwsRotateSchedule {
            name: "K".into(),
            every_secs: Some(86_400),
            via: Some("aws-iam".into()),
        });
        let wire = serde_json::to_string(&r).unwrap();
        assert!(wire.contains(r#""cmd":"aws_rotate_schedule""#), "{wire}");
        let back: Request = serde_json::from_str(&wire).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), wire);
        assert!(matches!(back, Request::Aws(_)));
        let off = r#"{"cmd":"aws_rotate_schedule","name":"K","every_secs":null,"via":null}"#;
        assert!(matches!(
            serde_json::from_str::<Request>(off).unwrap(),
            Request::Aws(AwsRequest::AwsRotateSchedule {
                every_secs: None,
                ..
            })
        ));
        let resp = Response::Aws(AwsResponse::AwsRotateScheduled {
            name: "K".into(),
            next_at: Some(5),
        });
        let wire = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&wire).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), wire);
        assert!(matches!(back, Response::Aws(_)));
        assert!(matches!(
            serde_json::from_str::<Response>(r#"{"kind":"err","error":"x"}"#),
            Ok(Response::Err { .. })
        ));
    }
}
