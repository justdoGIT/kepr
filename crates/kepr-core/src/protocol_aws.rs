// protocol_aws.rs — wire types of the `aws` ticket batch: scheduled
// rotation (T7.07). Wrapped by `Request::Aws` / `Response::Aws`, which are
// `#[serde(untagged)]` and tried after every tagged variant, so the `cmd`
// / `kind` names here must not repeat one in protocol.rs or another
// batch's file (they all start with `aws_`). Nothing here is secret.

use serde::{Deserialize, Serialize};

/// How a scheduled rotation runs (`.meta` `rotate_via`):
/// `aws-iam`, `db`, or `hook:<generator>:<absolute path>`.
pub fn valid_rotate_via(via: &str) -> bool {
    match via {
        "aws-iam" | "db" => true,
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
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AwsResponse {
    /// The schedule of `name`; `next_at` (unix seconds) is `None` once
    /// it is stopped.
    AwsRotateScheduled { name: String, next_at: Option<u64> },
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
            "aws",
        ] {
            assert!(!valid_rotate_via(bad), "{bad}");
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
