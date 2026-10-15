// cli_aws/grant.rs — `kepr grant` (T7.10).
//
//   kepr grant NAME --to claude --for 2h   let claude sessions use NAME
//   kepr grant NAME --revoke [--to claude] close the window(s) now
//   kepr grant NAME --jit off              stop asking for grants
//   kepr grant NAME                        the windows NAME has open
//
// A granted credential is just-in-time (`jit` in its `.meta`): outside
// every window no agent session resolves it, and `kepr agent run` says
// which harness a session is (the daemon checks it at resolve time,
// daemon_aws/grant.rs). Nothing here prints a value.

use kepr_core::protocol::{CredInfo, Request, Response};
use kepr_core::protocol_aws::{AwsRequest, AwsResponse, Grant, GrantOp};

const USAGE: &str = "usage: kepr grant NAME [--to HARNESS --for 2h | --revoke [--to HARNESS] \
                     | --jit on|off]";

/// `2h`, `90m`, `45s`, `7d` or bare seconds.
pub fn parse_for(s: &str) -> Result<u64, String> {
    super::rotate_sched::parse_every(s)
        .ok()
        .flatten()
        .filter(|_| s != "off")
        .ok_or_else(|| format!("--for takes a window like 2h, 90m or 45s, not {s:?}"))
}

pub fn parse(args: &[&str]) -> Result<(String, Option<GrantOp>), String> {
    let valued = ["--to", "--for", "--jit"];
    let name = super::positional(args, &valued)
        .ok_or(USAGE)?
        .to_uppercase();
    let to = super::flag(args, "--to").map(str::to_string);
    let revoke = args.contains(&"--revoke");
    let op = match (
        to,
        super::flag(args, "--for"),
        super::flag(args, "--jit"),
        revoke,
    ) {
        (_, Some(_), _, true) | (_, _, Some(_), true) | (_, Some(_), Some(_), _) => {
            return Err(format!("--revoke, --for and --jit are separate\n{USAGE}"))
        }
        (Some(harness), Some(w), None, false) => Some(GrantOp::Open {
            harness,
            for_secs: parse_for(w)?,
        }),
        (harness, None, None, true) => Some(GrantOp::Revoke { harness }),
        (None, None, Some(on), false) => Some(GrantOp::Jit {
            on: match on {
                "on" => true,
                "off" => false,
                _ => return Err("--jit takes on or off".into()),
            },
        }),
        (None, None, None, false) => None,
        (Some(_), None, None, false) => {
            return Err(format!("--to needs --for 2h (or --revoke)\n{USAGE}"))
        }
        _ => return Err(USAGE.into()),
    };
    Ok((name, op))
}

/// What a credential's windows look like at `now`.
pub fn describe(jit: bool, grants: &[Grant], now: u64) -> String {
    let mut open: Vec<String> = grants
        .iter()
        .filter(|g| g.until > now)
        .map(|g| {
            let who = if g.harness == kepr_core::protocol_aws::ANY_HARNESS {
                "any session" // T7.12: an approved M-of-N window
            } else {
                g.harness.as_str()
            };
            let how = if g.approved { " (approved)" } else { "" };
            let left = super::rotate_sched::rough(g.until - now);
            format!("{who} for {left}{how}")
        })
        .collect();
    open.sort_unstable();
    match (jit, open.is_empty()) {
        (false, true) => "any agent session may use it (not just-in-time)".into(),
        (false, false) => format!("not just-in-time; windows kept: {}", open.join(", ")),
        (true, true) => "just-in-time: no window open, so no session can use it".into(),
        (true, false) => format!("just-in-time, open to {}", open.join(", ")),
    }
}

/// The credential's grants without changing them.
fn show(name: &str) -> Response {
    let list = crate::client::send_request(&Request::List).unwrap_or_else(Response::fail);
    let Response::ListOk { credentials, .. } = list else {
        return list;
    };
    let Some(c) = credentials.into_iter().find(|c| c.name == name) else {
        return Response::fail("credential unavailable");
    };
    let (jit, grants) = (c.jit == Some(true), c.grants.unwrap_or_default());
    if !crate::cli_ui::json_mode() {
        crate::cli_ui::info(&format!("{name}: {}", describe(jit, &grants, now())));
    }
    Response::Aws(AwsResponse::AwsGrants {
        name: name.to_string(),
        jit,
        grants,
    })
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn cmd(args: &[&str]) -> Response {
    let (name, op) = match parse(args) {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
    let Some(op) = op else {
        return show(&name);
    };
    let req = Request::Aws(AwsRequest::AwsGrant {
        name: name.clone(),
        op,
    });
    let r = crate::client::send_request(&req).unwrap_or_else(Response::fail);
    if let (Response::Aws(AwsResponse::AwsGrants { jit, grants, .. }), false) =
        (&r, crate::cli_ui::json_mode())
    {
        crate::cli_ui::ok(&format!("{name}: {}", describe(*jit, grants, now())));
    }
    r
}

/// `kepr list`: the just-in-time state.
pub fn list_tail(c: &CredInfo) -> String {
    if c.jit != Some(true) {
        return String::new();
    }
    let open = c
        .grants
        .iter()
        .flatten()
        .filter(|g| g.until > now())
        .count();
    match open {
        0 => "  (just-in-time: no grant)".into(),
        n => format!("  (just-in-time: {n} granted)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_three_shapes() {
        assert_eq!(
            parse(&["k", "--to", "claude", "--for", "2h"]).unwrap(),
            (
                "K".into(),
                Some(GrantOp::Open {
                    harness: "claude".into(),
                    for_secs: 7200
                })
            )
        );
        assert_eq!(
            parse(&["K", "--revoke", "--to", "claude"]).unwrap().1,
            Some(GrantOp::Revoke {
                harness: Some("claude".into())
            })
        );
        assert_eq!(
            parse(&["K", "--revoke"]).unwrap().1,
            Some(GrantOp::Revoke { harness: None })
        );
        assert_eq!(
            parse(&["K", "--jit", "off"]).unwrap().1,
            Some(GrantOp::Jit { on: false })
        );
        assert_eq!(parse(&["K"]).unwrap(), ("K".into(), None));
        for bad in [
            &["--to", "claude", "--for", "2h"][..],
            &["K", "--to", "claude"],
            &["K", "--for", "2h"],
            &["K", "--to", "claude", "--for", "off"],
            &["K", "--revoke", "--for", "2h"],
            &["K", "--jit", "maybe"],
            &["K", "--jit", "on", "--to", "claude"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse_for("45s"), Ok(45));
        assert!(parse_for("0h").is_err());
    }

    #[test]
    fn describes_and_lists_the_windows() {
        let g = |h: &str, until: u64| Grant {
            harness: h.into(),
            until,
            approved: false,
        };
        assert_eq!(
            describe(true, &[g("claude", 1000 + 7200)], 1000),
            "just-in-time, open to claude for 2h"
        );
        assert!(describe(true, &[g("claude", 999)], 1000).contains("no window open"));
        assert!(describe(false, &[], 0).contains("not just-in-time"));
        assert!(describe(false, &[g("a", 9_999_999_999)], 0).contains("windows kept: a for"));
        let approved = Grant {
            harness: kepr_core::protocol_aws::ANY_HARNESS.into(),
            until: 7200,
            approved: true,
        };
        assert_eq!(
            describe(true, &[approved], 0),
            "just-in-time, open to any session for 2h (approved)"
        );
        let mut c = CredInfo {
            name: "K".into(),
            ..Default::default()
        };
        assert_eq!(list_tail(&c), "");
        c.jit = Some(true);
        assert_eq!(list_tail(&c), "  (just-in-time: no grant)");
        c.grants = Some(vec![g("claude", 9_999_999_999), g("old", 1)]);
        assert_eq!(list_tail(&c), "  (just-in-time: 1 granted)");
    }
}
