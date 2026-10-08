// rotate_sched.rs — scheduled rotation, CLI side (T7.07).
//
//   kepr rotate NAME --every 30d --hook CMD [--generate KIND]
//   kepr rotate NAME --every 30d --aws-iam | --db
//   kepr rotate NAME --every off          stop rotating NAME
//   kepr rotate NAME --scheduled          rotate now, the scheduled way
//
// The schedule lives in the credential's `.meta` (daemon_aws/
// rotate_sched.rs). The user-mode daemon spawns `kepr rotate NAME
// --scheduled` when one is due, which reads `rotate_via` back from
// `kepr list` and runs the matching rotator here, so the rotators and
// their network code never run inside the daemon.

use std::path::Path;

use kepr_core::generate::GenKind;
use kepr_core::protocol::{CredInfo, Request, Response};
use kepr_core::protocol_aws::{AwsRequest, AwsResponse};

use crate::cli_args::Args;

/// `30d`, `12h`, `90m`, `3600s`, `2w` or bare seconds; `off` is `None`.
pub fn parse_every(s: &str) -> Result<Option<u64>, String> {
    if s == "off" {
        return Ok(None);
    }
    let bad = || format!("--every takes a duration like 30d, 12h or 90m (or off), not {s:?}");
    let (num, unit) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c),
        _ => (s, 's'),
    };
    let mult = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        'w' => 7 * 86_400,
        _ => return Err(bad()),
    };
    let n: u64 = num.parse().map_err(|_| bad())?;
    n.checked_mul(mult)
        .filter(|v| *v > 0)
        .map(Some)
        .ok_or_else(bad)
}

/// A duration the way `--every` takes it, in its largest whole unit.
pub fn human(secs: u64) -> String {
    match secs {
        s if s >= 86_400 && s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s >= 3600 && s % 3600 == 0 => format!("{}h", s / 3600),
        s if s >= 60 && s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// A rough "in …" for a wait: the nearest day, hour or minute.
fn rough(secs: u64) -> String {
    match secs {
        s if s >= 86_400 => format!("{}d", (s + 43_200) / 86_400),
        s if s >= 3600 => format!("{}h", (s + 1800) / 3600),
        s => format!("{}m", s.div_ceil(60)),
    }
}

/// The `rotate_via` for this command line: exactly one rotator.
pub fn via(hook: Option<&Path>, kind: GenKind, aws_iam: bool, db: bool) -> Result<String, String> {
    match (hook, aws_iam, db) {
        (Some(h), false, false) => {
            let abs = std::fs::canonicalize(h).map_err(|e| format!("{}: {e}", h.display()))?;
            Ok(format!("hook:{}:{}", kind.as_str(), abs.display()))
        }
        (None, true, false) => Ok("aws-iam".into()),
        (None, false, true) => Ok("db".into()),
        (None, false, false) => {
            Err("--every needs a rotator: --hook CMD, --aws-iam or --db".into())
        }
        _ => Err("pick one rotator: --hook CMD, --aws-iam or --db".into()),
    }
}

/// `kepr rotate NAME --every DUR|off ...`
pub fn schedule(a: &Args, name: &str, every: &str) -> Response {
    let every = match parse_every(every) {
        Ok(e) => e,
        Err(e) => return Response::fail(e),
    };
    let rotator = a.hook_path.is_some() || a.aws.aws_iam || a.aws.db;
    let via = match every {
        None if rotator => return Response::fail("--every off takes no rotator"),
        None => None,
        Some(_) => match via(a.hook_path.as_deref(), a.gen_kind, a.aws.aws_iam, a.aws.db) {
            Ok(v) => Some(v),
            Err(e) => return Response::fail(e),
        },
    };
    let req = Request::Aws(AwsRequest::AwsRotateSchedule {
        name: name.to_uppercase(),
        every_secs: every,
        via,
    });
    let r = crate::client::send_request(&req).unwrap_or_else(Response::fail);
    if let (Response::Aws(AwsResponse::AwsRotateScheduled { name, next_at }), false) =
        (&r, crate::cli_ui::json_mode())
    {
        crate::cli_ui::ok(&match (every, next_at) {
            (Some(e), Some(_)) => format!(
                "{name} rotates every {} (next in {}); the user-mode daemon runs it, \
                 `kepr rotate {name} --scheduled` runs it now",
                human(e),
                rough(e)
            ),
            _ => format!("{name}: scheduled rotation stopped"),
        });
    }
    r
}

/// Print an error in human mode (core-verb errors aren't printed).
pub fn shout(r: Response) -> Response {
    if let (Some(e), false) = (r.err_msg(), crate::cli_ui::json_mode()) {
        crate::cli_ui::err(e);
    }
    r
}

fn scheduled_via(upper: &str) -> Result<String, String> {
    let list = crate::client::send_request(&Request::List)?;
    let Response::ListOk { credentials, .. } = list else {
        return Err(list.err_msg().unwrap_or("unexpected response").to_string());
    };
    credentials
        .into_iter()
        .find(|c| c.name == upper)
        .and_then(|c| c.rotate_via)
        .ok_or_else(|| {
            format!("{upper} has no rotation schedule (kepr rotate {upper} --every 30d --hook CMD)")
        })
}

fn run_hook(upper: &str, kind: &str, path: &str) -> Response {
    let Some(k) = GenKind::from_str(kind) else {
        return Response::fail(format!("unknown generator in the schedule: {kind}"));
    };
    let r = crate::cli_rotate::cmd_rotate(upper, k, Path::new(path));
    if r.is_success() && !crate::cli_ui::json_mode() {
        crate::cli_ui::ok(&format!("{upper} rotated; the hook accepted the new value"));
    }
    r
}

/// `kepr rotate NAME --scheduled`: run the rotator its schedule names.
pub fn run_scheduled(name: &str) -> Response {
    let upper = name.to_uppercase();
    let via = match scheduled_via(&upper) {
        Ok(v) => v,
        Err(e) => return shout(Response::fail(e)),
    };
    match via.as_str() {
        "aws-iam" => super::rotate_iam::cmd(&upper),
        "db" => shout(crate::cli_agent_db_rotate::cmd_rotate_db(&[upper])),
        _ => shout(
            match via.strip_prefix("hook:").and_then(|r| r.split_once(':')) {
                Some((kind, path)) => run_hook(&upper, kind, path),
                None => Response::fail("unknown rotation in the schedule"),
            },
        ),
    }
}

/// `kepr list`: the schedule, as of `now`.
pub fn tail_at(c: &CredInfo, now: u64) -> String {
    let (Some(every), Some(_)) = (c.rotate_every_secs, &c.rotate_via) else {
        return String::new();
    };
    let when = match (c.rotate_failures, c.rotate_next_at) {
        (Some(1), _) => "last try failed".into(),
        (Some(n), _) if n > 1 => format!("last {n} tries failed"),
        (_, Some(t)) if t > now => format!("next in {}", rough(t - now)),
        _ => "due".into(),
    };
    format!("  (rotates every {}, {when})", human(every))
}

pub fn list_tail(c: &CredInfo) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    tail_at(c, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_every("30d"), Ok(Some(30 * 86_400)));
        assert_eq!(parse_every("12h"), Ok(Some(43_200)));
        assert_eq!(parse_every("90m"), Ok(Some(5400)));
        assert_eq!(parse_every("2w"), Ok(Some(14 * 86_400)));
        assert_eq!(parse_every("3600"), Ok(Some(3600)));
        assert_eq!(parse_every("3600s"), Ok(Some(3600)));
        assert_eq!(parse_every("off"), Ok(None));
        for bad in ["", "d", "0d", "-1d", "30y", "1.5d", "99999999999999999999d"] {
            assert!(parse_every(bad).is_err(), "{bad}");
        }
        assert_eq!(human(30 * 86_400), "30d");
        assert_eq!(human(5400), "90m");
        assert_eq!(human(90_000), "25h");
        assert_eq!(rough(90_000), "1d");
        assert_eq!(rough(30 * 86_400 - 5), "30d");
        assert_eq!(rough(30), "1m");
    }

    #[test]
    fn exactly_one_rotator() {
        assert_eq!(via(None, GenKind::Hex, true, false), Ok("aws-iam".into()));
        assert_eq!(via(None, GenKind::Hex, false, true), Ok("db".into()));
        assert!(via(None, GenKind::Hex, false, false).is_err());
        assert!(via(None, GenKind::Hex, true, true).is_err());
        let sh = Path::new("/bin/sh");
        assert!(via(Some(sh), GenKind::Hex, true, false).is_err());
        let v = via(Some(sh), GenKind::Hex, false, false).unwrap();
        assert!(
            v.starts_with("hook:hex:/") && kepr_core::protocol_aws::valid_rotate_via(&v),
            "{v}"
        );
        assert!(via(Some(Path::new("/no/such/hook")), GenKind::Hex, false, false).is_err());
    }

    #[test]
    fn list_shows_the_next_rotation() {
        let mut c = CredInfo {
            name: "K".into(),
            ..Default::default()
        };
        assert_eq!(tail_at(&c, 0), "");
        c.rotate_every_secs = Some(30 * 86_400);
        c.rotate_via = Some("aws-iam".into());
        c.rotate_next_at = Some(1000 + 3 * 86_400);
        assert_eq!(tail_at(&c, 1000), "  (rotates every 30d, next in 3d)");
        assert_eq!(tail_at(&c, 1000 + 3 * 86_400), "  (rotates every 30d, due)");
        c.rotate_failures = Some(1);
        assert_eq!(tail_at(&c, 1000), "  (rotates every 30d, last try failed)");
        c.rotate_failures = Some(2);
        assert_eq!(
            tail_at(&c, 1000),
            "  (rotates every 30d, last 2 tries failed)"
        );
    }
}
