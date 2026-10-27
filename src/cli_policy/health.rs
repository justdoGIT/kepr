// cli_policy/health.rs — `kepr health … --notify URL [--format F]`
// (T6.08): post the findings to a webhook. The message carries names
// and finding flags only: never a value, and never the breach-lookup
// hash prefix that `KeyHealth` carries for the range query.

use kepr_core::protocol::{KeyHealth, Response};

use super::notify::{self, Format, Note};
use crate::{cli_mode, cli_ui};

pub struct HealthNotify {
    /// `https://…` or `kepr:NAME` (resolved when sending).
    url: String,
    format: Option<Format>,
}

/// `--notify URL [--format F]` from the health arguments.
pub fn parse(args: &[String]) -> Result<Option<HealthNotify>, String> {
    let format = match crate::cli_extra::flag(args, "--format") {
        Some(f) => Some(Format::parse(f)?),
        None if args.iter().any(|a| a == "--format") => return Err("--format needs a value".into()),
        None => None,
    };
    match crate::cli_extra::flag(args, "--notify") {
        Some(url) => Ok(Some(HealthNotify {
            url: url.to_string(),
            format,
        })),
        None if args.iter().any(|a| a == "--notify") => {
            Err("--notify needs a webhook URL (or kepr:NAME)".into())
        }
        None if format.is_some() => Err("--format goes with --notify URL".into()),
        None => Ok(None),
    }
}

/// The health arguments without `--notify URL` / `--format F`, for the
/// `kepr health` parser, which owns the rest.
pub fn rest(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--notify" || a == "--format" {
            it.next();
        } else {
            out.push(a.clone());
        }
    }
    out
}

/// The webhook message, or `None` when every credential is healthy.
pub fn note(items: &[KeyHealth]) -> Option<Note> {
    let lines: Vec<String> = items
        .iter()
        .filter(|i| !i.issues.is_empty())
        .map(|i| format!("{}: {}", i.name, i.issues.join("; ")))
        .collect();
    if lines.is_empty() {
        return None;
    }
    Some(Note {
        title: format!(
            "kepr health: {} of {} credential(s) need attention",
            lines.len(),
            items.len()
        ),
        lines,
    })
}

/// Post the findings of a finished `kepr health` run.
pub fn after(n: Option<HealthNotify>, r: Response) -> Response {
    let (Some(n), Response::HealthOk { items }) = (n, &r) else {
        return r;
    };
    let Some(note) = note(items) else {
        if !cli_mode::json_mode() {
            cli_ui::dim("no findings; nothing posted");
        }
        return r;
    };
    let sent = notify::resolve_url(&n.url).and_then(|url| {
        let format = n.format.unwrap_or_else(|| Format::guess(url.as_str()));
        notify::send(url.as_str(), format, &note)
    });
    match sent {
        Ok(()) => {
            if !cli_mode::json_mode() {
                cli_ui::ok("findings posted to the webhook");
            }
            r
        }
        Err(e) => Response::fail(format!("health findings not delivered: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rest_drops_the_notify_flags_only() {
        let a: Vec<String> = [
            "--period",
            "90d",
            "--notify",
            "kepr:HOOK",
            "--format",
            "slack",
            "--breach",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(rest(&a), vec!["--period", "90d", "--breach"]);
        let parsed = crate::cli_health::parse(&rest(&a)).unwrap();
        assert!(parsed.breach && parsed.period);
    }

    fn item(name: &str, issues: &[&str]) -> KeyHealth {
        KeyHealth {
            name: name.into(),
            issues: issues.iter().map(|s| s.to_string()).collect(),
            age_days: 400,
            hibp_prefix: Some("5BAA6".into()),
            ignored: Vec::new(),
            ignore: Vec::new(),
        }
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn note_lists_names_and_flags_only() {
        let items = [
            item(
                "DB_PASS",
                &["weak (easy to guess)", "found in a data breach"],
            ),
            item("FINE", &[]),
        ];
        let n = note(&items).unwrap();
        assert_eq!(n.title, "kepr health: 1 of 2 credential(s) need attention");
        assert_eq!(
            n.lines,
            ["DB_PASS: weak (easy to guess); found in a data breach"]
        );
        for f in [
            Format::Slack,
            Format::Teams,
            Format::Discord,
            Format::Ntfy,
            Format::Json,
        ] {
            let b = notify::render(f, &n);
            let all = format!("{}{:?}", b.body, b.headers);
            assert!(all.contains("DB_PASS"), "{f:?}");
            assert!(!all.contains("5BAA6"), "hash prefix leaked in {f:?}");
            assert!(!all.contains("FINE"), "{f:?}");
        }
        assert!(note(&[item("FINE", &[])]).is_none());
    }

    #[test]
    fn parses_notify_flags() {
        assert!(parse(&args(&["--breach"])).unwrap().is_none());
        let n = parse(&args(&["--notify", "kepr:HOOK", "--format", "ntfy"]))
            .unwrap()
            .unwrap();
        assert_eq!(n.url, "kepr:HOOK");
        assert_eq!(n.format, Some(Format::Ntfy));
        assert!(parse(&args(&["--notify"])).is_err());
        assert!(parse(&args(&["--format", "slack"])).is_err());
        assert!(parse(&args(&["--notify", "https://x", "--format", "pager"])).is_err());
    }

    #[test]
    fn delivers_and_reports_non_2xx() {
        let items = vec![item("DB_PASS", &["reused (same value as API_KEY)"])];
        let (url, h) = notify::testserver::once(200);
        let n = parse(&args(&["--notify", &url, "--format", "slack"])).unwrap();
        let r = after(
            n,
            Response::HealthOk {
                items: items.clone(),
            },
        );
        assert!(matches!(r, Response::HealthOk { .. }));
        let req = h.join().unwrap();
        assert!(req.contains("DB_PASS: reused"));
        assert!(!req.contains("5BAA6"));

        let (url, h) = notify::testserver::once(503);
        let n = parse(&args(&["--notify", &url])).unwrap();
        match after(n, Response::HealthOk { items }) {
            Response::Err { error } => assert_eq!(
                error,
                "health findings not delivered: webhook answered HTTP 503"
            ),
            other => panic!("{other:?}"),
        }
        h.join().unwrap();
    }
}
