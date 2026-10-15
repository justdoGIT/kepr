// cli_gatex/logs.rs — `kepr agent logs` (T11.22).
//
//   kepr agent logs [SESSION] [-n N] [--follow]
//
// Prints the gate request journal the daemon keeps for the caller: one
// line per request or connection (time, session, route, method, host and
// path template, status, bytes sent, duration, and why the gate blocked
// it). Metadata only: the gate journals what the agent sent, never a
// header, query, body or substituted key. `--follow` keeps polling from
// the daemon's cursor, which carries on across journal rotation.

use std::time::Duration;

use kepr_core::gate_journal::JournalEntry;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_gatex::{valid_session, GatexRequest, GatexResponse, LogCursor};

use crate::{cli_ui, client};

const USAGE: &str = "usage: kepr agent logs [SESSION] [-n N] [--follow]";
const DEFAULT_LAST: u32 = 100;
const POLL: Duration = Duration::from_secs(1);

#[derive(Debug, PartialEq)]
struct Args {
    session: Option<String>,
    last: u32,
    follow: bool,
}

fn parse(raw: &[String]) -> Result<Args, String> {
    let mut a = Args {
        session: None,
        last: DEFAULT_LAST,
        follow: false,
    };
    let mut it = raw.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--follow" | "-f" => a.follow = true,
            "-n" | "--lines" => {
                let n = it.next().ok_or(format!("{arg} needs a number\n{USAGE}"))?;
                a.last = n
                    .parse()
                    .ok()
                    .filter(|n| (1..=MAX_LAST).contains(n))
                    .ok_or(format!("{arg}: a number from 1 to {MAX_LAST}"))?;
            }
            "--json" => {}
            s if !s.starts_with('-') && a.session.is_none() => {
                if !valid_session(s) {
                    return Err(format!(
                        "{s}: not a session id (16 hex characters, as `kepr agent run` prints)"
                    ));
                }
                a.session = Some(s.to_string());
            }
            other => return Err(format!("unexpected argument: {other}\n{USAGE}")),
        }
    }
    Ok(a)
}

/// Same bound as the daemon's.
pub const MAX_LAST: u32 = 10_000;

pub fn main(raw: &[String]) -> Response {
    let a = match parse(raw) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    let json = cli_ui::json_mode();
    let mut kept = Vec::new();
    let mut shown = 0usize;
    let result = run(
        &a,
        send,
        |entries| {
            shown += entries.len();
            match (json, a.follow) {
                (true, true) => entries.iter().for_each(|e| println!("{}", ndjson(e))),
                (true, false) => kept.extend_from_slice(entries),
                (false, _) => entries.iter().for_each(|e| println!("{}", format_entry(e))),
            }
        },
        || {
            std::thread::sleep(POLL);
            true
        },
    );
    match result {
        Ok(next) => {
            if shown == 0 && !json {
                cli_ui::info("no agent requests journaled yet");
            }
            GatexResponse::AgentLogsOk {
                entries: kept,
                next,
                more: false,
            }
            .into()
        }
        Err(e) => Response::fail(e),
    }
}

/// One request, retried while the daemon's rate limit refuses it (a long
/// `-n` takes several pages).
fn send(req: &Request) -> Result<Response, String> {
    for _ in 0..20 {
        match client::send_request(req) {
            Ok(Response::Err { error }) if error.contains("rate limited") => {
                std::thread::sleep(Duration::from_millis(300));
            }
            other => return other,
        }
    }
    Err("the daemon is busy; try again".into())
}

/// The last `a.last` entries page by page, then (with `--follow`) every
/// new one: each poll asks from where the previous reply ended. `wait`
/// returns false to stop following. Returns the final cursor.
fn run(
    a: &Args,
    mut send: impl FnMut(&Request) -> Result<Response, String>,
    mut out: impl FnMut(&[JournalEntry]),
    mut wait: impl FnMut() -> bool,
) -> Result<LogCursor, String> {
    let (mut from, mut last) = (None, Some(a.last));
    loop {
        let req = Request::Gatex(GatexRequest::AgentLogs {
            session: a.session.clone(),
            from,
            last,
        });
        let (entries, next, more) = match send(&req)? {
            Response::Gatex(GatexResponse::AgentLogsOk {
                entries,
                next,
                more,
            }) => (entries, next, more),
            Response::Err { error } => return Err(error),
            _ => return Err("unexpected daemon response".into()),
        };
        out(&entries);
        (from, last) = (Some(next), None);
        let go_on = more || (a.follow && wait());
        if !go_on {
            return Ok(next);
        }
    }
}

fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn ndjson(e: &JournalEntry) -> String {
    serde_json::to_string(e).unwrap_or_default()
}

/// `YYYY-MM-DD HH:MM:SS` UTC.
fn utc(ts: u64) -> String {
    let d = kepr_core::sigv4::format_amz_date(ts); // YYYYMMDDTHHMMSSZ
    format!(
        "{}-{}-{} {}:{}:{}",
        &d[0..4],
        &d[4..6],
        &d[6..8],
        &d[9..11],
        &d[11..13],
        &d[13..15]
    )
}

/// One journal line for a person.
pub fn format_entry(e: &JournalEntry) -> String {
    let target = match (e.host.as_str(), e.path.as_str()) {
        (h, p) if p.starts_with('/') => format!("{h}{p}"),
        (h, "") => h.to_string(),
        ("", p) => p.to_string(),
        (h, p) => format!("{h} {p}"),
    };
    let mut line = format!(
        "{}  {}  {:<10} {:<7} {}  {}  {} B  {} ms",
        utc(e.ts),
        clean(&e.session),
        clean(&e.provider),
        clean(&e.method),
        clean(&target),
        e.status,
        e.bytes_out,
        e.ms
    );
    if let Some(b) = &e.blocked {
        line.push_str(&format!("  blocked: {}", clean(b)));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "0123456789abcdef";

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn entry(path: &str) -> JournalEntry {
        JournalEntry {
            ts: 1_791_331_201,
            session: SID.into(),
            provider: "anthropic".into(),
            host: "api.anthropic.com".into(),
            method: "POST".into(),
            path: path.into(),
            status: 200,
            bytes_out: 1234,
            ms: 56,
            blocked: None,
            tokens: None,
        }
    }

    #[test]
    fn parses_session_lines_and_follow() {
        let a = parse(&[]).unwrap();
        assert_eq!((a.session, a.last, a.follow), (None, DEFAULT_LAST, false));
        let a = parse(&v(&[SID, "-n", "5", "--follow"])).unwrap();
        assert_eq!(
            (a.session.as_deref(), a.last, a.follow),
            (Some(SID), 5, true)
        );
        assert!(parse(&v(&["-f"])).unwrap().follow);
        for bad in [
            &["-n"][..],
            &["-n", "0"],
            &["-n", "x"],
            &["../x"],
            &[SID, SID],
            &["--x"],
        ] {
            assert!(parse(&v(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn formats_http_database_and_blocked_lines() {
        assert_eq!(
            format_entry(&entry("/v1/messages")),
            "2026-10-07 00:00:01  0123456789abcdef  anthropic  POST    api.anthropic.com/v1/messages  200  1234 B  56 ms"
        );
        let db = JournalEntry {
            provider: "postgres".into(),
            host: "db.internal:5432".into(),
            method: "LOGIN".into(),
            path: "db:APP_DB".into(),
            ..entry("")
        };
        assert!(format_entry(&db).contains("postgres   LOGIN   db.internal:5432 db:APP_DB  200"));
        let blocked = JournalEntry {
            status: 403,
            blocked: Some("dlp".into()),
            ..entry("/v1/messages")
        };
        assert!(format_entry(&blocked).ends_with("403  1234 B  56 ms  blocked: dlp"));
        let hostile = JournalEntry {
            method: "GET\u{1b}[2J".into(),
            path: "/a\nb".into(),
            ..entry("")
        };
        let line = format_entry(&hostile);
        assert!(!line.chars().any(char::is_control), "{line:?}");
    }

    fn page(paths: &[&str], next: u64, more: bool) -> Response {
        GatexResponse::AgentLogsOk {
            entries: paths.iter().map(|p| entry(p)).collect(),
            next: LogCursor {
                gen: 1,
                offset: next,
            },
            more,
        }
        .into()
    }

    #[test]
    fn pages_then_follows_from_each_replys_cursor() {
        let replies = vec![
            page(&["/a", "/b"], 10, true),
            page(&["/c"], 20, false),
            page(&[], 20, false),
            page(&["/d"], 30, false),
        ];
        let mut replies = replies.into_iter();
        let mut asked = Vec::new();
        let mut got = Vec::new();
        let mut polls = 0;
        let a = Args {
            session: Some(SID.into()),
            last: 7,
            follow: true,
        };
        let end = run(
            &a,
            |req| {
                if let Request::Gatex(GatexRequest::AgentLogs {
                    session,
                    from,
                    last,
                }) = req
                {
                    asked.push((session.clone(), *from, *last));
                }
                Ok(replies.next().unwrap())
            },
            |es| got.extend(es.iter().map(|e| e.path.clone())),
            || {
                polls += 1;
                polls < 3
            },
        )
        .unwrap();
        assert_eq!(got, ["/a", "/b", "/c", "/d"]);
        assert_eq!(end, LogCursor { gen: 1, offset: 30 });
        let at = |o| Some(LogCursor { gen: 1, offset: o });
        let s = Some(SID.to_string());
        assert_eq!(
            asked,
            [
                (s.clone(), None, Some(7)),
                (s.clone(), at(10), None),
                (s.clone(), at(20), None),
                (s, at(20), None),
            ]
        );
    }

    #[test]
    fn without_follow_it_stops_at_the_end_and_reports_errors() {
        let a = Args {
            session: None,
            last: 1,
            follow: false,
        };
        let mut n = 0;
        let end = run(
            &a,
            |_| Ok(page(&["/a"], 5, false)),
            |_| n += 1,
            || panic!("no wait"),
        );
        assert_eq!((end.unwrap().offset, n), (5, 1));
        let err = run(&a, |_| Ok(Response::fail("nope")), |_| {}, || true);
        assert_eq!(err.unwrap_err(), "nope");
    }
}
