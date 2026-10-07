// cli_policy/alerts_cmd.rs — `kepr alerts check|run` (T7.15): watch the
// audit feed and post rule hits to their webhooks. Runs as the user (the
// daemon has no network). Webhook URLs are resolved once at start, so
// fetching a `kepr:NAME` URL doesn't itself become a stream of events.
// The first run starts at the end of the log: alerts are for new events.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;

use super::alerts::{self, Rule, Throttle};
use super::notify::{self, Format, Note};
use super::tail;
use crate::{cli_mode, cli_ui};

const USAGE: &str =
    "usage: kepr alerts check|run [--file alerts.toml] [--once] [--interval SECS] [--state FILE]";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub after: Option<String>,
    /// False until the first run skipped to the end of the log.
    #[serde(default)]
    pub started: bool,
    #[serde(default)]
    pub throttle: Throttle,
}

/// One pass over new events: returns how many alerts were sent. A failed
/// send keeps both the cursor and the throttle where they were, so the
/// page is retried on the next pass.
pub fn pass(
    src: &dyn tail::Source,
    rules: &[Rule],
    send: &dyn Fn(usize, &Note) -> Result<(), String>,
    state_path: &Path,
    now: u64,
) -> Result<usize, String> {
    let st = RefCell::new(tail::load::<State>(state_path));
    let mut after = st.borrow().after.clone();
    let fresh = !st.borrow().started;
    let mut sent = 0;
    tail::drain(
        src,
        &mut after,
        &mut |recs, _| {
            if fresh {
                return Ok(());
            }
            let mut t = st.borrow().throttle.clone();
            let hits = alerts::evaluate(rules, &mut t, recs, now);
            for h in &hits {
                send(h.rule, &h.note)?;
            }
            sent += hits.len();
            st.borrow_mut().throttle = t;
            Ok(())
        },
        &mut |a| {
            st.borrow_mut().after = a.clone();
            tail::save(state_path, &*st.borrow())
        },
    )?;
    if fresh {
        let mut s = st.borrow_mut();
        s.started = true;
        tail::save(state_path, &*s)?;
    }
    Ok(sent)
}

fn read_rules(path: &Path) -> Result<Vec<Rule>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    alerts::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn cmd_alerts(args: &[String]) -> Response {
    let a = super::plain_args(args);
    let file = crate::cli_extra::flag(args, "--file")
        .map(PathBuf::from)
        .unwrap_or_else(|| tail::config_dir().join("alerts.toml"));
    let rules = match read_rules(&file) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    match a.first() {
        Some(&"check") => {
            if !cli_mode::json_mode() {
                for r in &rules {
                    println!(
                        "{}: ops {:?} names {:?} result {:?}, throttle {}s",
                        r.name, r.ops, r.names, r.result, r.throttle_secs
                    );
                }
            }
            super::done(format!("{} alert rule(s) OK", rules.len()))
        }
        Some(&"run") => run(args, &file, &rules),
        _ => Response::fail(USAGE),
    }
}

fn run(args: &[String], file: &Path, rules: &[Rule]) -> Response {
    let interval = match crate::cli_extra::flag(args, "--interval").map(str::parse::<u64>) {
        None => 10,
        Some(Ok(n)) if n > 0 => n,
        Some(_) => return Response::fail("--interval needs a number of seconds"),
    };
    let mut hooks: Vec<(ZeroString, Format)> = Vec::new();
    for r in rules {
        match notify::resolve_url(&r.webhook) {
            Ok(url) => {
                let f = r.format.unwrap_or_else(|| Format::guess(url.as_str()));
                hooks.push((url, f));
            }
            Err(e) => return Response::fail(format!("rule {}: {e}", r.name)),
        }
    }
    let send = |i: usize, note: &Note| notify::send(hooks[i].0.as_str(), hooks[i].1, note);
    let state = crate::cli_extra::flag(args, "--state")
        .map(PathBuf::from)
        .unwrap_or_else(|| tail::state_file("alerts", &file.to_string_lossy()));
    if args.iter().any(|a| a == "--once") {
        return match pass(&tail::Daemon, rules, &send, &state, now()) {
            Ok(n) => super::done(format!("{n} alert(s) sent")),
            Err(e) => Response::fail(format!("alerts: {e}")),
        };
    }
    if !cli_mode::json_mode() {
        cli_ui::info(&format!(
            "watching the audit log with {} rule(s), every {interval}s (Ctrl-C stops)",
            rules.len()
        ));
    }
    loop {
        match pass(&tail::Daemon, rules, &send, &state, now()) {
            Ok(0) => {}
            Ok(n) => cli_ui::dim(&format!("{n} alert(s) sent")),
            Err(e) => cli_ui::warn(&format!("alerts: {e}; retrying")),
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_policy::siem::record;
    use crate::cli_policy::tail::fixture;
    use std::cell::RefCell;

    const RULES: &str =
        "[[rule]]\nname = \"deletes\"\nops = [\"delete\"]\nwebhook = \"https://x\"\n";

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kepr-alerts-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d.join("state.json")
    }

    #[test]
    fn first_run_skips_history_then_alerts_on_new_events() {
        let rules = alerts::parse(RULES).unwrap();
        let state = tmp("first");
        let log = fixture::Log::new(vec![record(0, "delete", Some("OLD"), "ok")]);
        let got = RefCell::new(Vec::new());
        let send = |_: usize, n: &Note| {
            got.borrow_mut().push(n.lines[0].clone());
            Ok(())
        };
        assert_eq!(pass(&log, &rules, &send, &state, 100).unwrap(), 0);
        log.records
            .borrow_mut()
            .push(record(1, "delete", Some("NEW"), "ok"));
        assert_eq!(pass(&log, &rules, &send, &state, 200).unwrap(), 1);
        assert_eq!(*got.borrow(), ["delete NEW by alice (uid 1000): ok"]);
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn a_failed_send_is_retried_not_throttled_away() {
        let rules = alerts::parse(RULES).unwrap();
        let state = tmp("retry");
        let log = fixture::Log::new(vec![]);
        pass(&log, &rules, &|_, _| Ok(()), &state, 0).unwrap();
        log.records
            .borrow_mut()
            .push(record(1, "delete", Some("K"), "ok"));
        let down = |_: usize, _: &Note| Err("webhook answered HTTP 500".to_string());
        assert!(pass(&log, &rules, &down, &state, 10).is_err());
        let (url, h) = notify::testserver::once(200);
        let up = |_: usize, n: &Note| notify::send(&url, Format::Discord, n);
        assert_eq!(pass(&log, &rules, &up, &state, 20).unwrap(), 1);
        assert!(h.join().unwrap().contains("delete K by alice"));
        let st: State = tail::load(&state);
        assert_eq!(st.after.as_deref(), Some("h1"));
        assert_eq!(st.throttle.sent["deletes"], 20);
        let _ = std::fs::remove_dir_all(state.parent().unwrap());
    }
}
