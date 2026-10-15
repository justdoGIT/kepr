// cli_policy/anomaly_cmd.rs — `kepr anomaly check|run` (T7.13): feed the
// gate request journal through the anomaly rules in ~/.config/kepr/rules.toml.
//
// By default the journal comes from the daemon, which keeps every gate's
// entries for `kepr agent logs` (followed with its cursor); `--journal
// FILE` reads JSON lines from a file (e.g. the gate's stderr), `-` from
// stdin. Hits are printed, posted to the rules' webhook through notify.rs
// (throttled per rule kind × provider), and with `revoke = true` answered
// with `kepr panic`. Entries older than FRESH_SECS only teach the
// baseline: replaying history never alerts or revokes. What was learned
// and the read position persist in a state file between runs.

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_gatex::{GatexRequest, GatexResponse, LogCursor};

use super::anomaly::{parse_line, Baseline, Finding, GateEvent, Rules};
use super::notify::{self, Format, Note};
use super::{siem, tail};
use crate::{cli_mode, cli_ui};

const USAGE: &str = "usage: kepr anomaly check | anomaly run [--journal daemon|FILE|-] [--rules FILE] [--once] [--interval SECS] [--state FILE]";
/// Older entries teach the baseline but raise nothing.
const FRESH_SECS: u64 = 600;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub baseline: Baseline,
    /// `kind provider` → when it last alerted.
    #[serde(default)]
    pub sent: BTreeMap<String, u64>,
    /// Bytes of the journal file already read.
    #[serde(default)]
    pub offset: u64,
    /// Where the daemon's journal was read up to.
    #[serde(default)]
    pub cursor: Option<LogCursor>,
}

/// What a hit does beyond being printed.
pub struct Act<'a> {
    pub throttle_secs: u64,
    pub send: &'a dyn Fn(&Note) -> Result<(), String>,
    /// `kepr panic`, when the rules ask for it.
    pub revoke: Option<&'a dyn Fn() -> Result<String, String>>,
    pub utc_offset: &'a dyn Fn(u64) -> i64,
    pub now: &'a dyn Fn() -> u64,
}

fn note(f: &Finding, ev: &GateEvent, revoked: Option<&str>) -> Note {
    let mut lines = vec![
        f.detail.clone(),
        format!("session {} at {}", ev.session, siem::rfc3339(ev.ts)),
    ];
    if let Some(r) = revoked {
        lines.push(r.to_string());
    }
    Note {
        title: format!("kepr anomaly: {} ({})", f.kind, f.provider),
        lines,
    }
}

/// Run `ev` through the rules; returns the hits that were not throttled.
pub fn handle(rules: &Rules, st: &mut State, ev: &GateEvent, act: &Act) -> Vec<Finding> {
    let mut fresh = Vec::new();
    let found = st.baseline.observe(rules, ev, (act.utc_offset)(ev.ts));
    if (act.now)().saturating_sub(ev.ts) > FRESH_SECS {
        return fresh; // history: learned, not acted on
    }
    for f in found {
        let key = format!("{} {}", f.kind, f.provider);
        let last = st.sent.get(&key).copied();
        if last.is_some_and(|l| ev.ts < l.saturating_add(act.throttle_secs)) {
            continue;
        }
        st.sent.insert(key, ev.ts);
        let revoked = act.revoke.map(|r| match r() {
            Ok(m) => m,
            Err(e) => format!("kepr panic failed: {e}"),
        });
        let n = note(&f, ev, revoked.as_deref());
        if !cli_mode::json_mode() {
            println!("{}: {}", n.title, n.lines.join("; "));
        }
        if let Err(e) = (act.send)(&n) {
            cli_ui::warn(&format!("anomaly alert not delivered: {e}"));
        }
        fresh.push(f);
    }
    fresh
}

/// The complete new lines of `path` since `st.offset` (a shorter file
/// was rotated: start again).
pub fn read_new(path: &Path, st: &mut State) -> Result<Vec<String>, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    if len < st.offset {
        st.offset = 0;
    }
    f.seek(SeekFrom::Start(st.offset))
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.take(64 << 20)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    let end = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    st.offset += end as u64;
    Ok(String::from_utf8_lossy(&buf[..end])
        .lines()
        .map(String::from)
        .collect())
}

/// New entries from the daemon's gate journal (`kepr agent logs`).
fn daemon_entries(st: &mut State) -> Result<Vec<GateEvent>, String> {
    let mut out = Vec::new();
    loop {
        let req = Request::Gatex(GatexRequest::AgentLogs {
            session: None,
            from: Some(st.cursor.unwrap_or_default()),
            last: None,
        });
        match crate::client::send_request(&req)? {
            Response::Gatex(GatexResponse::AgentLogsOk {
                entries,
                next,
                more,
            }) => {
                out.extend(entries.iter().map(GateEvent::from));
                st.cursor = Some(next);
                if !more {
                    return Ok(out);
                }
            }
            Response::Err { error } => return Err(error),
            _ => return Err("unexpected daemon response".into()),
        }
    }
}

/// `tm_gmtoff` of local time at `ts`.
fn utc_offset(ts: u64) -> i64 {
    let t = ts as libc::time_t;
    // SAFETY: localtime_r writes only into the zeroed `tm` we own.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return 0;
    }
    tm.tm_gmtoff
}

fn panic_gates() -> Result<String, String> {
    match crate::client::send_request(&Request::Panic)? {
        Response::PanicOk { gates_stopped, .. } => Ok(format!(
            "revoked: kepr panic stopped {gates_stopped} agent gate(s)"
        )),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

fn load_rules(path: &Path) -> Result<(Rules, u64), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let rules: Rules = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let throttle = match rules.throttle.as_deref() {
        None => 600,
        Some("0") => 0,
        Some(t) => crate::cli_sharing::parse_duration(t)?,
    };
    if let Some(f) = &rules.format {
        Format::parse(f)?;
    }
    Ok((rules, throttle))
}

pub fn cmd_anomaly(args: &[String]) -> Response {
    let a = super::plain_args(args);
    let file = crate::cli_extra::flag(args, "--rules")
        .map(PathBuf::from)
        .unwrap_or_else(|| tail::config_dir().join("rules.toml"));
    let (rules, throttle_secs) = match load_rules(&file) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    match a.first() {
        Some(&"check") => {
            let on: Vec<&str> = [
                ("new path", rules.new_path.is_some()),
                ("volume spike", rules.volume_spike.is_some()),
                ("off hours", rules.off_hours.is_some()),
                ("error burst", rules.error_burst.is_some()),
            ]
            .iter()
            .filter(|(_, on)| *on)
            .map(|(n, _)| *n)
            .collect();
            super::done(format!(
                "anomaly rules OK: {} (baseline {} days)",
                if on.is_empty() {
                    "none enabled".to_string()
                } else {
                    on.join(", ")
                },
                rules.baseline_days
            ))
        }
        Some(&"run") => match run(args, &file, &rules, throttle_secs) {
            Ok(n) => super::done(format!("{n} anomaly hit(s)")),
            Err(e) => Response::fail(format!("anomaly: {e}")),
        },
        _ => Response::fail(USAGE),
    }
}

fn run(args: &[String], file: &Path, rules: &Rules, throttle_secs: u64) -> Result<usize, String> {
    let journal = crate::cli_extra::flag(args, "--journal").unwrap_or("daemon");
    let interval = match crate::cli_extra::flag(args, "--interval").map(str::parse::<u64>) {
        None => 10,
        Some(Ok(n)) if n > 0 => n,
        Some(_) => return Err("--interval needs a number of seconds".into()),
    };
    let hook = rules
        .webhook
        .as_deref()
        .map(notify::resolve_url)
        .transpose()?;
    let format = match (&rules.format, &hook) {
        (Some(f), _) => Format::parse(f)?,
        (None, Some(u)) => Format::guess(u.as_str()),
        (None, None) => Format::Json,
    };
    let send = |n: &Note| match &hook {
        Some(u) => notify::send(u.as_str(), format, n),
        None => Ok(()),
    };
    let revoke: &dyn Fn() -> Result<String, String> = &panic_gates;
    let act = Act {
        throttle_secs,
        send: &send,
        revoke: rules.revoke.then_some(revoke),
        utc_offset: &utc_offset,
        now: &tail::now_unix,
    };
    let state = crate::cli_extra::flag(args, "--state")
        .map(PathBuf::from)
        .unwrap_or_else(|| tail::state_file("anomaly", &format!("{}\n{journal}", file.display())));
    let mut st: State = tail::load(&state);
    let mut hits = 0;
    if journal == "-" {
        for (i, line) in std::io::stdin()
            .lock()
            .lines()
            .map_while(Result::ok)
            .enumerate()
        {
            let Some(ev) = parse_line(&line) else {
                continue;
            };
            let n = handle(rules, &mut st, &ev, &act).len();
            hits += n;
            if n > 0 || i % 100 == 99 {
                tail::save(&state, &st)?;
            }
        }
        tail::save(&state, &st)?;
        return Ok(hits);
    }
    loop {
        let events: Vec<GateEvent> = match journal {
            "daemon" => daemon_entries(&mut st)?,
            path => read_new(Path::new(path), &mut st)?
                .iter()
                .filter_map(|l| parse_line(l))
                .collect(),
        };
        for ev in &events {
            hits += handle(rules, &mut st, ev, &act).len();
        }
        tail::save(&state, &st)?;
        if args.iter().any(|a| a == "--once") {
            return Ok(hits);
        }
        std::thread::sleep(Duration::from_secs(interval));
    }
}

#[cfg(test)]
mod tests {
    use super::super::anomaly::ev;
    use super::*;
    use std::cell::{Cell, RefCell};

    fn rules(text: &str) -> Rules {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn hits_alert_once_per_throttle_and_can_revoke() {
        let r = rules("revoke = true\n[error_burst]\nerrors = 2\nwindow_secs = 60");
        let notes = RefCell::new(Vec::new());
        let panics = Cell::new(0);
        let send = |n: &Note| {
            notes.borrow_mut().push(n.clone());
            Ok(())
        };
        let revoke = || {
            panics.set(panics.get() + 1);
            Ok("revoked: kepr panic stopped 1 agent gate(s)".to_string())
        };
        let act = Act {
            throttle_secs: 600,
            send: &send,
            revoke: Some(&revoke),
            utc_offset: &|_| 0,
            now: &|| 1_500,
        };
        let mut st = State::default();
        let mut hits = 0;
        // Two bursts 2 minutes apart: the second is inside the throttle.
        for t in [0, 1, 120, 121] {
            hits += handle(&r, &mut st, &ev(1000 + t, "openai", "/v1/x", 401), &act).len();
        }
        assert_eq!((hits, panics.get()), (1, 1));
        let n = notes.borrow()[0].clone();
        assert_eq!(n.title, "kepr anomaly: error-burst (openai)");
        assert_eq!(n.lines[1], "session s1 at 1970-01-01T00:16:41Z");
        assert_eq!(n.lines[2], "revoked: kepr panic stopped 1 agent gate(s)");
        // After the throttle window the next burst alerts again.
        for t in [700, 701] {
            hits += handle(&r, &mut st, &ev(1000 + t, "openai", "/v1/x", 500), &act).len();
        }
        assert_eq!(hits, 2);
        // History (older than FRESH_SECS) only teaches the baseline.
        let old = Act {
            now: &|| 1_000_000,
            ..act
        };
        for t in [900, 901] {
            hits += handle(&r, &mut st, &ev(1000 + t, "openai", "/v1/x", 500), &old).len();
        }
        assert_eq!((hits, panics.get()), (2, 2));
    }

    #[test]
    fn journal_files_are_read_incrementally() {
        let d = std::env::temp_dir().join(format!("kepr-anomaly-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join("gate.log");
        let line = |t: u64| {
            format!(
                r#"{{"ts":{t},"session":"s","provider":"p","method":"GET","path":"/a","status":200}}"#
            )
        };
        std::fs::write(&path, format!("{}\nnoise\n{}", line(1), line(2))).unwrap();
        let mut st = State::default();
        // The unterminated last line waits for its newline.
        assert_eq!(read_new(&path, &mut st).unwrap(), [line(1), "noise".into()]);
        std::fs::write(&path, format!("{}\nnoise\n{}\n", line(1), line(2))).unwrap();
        assert_eq!(read_new(&path, &mut st).unwrap(), [line(2)]);
        assert!(read_new(&path, &mut st).unwrap().is_empty());
        // Rotated (shorter): from the start.
        std::fs::write(&path, format!("{}\n", line(3))).unwrap();
        assert_eq!(read_new(&path, &mut st).unwrap(), [line(3)]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rules_files_validate() {
        let d = std::env::temp_dir().join(format!("kepr-anomaly-rules-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("rules.toml");
        std::fs::write(
            &p,
            "webhook = \"https://x\"\nthrottle = \"5m\"\n[new_path]\n",
        )
        .unwrap();
        assert_eq!(load_rules(&p).unwrap().1, 300);
        std::fs::write(&p, "format = \"pager\"\n").unwrap();
        assert!(load_rules(&p).is_err());
        std::fs::write(&p, "webhok = \"https://x\"\n").unwrap();
        assert!(load_rules(&p).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
