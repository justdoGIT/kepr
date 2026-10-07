// cli_policy/anomaly.rs — anomaly rules over gate journal events (T7.13).
// Pure: a learned `Baseline` (kept in a state file between runs) and an
// evaluator fed one journal event at a time, with the clock taken from the
// events and the local UTC offset passed in.
//
//   new path      a provider path the baseline has never seen
//   volume spike  this hour's requests > factor × the baseline's average hour
//   off hours     a request outside the allowed local hours / weekdays
//   error burst   N errors (HTTP ≥ 400 or blocked) within a window
//
// The first two need `baseline_days` of data before they fire. Journal
// lines carry provider, method, path (no query), status: never a value.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One gate journal line (`crates/kepr-gate/src/journal.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GateEvent {
    pub ts: u64,
    #[serde(default)]
    pub session: String,
    pub provider: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub blocked: Option<String>,
}

impl From<&kepr_core::gate_journal::JournalEntry> for GateEvent {
    fn from(e: &kepr_core::gate_journal::JournalEntry) -> Self {
        GateEvent {
            ts: e.ts,
            session: e.session.clone(),
            provider: e.provider.clone(),
            method: e.method.clone(),
            path: e.path.clone(),
            status: e.status,
            blocked: e.blocked.clone(),
        }
    }
}

/// A journal line, alone or after a log prefix (`journalctl -o short`).
pub fn parse_line(line: &str) -> Option<GateEvent> {
    serde_json::from_str(&line[line.find('{')?..]).ok()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spike {
    #[serde(default = "five")]
    pub factor: f64,
    #[serde(default = "twenty")]
    pub min_requests: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OffHours {
    /// Allowed local hours, `[start, end)`; `[22, 6]` wraps midnight.
    pub hours: [u32; 2],
    #[serde(default)]
    pub weekdays_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Burst {
    #[serde(default = "ten")]
    pub errors: usize,
    #[serde(default = "minute")]
    pub window_secs: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewPath {}

/// `rules.toml`: where hits go, and the rules (sections absent = off).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// `https://…` or `kepr:NAME`; absent: hits are only printed.
    #[serde(default)]
    pub webhook: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    /// Per rule kind × provider, like the alert rules (default 10m).
    #[serde(default)]
    pub throttle: Option<String>,
    /// A hit runs `kepr panic`: every agent gate stops.
    #[serde(default)]
    pub revoke: bool,
    #[serde(default = "seven")]
    pub baseline_days: u64,
    #[serde(default)]
    pub new_path: Option<NewPath>,
    #[serde(default)]
    pub volume_spike: Option<Spike>,
    #[serde(default)]
    pub off_hours: Option<OffHours>,
    #[serde(default)]
    pub error_burst: Option<Burst>,
}

fn five() -> f64 {
    5.0
}
fn twenty() -> u64 {
    20
}
fn ten() -> usize {
    10
}
fn minute() -> u64 {
    60
}
fn seven() -> u64 {
    7
}

/// What the evaluator learned; persisted between runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    /// Time of the first event learned.
    #[serde(default)]
    pub since: Option<u64>,
    /// `provider METHOD /path` → first seen.
    #[serde(default)]
    pub paths: BTreeMap<String, u64>,
    /// provider → hour number → requests.
    #[serde(default)]
    pub hourly: BTreeMap<String, BTreeMap<u64, u64>>,
    /// provider → recent error times.
    #[serde(default)]
    pub errors: BTreeMap<String, Vec<u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    pub provider: String,
    pub detail: String,
}

/// An id-like path segment (numbers, long tokens) → `*`, so
/// `/v1/threads/thread_8f2a…/runs` is one path, not one per thread.
pub fn normalize(path: &str) -> String {
    let id = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            || (s.len() >= 16
                && s.bytes().any(|b| b.is_ascii_digit())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    };
    path.split('/')
        .map(|s| if id(s) { "*" } else { s })
        .collect::<Vec<_>>()
        .join("/")
}

/// Local hour and weekday (0 = Sunday) of `ts` at `utc_offset` seconds.
fn local(ts: u64, utc_offset: i64) -> (u32, u32) {
    let t = ts as i64 + utc_offset;
    let hour = t.div_euclid(3600).rem_euclid(24) as u32;
    let weekday = (t.div_euclid(86_400) + 4).rem_euclid(7) as u32; // 1970-01-01: Thursday
    (hour, weekday)
}

impl Baseline {
    fn ready(&self, rules: &Rules, now: u64) -> bool {
        self.since
            .is_some_and(|s| now >= s.saturating_add(rules.baseline_days * 86_400))
    }

    /// Learn `ev` and return the rules it trips.
    pub fn observe(&mut self, rules: &Rules, ev: &GateEvent, utc_offset: i64) -> Vec<Finding> {
        let mut out = Vec::new();
        let ready = self.ready(rules, ev.ts);
        self.since.get_or_insert(ev.ts);
        let hit = |kind, detail: String| Finding {
            kind,
            provider: ev.provider.clone(),
            detail,
        };

        let key = format!("{} {} {}", ev.provider, ev.method, normalize(&ev.path));
        if let std::collections::btree_map::Entry::Vacant(v) = self.paths.entry(key) {
            if ready && rules.new_path.is_some() {
                out.push(hit("new-path", format!("first request to {}", v.key())));
            }
            v.insert(ev.ts);
        }

        let window = rules.baseline_days.max(1) * 24;
        let hour = ev.ts / 3600;
        let counts = self.hourly.entry(ev.provider.clone()).or_default();
        let now_count = {
            let c = counts.entry(hour).or_default();
            *c += 1;
            *c
        };
        if let (true, Some(s)) = (ready, &rules.volume_spike) {
            let past: u64 = counts
                .range(hour.saturating_sub(window)..hour)
                .map(|(_, n)| n)
                .sum();
            let threshold = (s.factor * past as f64 / window as f64).max(s.min_requests as f64);
            // Fire once, when this hour first crosses the line.
            if now_count as f64 > threshold && (now_count - 1) as f64 <= threshold {
                out.push(hit(
                    "volume-spike",
                    format!(
                        "{now_count} requests this hour; the {}-day average is {:.1}/hour",
                        rules.baseline_days,
                        past as f64 / window as f64
                    ),
                ));
            }
        }
        let keep_from = hour.saturating_sub(window);
        counts.retain(|h, _| *h >= keep_from);

        if let Some(o) = &rules.off_hours {
            let (h, wd) = local(ev.ts, utc_offset);
            let [a, b] = o.hours;
            let in_hours = if a <= b {
                h >= a && h < b
            } else {
                h >= a || h < b
            };
            let weekend = o.weekdays_only && (wd == 0 || wd == 6);
            if !in_hours || weekend {
                out.push(hit(
                    "off-hours",
                    format!("{} {} at local hour {h:02}", ev.method, ev.path),
                ));
            }
        }

        if let Some(b) = &rules.error_burst {
            let errs = self.errors.entry(ev.provider.clone()).or_default();
            errs.retain(|t| ev.ts < t.saturating_add(b.window_secs));
            if ev.status >= 400 || ev.blocked.is_some() {
                errs.push(ev.ts);
                if errs.len() == b.errors {
                    out.push(hit(
                        "error-burst",
                        format!("{} errors within {}s", b.errors, b.window_secs),
                    ));
                }
            }
        }
        out
    }
}

#[cfg(test)]
pub fn ev(ts: u64, provider: &str, path: &str, status: u16) -> GateEvent {
    GateEvent {
        ts,
        session: "s1".into(),
        provider: provider.into(),
        method: "POST".into(),
        path: path.into(),
        status,
        blocked: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;
    /// 2026-10-05 (a Monday) 00:00 UTC.
    const T0: u64 = 1_791_158_400;

    fn rules(extra: &str) -> Rules {
        toml::from_str(&format!("baseline_days = 2\n{extra}")).unwrap()
    }

    fn kinds(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|x| x.kind).collect()
    }

    #[test]
    fn parses_journal_lines() {
        let line = r#"{"ts":5,"session":"s","provider":"anthropic","method":"POST","path":"/v1/messages","status":200,"bytes_out":9,"ms":3}"#;
        assert_eq!(parse_line(line).unwrap().path, "/v1/messages");
        let prefixed = format!("Oct 07 10:00:00 host kepr-gate[42]: {line}");
        assert_eq!(parse_line(&prefixed).unwrap().provider, "anthropic");
        assert!(parse_line("kepr-gate: listening on 127.0.0.1:4100").is_none());
        assert!(parse_line(r#"{"ts":1}"#).is_none());
    }

    #[test]
    fn new_path_needs_the_baseline() {
        let r = rules("[new_path]");
        let mut b = Baseline::default();
        // Day 0: everything is new but there is no baseline yet.
        assert!(b
            .observe(&r, &ev(T0 + 10, "openai", "/v1/chat/completions", 200), 0)
            .is_empty());
        assert!(b
            .observe(&r, &ev(T0 + DAY, "openai", "/v1/files", 200), 0)
            .is_empty());
        // Two days later the baseline is ready: a known path is quiet, a new one fires.
        let later = T0 + 2 * DAY + 20;
        assert!(b
            .observe(&r, &ev(later, "openai", "/v1/chat/completions", 200), 0)
            .is_empty());
        let f = b.observe(
            &r,
            &ev(later, "openai", "/v1/organization/admin_api_keys", 200),
            0,
        );
        assert_eq!(kinds(&f), ["new-path"]);
        assert_eq!(
            f[0].detail,
            "first request to openai POST /v1/organization/admin_api_keys"
        );
        // Ids are folded: a new thread id is not a new path.
        b.observe(
            &r,
            &ev(
                later,
                "openai",
                "/v1/threads/thread_abc123def456ghi7/runs",
                200,
            ),
            0,
        );
        let f = b.observe(
            &r,
            &ev(
                later,
                "openai",
                "/v1/threads/thread_zzz999yyy888xxx7/runs",
                200,
            ),
            0,
        );
        assert!(f.is_empty());
    }

    #[test]
    fn volume_spike_against_the_hourly_average() {
        let r = rules("[volume_spike]\nfactor = 4.0\nmin_requests = 5");
        let mut b = Baseline::default();
        // Two days at 2 requests per hour.
        for h in 0..48 {
            for i in 0..2 {
                assert!(b
                    .observe(
                        &r,
                        &ev(T0 + h * 3600 + i, "anthropic", "/v1/messages", 200),
                        0
                    )
                    .is_empty());
            }
        }
        let hour = T0 + 48 * 3600;
        let mut fired = Vec::new();
        for i in 0..12 {
            fired.extend(b.observe(&r, &ev(hour + i, "anthropic", "/v1/messages", 200), 0));
        }
        // Average 2/hour × 4 = 8: the 9th request fires, once.
        assert_eq!(kinds(&fired), ["volume-spike"]);
        assert_eq!(
            fired[0].detail,
            "9 requests this hour; the 2-day average is 2.0/hour"
        );
        // Another provider has no history of its own: under min_requests, quiet.
        assert!(b
            .observe(&r, &ev(hour, "openai", "/v1/x", 200), 0)
            .is_empty());
    }

    #[test]
    fn off_hours_in_local_time() {
        let r = rules("[off_hours]\nhours = [8, 20]\nweekdays_only = true");
        let mut b = Baseline::default();
        // Monday 09:00 UTC is fine at UTC, off-hours at UTC-2 (07:00).
        assert!(b
            .observe(&r, &ev(T0 + 9 * 3600, "x", "/a", 200), 0)
            .is_empty());
        let f = b.observe(&r, &ev(T0 + 9 * 3600, "x", "/a", 200), -7200);
        assert_eq!(kinds(&f), ["off-hours"]);
        assert_eq!(f[0].detail, "POST /a at local hour 07");
        // Saturday noon.
        assert_eq!(
            kinds(&b.observe(&r, &ev(T0 + 5 * DAY + 12 * 3600, "x", "/a", 200), 0)),
            ["off-hours"]
        );
        // A wrapping window: night shift 22–06.
        let night = rules("[off_hours]\nhours = [22, 6]");
        assert!(b
            .observe(&night, &ev(T0 + 23 * 3600, "x", "/a", 200), 0)
            .is_empty());
        assert_eq!(
            kinds(&b.observe(&night, &ev(T0 + 12 * 3600, "x", "/a", 200), 0)),
            ["off-hours"]
        );
    }

    #[test]
    fn error_bursts_within_the_window() {
        let r = rules("[error_burst]\nerrors = 3\nwindow_secs = 60");
        let mut b = Baseline::default();
        let mut fired = Vec::new();
        for t in [0, 30, 100, 130] {
            fired.extend(b.observe(&r, &ev(T0 + t, "x", "/a", 401), 0));
        }
        assert!(fired.is_empty(), "never 3 within 60s");
        fired.extend(b.observe(&r, &ev(T0 + 140, "x", "/a", 200), 0));
        let mut blocked = ev(T0 + 150, "x", "/a", 403);
        blocked.blocked = Some("dlp".into());
        fired.extend(b.observe(&r, &blocked, 0));
        assert_eq!(kinds(&fired), ["error-burst"]);
        assert!(
            b.observe(&r, &ev(T0 + 151, "x", "/a", 500), 0).is_empty(),
            "fires once per burst"
        );
    }

    #[test]
    fn rules_file_rejects_typos() {
        assert!(toml::from_str::<Rules>("[volume_spike]\nfactr = 2.0").is_err());
        let r = rules("");
        assert!(r.new_path.is_none() && r.volume_spike.is_none());
    }
}
