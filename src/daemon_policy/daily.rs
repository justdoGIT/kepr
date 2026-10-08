// daemon_policy/daily.rs — T9.06: per-credential daily usage that every
// gate session of a user reports to (`GateRequest::DayUsage`), so
// `kepr agent run --max-requests-day / --max-tokens-day` hold across
// sessions. A day is the daemon's local calendar day: the counters start
// again at local midnight. Kept in memory and in a small 0600 state file
// per user (rewritten at most every few seconds and on a new day), so a
// daemon restart doesn't hand out a fresh allowance.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Most credentials tracked per user per day.
const MAX_CREDS: usize = 1024;
const SAVE_EVERY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Day {
    /// Local days since 1970-01-01.
    pub day: i64,
    /// Credential → (requests, tokens) today.
    pub creds: BTreeMap<String, (u64, u64)>,
}

/// The local day number of `ts` at `utc_offset` seconds.
pub fn local_day(ts: u64, utc_offset: i64) -> i64 {
    (ts as i64 + utc_offset).div_euclid(86_400)
}

impl Day {
    /// Add usage on `today`; a new day starts from zero. Returns today's
    /// totals for `name`.
    pub fn add(&mut self, today: i64, name: &str, requests: u64, tokens: u64) -> (u64, u64) {
        if self.day != today {
            *self = Day {
                day: today,
                creds: BTreeMap::new(),
            };
        }
        if !self.creds.contains_key(name) && self.creds.len() >= MAX_CREDS {
            return (u64::MAX, u64::MAX); // fail closed rather than grow
        }
        let e = self.creds.entry(name.to_string()).or_default();
        e.0 = e.0.saturating_add(requests);
        e.1 = e.1.saturating_add(tokens);
        *e
    }
}

struct Slot {
    day: Day,
    saved: Option<Instant>,
}

static DAYS: Mutex<Option<HashMap<u32, Slot>>> = Mutex::new(None);

fn state_path(uid: u32) -> PathBuf {
    #[cfg(test)]
    let root = std::env::temp_dir().join(format!("kepr-daily-tests-{}", std::process::id()));
    #[cfg(not(test))]
    let root = crate::state_dir();
    root.join(format!("daily-usage-{uid}.json"))
}

/// `tm_gmtoff` of the daemon's local time at `ts`.
fn utc_offset(ts: u64) -> i64 {
    let t = ts as libc::time_t;
    // SAFETY: localtime_r only writes into the zeroed `tm` we own.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return 0;
    }
    tm.tm_gmtoff
}

/// Record a gate's usage of `name` for `uid`; returns today's totals.
pub fn record(uid: u32, name: &str, requests: u64, tokens: u64) -> (u64, u64) {
    let now = crate::expiry::now_unix();
    record_at(
        uid,
        name,
        (requests, tokens),
        local_day(now, utc_offset(now)),
    )
}

fn record_at(uid: u32, name: &str, (requests, tokens): (u64, u64), today: i64) -> (u64, u64) {
    let mut g = DAYS.lock().unwrap_or_else(|p| p.into_inner());
    let slot = g
        .get_or_insert_with(HashMap::new)
        .entry(uid)
        .or_insert_with(|| {
            let day = std::fs::read(state_path(uid))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            Slot { day, saved: None }
        });
    let new_day = slot.day.day != today;
    let totals = slot.day.add(today, name, requests, tokens);
    if new_day || slot.saved.is_none_or(|t| t.elapsed() >= SAVE_EVERY) {
        if let Ok(bytes) = serde_json::to_vec(&slot.day) {
            let p = state_path(uid);
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = crate::atomic_file::write(&p, &bytes, 0o600);
        }
        slot.saved = Some(Instant::now());
    }
    totals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_reset_at_local_midnight() {
        // 2026-10-07 23:30 UTC is 2026-10-08 01:30 at UTC+2.
        let ts = 1_791_331_200 + 23 * 3600 + 1800;
        assert_eq!(local_day(ts, 0) + 1, local_day(ts, 7200));
        assert_eq!(local_day(ts, -3600), local_day(ts, 0));
        let mut d = Day::default();
        let today = local_day(ts, 0);
        assert_eq!(d.add(today, "K", 1, 0), (1, 0));
        assert_eq!(d.add(today, "K", 1, 500), (2, 500));
        assert_eq!(
            d.add(today + 1, "K", 1, 0),
            (1, 0),
            "a new day starts at zero"
        );
        assert_eq!(d.creds.len(), 1);
    }

    #[test]
    fn a_second_session_sees_the_first_ones_usage() {
        let (uid, today) = (8_101, 20_000);
        // Session A: two requests and 300 tokens.
        record_at(uid, "OPENAI", (1, 0), today);
        record_at(uid, "OPENAI", (1, 300), today);
        // Session B asks for its first request and sees the day so far.
        assert_eq!(record_at(uid, "OPENAI", (1, 0), today), (3, 300));
        // Other users and other credentials are separate.
        assert_eq!(record_at(8_102, "OPENAI", (1, 0), today), (1, 0));
        assert_eq!(record_at(uid, "ANTHROPIC", (1, 0), today), (1, 0));
        // And it survives a restart (the state file; force the next write).
        let forget =
            |f: &dyn Fn(&mut HashMap<u32, Slot>)| f(DAYS.lock().unwrap().as_mut().unwrap());
        forget(&|m| m.get_mut(&uid).unwrap().saved = None);
        record_at(uid, "OPENAI", (0, 0), today);
        forget(&|m| {
            m.remove(&uid);
        });
        assert_eq!(record_at(uid, "OPENAI", (0, 0), today), (3, 300));
        let _ = std::fs::remove_file(state_path(uid));
    }

    #[test]
    fn a_gate_reports_only_its_sessions_credentials() {
        use kepr_core::gate_protocol::GateResponse;
        let creds: std::collections::HashSet<String> = ["MINE".to_string()].into();
        let other = super::super::day_usage(&creds, 8_103, 4, "THEIRS", (1, 0));
        assert!(
            matches!(other, GateResponse::Err { id: 4, ref error } if error == "credential unavailable")
        );
        let mine = super::super::day_usage(&creds, 8_103, 5, "MINE", (1, 7));
        assert!(matches!(
            mine,
            GateResponse::UsageToday {
                id: 5,
                requests: 1,
                tokens: 7
            }
        ));
        let _ = std::fs::remove_file(state_path(8_103));
    }
}
