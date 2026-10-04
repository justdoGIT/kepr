// daemon_usage.rs — `kepr usage`: per-credential usage report from the
// hash-chained audit log (agent vault P9.6 / A15 "unused / stale key
// report").
//
// For each of the caller's current credentials: how often it was used
// (get, gate resolve, SSH sign) and refused in the window, and when it
// was last used at all. Never-used keys stand out so they can be
// revoked. Only entries with the caller's uid are read, and the chain
// is verified first so the report says whether the log is intact.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

use kepr_core::protocol::{KeyUsage, Response};

use crate::audit::{self, AuditEvent, AuditResult};
use crate::audit_chain::{AuditChain, ChainEntry};
use crate::{daemon_cache, expiry};

/// Audit ops that count as "the value was used".
const USE_OPS: &[&str] = &["get", "resolve", "ssh-sign"];

#[derive(Default)]
struct Tally {
    uses: u64,
    refused: u64,
    last_used: Option<u64>,
}

/// Fold one uid's entries into per-name tallies. `since` bounds the
/// counts; `last_used` is all-time.
fn tally<'a>(
    entries: impl Iterator<Item = &'a ChainEntry>,
    uid: u32,
    since: u64,
) -> (HashMap<String, Tally>, u64) {
    let mut by_name: HashMap<String, Tally> = HashMap::new();
    let mut gate_sessions = 0;
    for e in entries.filter(|e| e.uid == uid) {
        let ok = e.result == "ok";
        if e.op == "start-gate" && ok && e.timestamp_unix >= since {
            gate_sessions += 1;
        }
        let Some(name) = e.name.as_ref().filter(|_| USE_OPS.contains(&e.op.as_str())) else {
            continue;
        };
        let t = by_name.entry(name.clone()).or_default();
        if ok {
            t.last_used = t.last_used.max(Some(e.timestamp_unix));
        }
        if e.timestamp_unix >= since {
            if ok {
                t.uses += 1;
            } else {
                t.refused += 1;
            }
        }
    }
    (by_name, gate_sessions)
}

fn read_entries(path: &Path) -> Vec<ChainEntry> {
    let Ok(f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

pub fn handle_usage(uid: u32, username: &str, chain_path: &Path, days: Option<u32>) -> Response {
    let now = expiry::now_unix();
    let since = days.map_or(0, |d| now.saturating_sub(u64::from(d) * 86_400));
    let chain_intact = AuditChain::verify(chain_path).is_ok();
    let entries = read_entries(chain_path);
    let (mut by_name, gate_sessions) = tally(entries.iter(), uid, since);
    let keys = daemon_cache::list_for_uid(uid)
        .into_iter()
        .map(|(name, _)| {
            let t = by_name.remove(&name).unwrap_or_default();
            KeyUsage {
                name,
                uses: t.uses,
                refused: t.refused,
                last_used: t.last_used.map(expiry::format_expires_at),
            }
        })
        .collect();
    audit::log(&AuditEvent {
        op: "usage",
        name: None,
        uid,
        username,
        result: AuditResult::Ok,
    });
    Response::UsageOk {
        since: (since > 0).then(|| expiry::format_expires_at(since)),
        chain_intact,
        gate_sessions,
        keys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(uid: u32, ts: u64, op: &str, name: Option<&str>, result: &str) -> ChainEntry {
        ChainEntry {
            seq: 0,
            timestamp_unix: ts,
            op: op.into(),
            name: name.map(str::to_string),
            uid,
            username: "u".into(),
            result: result.into(),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    #[test]
    fn tallies_only_the_callers_uses_in_the_window() {
        let log = [
            e(1, 10, "resolve", Some("A"), "ok"),
            e(1, 200, "get", Some("A"), "ok"),
            e(1, 300, "resolve", Some("A"), "fail: sealed"),
            e(1, 400, "set", Some("A"), "ok"),
            e(2, 500, "get", Some("A"), "ok"),
            e(1, 150, "start-gate", None, "ok"),
            e(1, 50, "start-gate", None, "ok"),
        ];
        let (t, gates) = tally(log.iter(), 1, 100);
        let a = &t["A"];
        assert_eq!((a.uses, a.refused, a.last_used), (1, 1, Some(200)));
        assert_eq!(gates, 1);
        assert!(!t.contains_key("B"));
    }
}
