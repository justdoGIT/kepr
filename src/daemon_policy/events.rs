// daemon_policy/events.rs — the audit chain as the event source: access
// reports (T6.12) read it whole; `AuditTail` (T7.14) hands it out page by
// page to the CLI-side forwarders and alert rules, which run as the user
// because this daemon cannot open network sockets.
//
// A caller sees its own uid's entries; root on the system daemon sees
// every user's (it is the machine's SIEM feed). Entries are op / name /
// uid / user / result / time: the chain never holds a value.

use std::io::{BufRead, BufReader};

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{AuditRecord, PolicyResponse};

use crate::audit_chain::ChainEntry;

/// Most entries in one page, and the JSON budget that keeps a page well
/// under the 64 KiB frame limit.
const PAGE_MAX: usize = 200;
const PAGE_BYTES: usize = 40 * 1024;

pub fn read_chain() -> Vec<ChainEntry> {
    let Ok(f) = std::fs::File::open(crate::audit_chain_path()) else {
        return Vec::new();
    };
    BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

fn record(e: &ChainEntry) -> AuditRecord {
    AuditRecord {
        seq: e.seq,
        time: e.timestamp_unix,
        op: e.op.clone(),
        name: e.name.clone(),
        uid: e.uid,
        user: e.username.clone(),
        result: e.result.clone(),
        hash: e.hash.clone(),
    }
}

/// The page after `after` among the entries `uid` may see (`all`: every
/// uid's). Returns (events, more, reset).
pub fn page(
    entries: &[ChainEntry],
    uid: u32,
    all: bool,
    after: Option<&str>,
) -> (Vec<AuditRecord>, bool, bool) {
    let visible: Vec<&ChainEntry> = entries.iter().filter(|e| all || e.uid == uid).collect();
    let (start, reset) = match after {
        None => (0, false),
        Some(h) => match visible.iter().position(|e| e.hash == h) {
            Some(i) => (i + 1, false),
            None => (0, true),
        },
    };
    let mut out = Vec::new();
    let mut bytes = 0;
    for e in &visible[start..] {
        let r = record(e);
        bytes += serde_json::to_string(&r).map_or(0, |s| s.len() + 1);
        if out.len() == PAGE_MAX || (bytes > PAGE_BYTES && !out.is_empty()) {
            return (out, true, reset);
        }
        out.push(r);
    }
    (out, false, reset)
}

/// `AuditTail`. Not itself audited: a forwarder polls every few seconds,
/// and an entry per poll would feed back into the stream it reads.
pub fn handle_tail(uid: u32, after: Option<&str>) -> Response {
    let all = uid == 0 && !crate::user_mode();
    let (events, more, reset) = page(&read_chain(), uid, all, after);
    Response::Policy(PolicyResponse::AuditTailOk {
        events,
        more,
        reset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(seq: u64, uid: u32) -> ChainEntry {
        ChainEntry {
            seq,
            timestamp_unix: 1000 + seq,
            op: "get".into(),
            name: Some(format!("K{seq}")),
            uid,
            username: format!("u{uid}"),
            result: "ok".into(),
            prev_hash: String::new(),
            hash: format!("h{seq}"),
        }
    }

    #[test]
    fn pages_follow_the_hash_and_hide_other_users() {
        let log = [e(0, 1), e(1, 2), e(2, 1), e(3, 1)];
        let (ev, more, reset) = page(&log, 1, false, None);
        let seqs: Vec<u64> = ev.iter().map(|r| r.seq).collect();
        assert_eq!((seqs, more, reset), (vec![0, 2, 3], false, false));
        let (ev, _, _) = page(&log, 1, false, Some("h2"));
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].hash, "h3");
        assert!(page(&log, 1, false, Some("h3")).0.is_empty());
        // Another user's hash is not a resume point for this one.
        let (ev, _, reset) = page(&log, 1, false, Some("h1"));
        assert!(reset);
        assert_eq!(ev.len(), 3);
        // Root on the system daemon sees everyone.
        assert_eq!(page(&log, 0, true, Some("h0")).0.len(), 3);
    }

    #[test]
    fn long_logs_come_in_pages_under_the_frame_limit() {
        let log: Vec<ChainEntry> = (0..1000).map(|i| e(i, 1)).collect();
        let (ev, more, _) = page(&log, 1, false, None);
        assert!(more);
        assert!(ev.len() <= PAGE_MAX);
        let wire = serde_json::to_string(&Response::Policy(PolicyResponse::AuditTailOk {
            events: ev.clone(),
            more,
            reset: false,
        }))
        .unwrap();
        assert!(wire.len() < kepr_core::protocol::MAX_MSG_BYTES);
        let last = ev.last().unwrap().hash.clone();
        let (next, _, _) = page(&log, 1, false, Some(&last));
        assert_eq!(next[0].seq, ev.len() as u64);
    }
}
