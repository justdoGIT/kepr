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

/// Bytes read per step when scanning the log backwards.
const BLOCK: u64 = 256 * 1024;

/// The entry whose hash is `after` and every entry after it, found by
/// reading the log from its end in `block`-byte steps. `None`: no such
/// entry (or the log cannot be read).
pub fn entries_after(
    path: &std::path::Path,
    after: &str,
    block: u64,
) -> Option<(ChainEntry, Vec<ChainEntry>)> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let mut pos = f.metadata().ok()?.len();
    let mut carry: Vec<u8> = Vec::new(); // the start of a line cut by the block edge
    let mut newer: Vec<ChainEntry> = Vec::new(); // newest first
    let needle = after.as_bytes();
    while pos > 0 {
        let start = pos.saturating_sub(block.max(1));
        let mut data = vec![0u8; (pos - start) as usize];
        f.seek(SeekFrom::Start(start)).ok()?;
        f.read_exact(&mut data).ok()?;
        data.extend_from_slice(&carry);
        let mut lines = data.split(|b| *b == b'\n');
        // Not at the start of the file: the first piece may be a partial line.
        carry = if start > 0 {
            lines.next().map(<[u8]>::to_vec).unwrap_or_default()
        } else {
            Vec::new()
        };
        for line in lines.rev().filter(|l| !l.is_empty()) {
            // The next entry's line holds this hash too, as its prev_hash.
            let Ok(e) = serde_json::from_slice::<ChainEntry>(line) else {
                continue;
            };
            if line.windows(needle.len()).any(|w| w == needle) && e.hash == after {
                newer.reverse();
                return Some((e, newer));
            }
            newer.push(e);
        }
        pos = start;
    }
    None
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
    // A forwarder resumes near the end: read back from there instead of
    // parsing the whole log on every poll.
    let quick = after
        .and_then(|h| entries_after(&crate::audit_chain_path(), h, BLOCK))
        .filter(|(found, _)| all || found.uid == uid);
    let (events, more, reset) = match quick {
        Some((_, tail)) => page(&tail, uid, all, None),
        None => page(&read_chain(), uid, all, after),
    };
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

    fn write_log(path: &std::path::Path, n: u64) -> Vec<ChainEntry> {
        let log: Vec<ChainEntry> = (0..n).map(|i| e(i, 1 + (i % 3) as u32)).collect();
        let text: String = log
            .iter()
            .map(|x| serde_json::to_string(x).unwrap() + "\n")
            .collect();
        std::fs::write(path, text).unwrap();
        log
    }

    #[test]
    fn reading_back_from_the_end_matches_a_full_read() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("audit.log");
        let log = write_log(&p, 120);
        // Block sizes smaller than a line, around it, and larger than the file.
        for block in [1, 7, 150, 400, 4096, 1 << 20] {
            for after in ["h0", "h57", "h118", "h119"] {
                let (found, tail) = entries_after(&p, after, block).expect(after);
                assert_eq!(found.hash, after);
                let i = log.iter().position(|x| x.hash == after).unwrap();
                let want: Vec<&str> = log[i + 1..].iter().map(|x| x.hash.as_str()).collect();
                let got: Vec<&str> = tail.iter().map(|x| x.hash.as_str()).collect();
                assert_eq!(got, want, "block {block} after {after}");
                // And the page equals the one the whole-file read gives.
                let a = page(&tail, 1, false, None);
                let b = page(&log, 1, false, Some(after));
                if found.uid == 1 {
                    assert_eq!(a, b, "block {block} after {after}");
                }
            }
        }
    }

    /// `cargo test --release --bin kepr-daemon poll_cost -- --ignored --nocapture`
    #[test]
    #[ignore = "timing, not a check"]
    fn poll_cost_whole_file_against_reading_back() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("audit.log");
        let log = write_log(&p, 200_000);
        let after = log[log.len() - 20].hash.clone();
        let t = std::time::Instant::now();
        let whole: Vec<ChainEntry> = std::fs::read_to_string(&p)
            .unwrap()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let _ = page(&whole, 1, false, Some(&after));
        let whole_t = t.elapsed();
        let t = std::time::Instant::now();
        let (_, tail) = entries_after(&p, &after, BLOCK).unwrap();
        let _ = page(&tail, 1, false, None);
        eprintln!(
            "poll of 200000 entries: whole file {whole_t:?}, reading back {:?}",
            t.elapsed()
        );
    }

    #[test]
    fn an_unknown_hash_or_a_torn_tail_is_handled() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("audit.log");
        write_log(&p, 10);
        assert!(entries_after(&p, "nope", 64).is_none());
        assert!(entries_after(&d.path().join("missing"), "h1", 64).is_none());
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.push_str("{\"seq\":10,\"timest");
        std::fs::write(&p, text).unwrap();
        let (_, tail) = entries_after(&p, "h7", 64).unwrap();
        assert_eq!(tail.len(), 2, "the torn line is skipped");
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
