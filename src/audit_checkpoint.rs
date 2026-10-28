// audit_checkpoint.rs — where the last start-up verified the audit chain.
//
// `AuditChain::open` used to re-hash the whole log on every daemon start:
// O(entries), seconds on a log of a few hundred thousand lines. It now
// records, next to the log (`audit.log.ckpt`), the number of entries
// verified, the head hash and the byte offset they end at, and the next
// start verifies only what follows. The checkpoint is used only when the
// log still has, ending at that offset, the entry it names (same seq and
// hash); anything else, and `KEPR_AUDIT_FULL_VERIFY=1`, means a full walk.
//
// This does not weaken tamper evidence against anyone who can write the
// log: the chain is unkeyed, so such a writer can rebuild it whole (see
// the anchors, T13.22). `kepr audit-verify` always checks the full file.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::audit_chain::{ChainEntry, VerifyReport};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub entries: u64,
    pub hash: String,
    pub offset: u64,
}

/// A checkpoint older than this is not used: the whole log is walked
/// again, so a quiet edit of old entries surfaces within a week.
const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// Longest log line looked at when confirming a checkpoint.
const MAX_LINE: u64 = 64 * 1024;

fn path_for(chain: &Path) -> PathBuf {
    let mut p = chain.as_os_str().to_owned();
    p.push(".ckpt");
    PathBuf::from(p)
}

/// The checkpoint for `chain`, when it can be trusted to skip a prefix.
pub fn usable(chain: &Path) -> Option<Checkpoint> {
    if std::env::var_os("KEPR_AUDIT_FULL_VERIFY").is_some_and(|v| v == "1") {
        return None;
    }
    let file = path_for(chain);
    let age = std::fs::metadata(&file)
        .ok()?
        .modified()
        .ok()?
        .elapsed()
        .ok()?;
    if age > MAX_AGE {
        return None; // a full walk now and then
    }
    let c: Checkpoint = serde_json::from_slice(&std::fs::read(file).ok()?).ok()?;
    confirm(chain, &c).then_some(c)
}

/// Does the log hold entry `c.entries` with hash `c.hash` ending at
/// `c.offset`?
fn confirm(chain: &Path, c: &Checkpoint) -> bool {
    if c.entries == 0 || c.offset == 0 {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(chain) else {
        return false;
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return false;
    };
    if c.offset > len {
        return false;
    }
    // The last line before the offset: read a window back to its start.
    let from = c.offset.saturating_sub(MAX_LINE);
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(from)).is_err()
        || f.take(c.offset - from).read_to_end(&mut buf).is_err()
        || buf.last() != Some(&b'\n')
    {
        return false;
    }
    buf.pop();
    let start = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    if start == 0 && from > 0 {
        return false; // the line is longer than the window
    }
    serde_json::from_slice::<ChainEntry>(&buf[start..])
        .is_ok_and(|e| e.seq == c.entries && e.hash == c.hash)
}

/// Record the head just verified. Best effort: without a checkpoint the
/// next start walks the whole log.
pub fn save(chain: &Path, r: &VerifyReport) {
    if r.entries == 0 {
        return;
    }
    let c = Checkpoint {
        entries: r.entries as u64,
        hash: r.last_hash.clone(),
        offset: r.end_offset,
    };
    if let Ok(b) = serde_json::to_vec(&c) {
        let _ = crate::atomic_file::write(&path_for(chain), &b, 0o640);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_chain::AuditChain;

    fn log(n: usize) -> (PathBuf, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("audit.log");
        let c = AuditChain::open(p.clone()).unwrap();
        for i in 0..n {
            c.append("get", Some(&format!("K{i}")), 1, "u", "ok")
                .unwrap();
        }
        (p, d)
    }

    #[test]
    fn a_reopen_saves_a_checkpoint_the_next_one_uses() {
        let (p, _d) = log(5);
        assert!(
            usable(&p).is_none(),
            "nothing saved before the first reopen"
        );
        AuditChain::open(p.clone()).unwrap();
        let c = usable(&p).expect("checkpoint after a reopen");
        assert_eq!(c.entries, 5);
        assert_eq!(c.offset, std::fs::metadata(&p).unwrap().len());
        // Entries appended after the checkpoint are verified from it.
        let chain = AuditChain::open(p.clone()).unwrap();
        chain.append("set", Some("NEW"), 1, "u", "ok").unwrap();
        let again = AuditChain::open(p.clone()).unwrap();
        again.append("get", Some("NEWER"), 1, "u", "ok").unwrap();
        assert_eq!(AuditChain::verify(&p).unwrap().entries, 7);
    }

    #[test]
    fn the_resumed_walk_reaches_the_same_head_as_a_full_one() {
        let (p, _d) = log(40);
        AuditChain::open(p.clone()).unwrap();
        let c = usable(&p).unwrap();
        let chain = AuditChain::open(p.clone()).unwrap();
        for i in 0..10 {
            chain
                .append("get", Some(&format!("N{i}")), 2, "v", "ok")
                .unwrap();
        }
        let part = AuditChain::verify_from(&p, Some(&c)).unwrap();
        let full = AuditChain::verify(&p).unwrap();
        assert_eq!(
            (part.entries, &part.last_hash, part.end_offset),
            (50, &full.last_hash, full.end_offset)
        );
        assert_eq!(full.entries, 50);
    }

    #[test]
    fn an_edit_after_the_checkpoint_is_still_caught_at_start() {
        let (p, _d) = log(6);
        AuditChain::open(p.clone()).unwrap();
        let chain = AuditChain::open(p.clone()).unwrap();
        chain.append("get", Some("TAIL"), 1, "u", "ok").unwrap();
        drop(chain);
        let text = std::fs::read_to_string(&p).unwrap().replace("TAIL", "EVIL");
        std::fs::write(&p, text).unwrap();
        assert!(AuditChain::open(p).is_err());
    }

    #[test]
    fn a_checkpoint_that_does_not_match_the_log_is_ignored() {
        let (p, _d) = log(6);
        AuditChain::open(p.clone()).unwrap();
        // A replaced log: shorter, different.
        let (q, _e) = log(3);
        std::fs::copy(&q, &p).unwrap();
        assert!(usable(&p).is_none(), "offset past the end or hash differs");
        assert!(
            AuditChain::open(p.clone()).is_ok(),
            "full walk of the new log"
        );
        // A checkpoint file with junk.
        std::fs::write(path_for(&p), b"not json").unwrap();
        assert!(usable(&p).is_none());
        // Same length log, a different entry at the checkpoint.
        let (r, _f) = log(6);
        AuditChain::open(r.clone()).unwrap();
        let text = std::fs::read_to_string(&r).unwrap().replace("K5", "KX");
        std::fs::write(&r, text).unwrap();
        // The checkpoint names the entry's seq and hash, which still match:
        // start-up skips the prefix; the full walk is what finds the edit.
        assert!(
            AuditChain::verify(&r).is_err(),
            "the full walk finds the edit"
        );
        assert!(
            AuditChain::open(r).is_ok(),
            "start-up trusts its checkpoint"
        );
    }

    #[test]
    fn an_old_checkpoint_forces_a_full_walk() {
        let (p, _d) = log(4);
        AuditChain::open(p.clone()).unwrap();
        assert!(usable(&p).is_some());
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(8 * 24 * 3600);
        std::fs::File::options()
            .write(true)
            .open(path_for(&p))
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(usable(&p).is_none());
    }

    /// `cargo test --bin kepr-daemon audit_checkpoint -- --ignored --nocapture`
    #[test]
    #[ignore = "timing, not a check"]
    fn start_up_time_with_and_without_a_checkpoint() {
        let (p, _d) = log(200_000);
        let t = std::time::Instant::now();
        AuditChain::open(p.clone()).unwrap();
        let full = t.elapsed();
        let t = std::time::Instant::now();
        AuditChain::open(p.clone()).unwrap();
        let resumed = t.elapsed();
        eprintln!("200000 entries: full walk {full:?}, from checkpoint {resumed:?}");
        assert!(resumed < full);
    }

    #[test]
    fn full_verify_can_be_forced() {
        let (p, _d) = log(4);
        AuditChain::open(p.clone()).unwrap();
        assert!(usable(&p).is_some());
        std::env::set_var("KEPR_AUDIT_FULL_VERIFY", "1");
        let forced = usable(&p);
        std::env::remove_var("KEPR_AUDIT_FULL_VERIFY");
        assert!(forced.is_none());
    }
}
