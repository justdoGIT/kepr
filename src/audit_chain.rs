// audit_chain.rs — append-only hash-chained audit log.
//
// Phase 2 δ. Closes the public-review tamper-evidence finding: the
// existing journald-backed audit pipeline is correct (see
// `audit::log`) but every entry is deletable by root, and root is
// the daemon's own uid. A hash-chained file owned by the daemon
// gives reviewers a way to detect deletions and edits after the
// fact:
//
//   H_n = SHA-256(H_{n-1} || canonical_event_bytes_n)
//
// The genesis hash H_0 is 32 zero bytes. Each on-disk line carries
// its own `hash` and `prev_hash` so the file is self-describing —
// `verify` walks it, recomputes each H_n, and asserts equality.
// Any tampering — deletion, reorder, edit, fabrication — breaks
// either the H_n recomputation OR the prev_hash continuity, so the
// verifier rejects.
//
// What this PR ships: the chain primitives. `AuditChain::open` +
// `append` + `verify`, with full unit-test coverage of the success
// path AND every tamper shape (edit, delete, reorder, insert). The
// integration into `audit::log` and the `kepr audit verify` CLI
// command are deliberate follow-ups so each PR stays under the
// 350-LOC ceiling and the chain primitives can be reasoned about
// in isolation.
//
// Concurrency: a single `Mutex<ChainState>` serialises appends
// within the daemon process. The kernel-level `O_APPEND` is belt-
// and-braces in case a future PR adds an alternative writer; the
// in-process Mutex is the contract today (only the daemon writes).
//
// File-format choice: one JSON object per line. Append-friendly
// (no trailing-comma JSON-array headache), grep-friendly for
// post-mortem ops, and serde round-trips cleanly via
// `serde_json::from_str` per line.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 32-byte zero hash, hex-encoded, used as `prev_hash` for the
/// first entry in any chain. Distinct from any real SHA-256 output
/// (the probability of SHA-256 collision against this is negligible),
/// so verifiers can distinguish "genesis" from "tampered prev_hash".
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// On-disk record. One per line, JSON-encoded. The `hash` and
/// `prev_hash` fields are derivable from the rest, but storing them
/// explicitly makes the file self-describing — a verifier can flag
/// "computed hash != stored hash" as a tamper signal without
/// re-deriving from outside state.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ChainEntry {
    pub seq: u64,
    pub timestamp_unix: u64,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    pub uid: u32,
    pub username: String,
    pub result: String,
    pub prev_hash: String,
    pub hash: String,
}

/// Subset of `ChainEntry` that participates in the hash. Excludes
/// `prev_hash` and `hash` themselves (those are the chain
/// metadata). serde-json's struct serialisation preserves field
/// order across Rust versions, so the byte-stream is stable.
#[derive(Serialize)]
struct CanonicalEvent<'a> {
    seq: u64,
    timestamp_unix: u64,
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    uid: u32,
    username: &'a str,
    result: &'a str,
}

/// Live chain handle. `state` holds the in-memory head + next seq.
/// One per audit-log file; the daemon constructs exactly one at
/// startup.
#[derive(Debug)]
pub struct AuditChain {
    path: PathBuf,
    state: Mutex<ChainState>,
}

#[derive(Debug)]
struct ChainState {
    /// Hex-encoded hash of the most recent committed entry. Set to
    /// `ZERO_HASH` for an empty chain. Updated under the Mutex on
    /// every successful `append`.
    last_hash: String,
    /// Next sequence number to issue. Starts at 1 for an empty
    /// chain; advances by 1 per `append`. Persisted implicitly
    /// (every entry carries its `seq`); reloaded on `open`.
    next_seq: u64,
}

/// Summary of a verification pass. `entries` is the count of
/// chain entries successfully validated; `last_hash` is the head
/// (matches the chain's authoritative head if the file is intact).
#[derive(Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub entries: usize,
    pub last_hash: String,
}

impl AuditChain {
    /// Open the chain at `path`. If the file exists, walks it to
    /// recover the in-memory head + next-seq state. If the file
    /// is absent, starts with the genesis state. A malformed or
    /// tampered existing file is a hard error — the daemon
    /// should refuse to start rather than silently begin a fresh
    /// chain on top of corruption.
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let state = match fs::metadata(&path) {
            Ok(_) => {
                // Existing file — verify and recover state from it.
                let report = Self::verify(&path)?;
                ChainState {
                    last_hash: report.last_hash,
                    next_seq: report.entries as u64 + 1,
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ChainState {
                last_hash: ZERO_HASH.to_string(),
                next_seq: 1,
            },
            Err(e) => return Err(format!("audit chain stat: {e}")),
        };
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    /// Append a new event to the chain. Computes the new hash
    /// over (prev_hash || canonical_event_bytes), writes the line,
    /// updates the in-memory head. Lock is held across the file
    /// write so a concurrent `append` from another worker thread
    /// can't interleave hashes.
    pub fn append(
        &self,
        op: &str,
        name: Option<&str>,
        uid: u32,
        username: &str,
        result: &str,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "audit chain mutex poisoned")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let canonical = CanonicalEvent {
            seq: state.next_seq,
            timestamp_unix: now,
            op,
            name,
            uid,
            username,
            result,
        };
        let canonical_bytes =
            serde_json::to_vec(&canonical).map_err(|e| format!("canonicalise event: {e}"))?;
        let new_hash = compute_hash(&state.last_hash, &canonical_bytes)?;

        let entry = ChainEntry {
            seq: state.next_seq,
            timestamp_unix: now,
            op: op.to_string(),
            name: name.map(|s| s.to_string()),
            uid,
            username: username.to_string(),
            result: result.to_string(),
            prev_hash: state.last_hash.clone(),
            hash: new_hash.clone(),
        };
        let mut line =
            serde_json::to_string(&entry).map_err(|e| format!("serialize entry: {e}"))?;
        line.push('\n');

        // Ensure the parent dir exists. The daemon's StateDirectory
        // creates /var/lib/kepr/ at 0700 before this runs in
        // production; the create-on-demand here makes tests usable
        // against a tempdir without pre-creating it.
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| format!("create audit dir: {e}"))?;
            }
        }

        // Open with O_APPEND + 0o640 so a fresh inode lands at
        // group-readable mode (the daemon's own group, not kepr-
        // group). This matches the master.key + cred-versions.json
        // pattern and keeps the file out of `kepr`-group reach.
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(&self.path)
            .map_err(|e| format!("open audit chain: {e}"))?;
        f.write_all(line.as_bytes())
            .map_err(|e| format!("write audit chain: {e}"))?;
        // Update in-memory state ONLY after the disk write
        // succeeds. If the write failed we'd want a retry to
        // re-emit the same seq + prev_hash; advancing in-memory
        // state on a failed write would skip a seq number.
        state.last_hash = new_hash;
        state.next_seq += 1;
        Ok(())
    }

    /// Walk the chain at `path`, verifying each H_n =
    /// SHA-256(H_{n-1} || canonical_event_bytes_n). Returns the
    /// number of validated entries plus the final head; any
    /// tamper (edit, delete, reorder, insert) fails the hash
    /// recomputation OR the prev_hash continuity and surfaces
    /// here with a line number.
    ///
    /// Public so a future `kepr audit verify` CLI command and ops
    /// scripts can call it directly. Cheap to read-only invoke
    /// even on a multi-megabyte chain — a single sequential pass
    /// with one SHA-256 per entry.
    pub fn verify(path: &Path) -> Result<VerifyReport, String> {
        let f = fs::File::open(path).map_err(|e| format!("open chain for verify: {e}"))?;
        let reader = BufReader::new(f);
        let mut entries = 0usize;
        let mut prev_hash = ZERO_HASH.to_string();
        let mut expected_seq = 1u64;
        for (idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| format!("read chain line {}: {e}", idx + 1))?;
            if line.is_empty() {
                continue; // tolerant of stray trailing newline
            }
            let entry: ChainEntry = serde_json::from_str(&line)
                .map_err(|e| format!("parse chain line {}: {e}", idx + 1))?;
            if entry.seq != expected_seq {
                return Err(format!(
                    "chain line {}: seq {} != expected {expected_seq} (reordered or dropped entry)",
                    idx + 1,
                    entry.seq
                ));
            }
            if entry.prev_hash != prev_hash {
                return Err(format!(
                    "chain line {}: prev_hash mismatch (expected {prev_hash}, found {})",
                    idx + 1,
                    entry.prev_hash
                ));
            }
            let canonical = CanonicalEvent {
                seq: entry.seq,
                timestamp_unix: entry.timestamp_unix,
                op: &entry.op,
                name: entry.name.as_deref(),
                uid: entry.uid,
                username: &entry.username,
                result: &entry.result,
            };
            let canonical_bytes = serde_json::to_vec(&canonical)
                .map_err(|e| format!("canonicalise line {}: {e}", idx + 1))?;
            let computed = compute_hash(&prev_hash, &canonical_bytes)?;
            if computed != entry.hash {
                return Err(format!(
                    "chain line {}: hash mismatch — entry has been edited",
                    idx + 1
                ));
            }
            prev_hash = entry.hash;
            entries += 1;
            expected_seq += 1;
        }
        Ok(VerifyReport {
            entries,
            last_hash: prev_hash,
        })
    }
}

fn compute_hash(prev_hash_hex: &str, canonical_bytes: &[u8]) -> Result<String, String> {
    let prev_bytes = hex_decode(prev_hash_hex)?;
    let mut hasher = Sha256::new();
    hasher.update(&prev_bytes);
    hasher.update(canonical_bytes);
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string: {s:?}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex byte: {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_chain() -> (AuditChain, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let chain = AuditChain::open(path).unwrap();
        (chain, dir)
    }

    #[test]
    fn open_on_missing_file_starts_at_genesis() {
        let (chain, _d) = fresh_chain();
        let st = chain.state.lock().unwrap();
        assert_eq!(st.last_hash, ZERO_HASH);
        assert_eq!(st.next_seq, 1);
    }

    #[test]
    fn append_writes_entry_with_zero_prev_hash() {
        let (chain, dir) = fresh_chain();
        chain
            .append("set", Some("FOO"), 1000, "alice", "ok")
            .unwrap();
        let body = fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let entry: ChainEntry = serde_json::from_str(body.trim()).unwrap();
        assert_eq!(entry.seq, 1);
        assert_eq!(entry.prev_hash, ZERO_HASH);
        assert_eq!(entry.op, "set");
        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.hash.len(), 64);
        assert_ne!(entry.hash, ZERO_HASH, "hash must not be all-zero");
    }

    #[test]
    fn second_append_chains_to_first() {
        let (chain, dir) = fresh_chain();
        chain
            .append("set", Some("FOO"), 1000, "alice", "ok")
            .unwrap();
        chain
            .append("get", Some("FOO"), 1000, "alice", "ok")
            .unwrap();
        let body = fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        let e1: ChainEntry = serde_json::from_str(lines[0]).unwrap();
        let e2: ChainEntry = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(e1.seq, 1);
        assert_eq!(e2.seq, 2);
        assert_eq!(e2.prev_hash, e1.hash, "second entry must chain to first");
    }

    #[test]
    fn verify_succeeds_on_a_clean_chain() {
        let (chain, dir) = fresh_chain();
        for op in ["set", "get", "list", "delete"] {
            chain.append(op, Some("X"), 1000, "alice", "ok").unwrap();
        }
        let report = AuditChain::verify(&dir.path().join("audit.log")).unwrap();
        assert_eq!(report.entries, 4);
        assert_ne!(report.last_hash, ZERO_HASH);
    }

    #[test]
    fn verify_detects_edited_entry() {
        let (chain, dir) = fresh_chain();
        chain
            .append("set", Some("FOO"), 1000, "alice", "ok")
            .unwrap();
        chain
            .append("get", Some("FOO"), 1000, "alice", "ok")
            .unwrap();
        let path = dir.path().join("audit.log");
        // Tamper: round-trip the second line via ChainEntry and
        // flip `result` ok → fail. Going through serde keeps the
        // JSON well-formed; the chain's hash check is the thing we
        // want to fail, not the JSON parser.
        let body = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        let mut second: ChainEntry = serde_json::from_str(lines[1]).unwrap();
        second.result = "fail".to_string();
        let edited = format!(
            "{}\n{}\n",
            lines[0],
            serde_json::to_string(&second).unwrap()
        );
        fs::write(&path, edited).unwrap();
        let err = AuditChain::verify(&path).expect_err("tampered hash must fail");
        assert!(
            err.contains("hash mismatch") || err.contains("entry has been edited"),
            "got: {err}"
        );
    }

    #[test]
    fn verify_detects_deleted_entry() {
        let (chain, dir) = fresh_chain();
        chain.append("set", None, 1000, "alice", "ok").unwrap();
        chain.append("get", None, 1000, "alice", "ok").unwrap();
        chain.append("delete", None, 1000, "alice", "ok").unwrap();
        let path = dir.path().join("audit.log");
        let body = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        // Drop the middle line.
        let truncated = format!("{}\n{}\n", lines[0], lines[2]);
        fs::write(&path, truncated).unwrap();
        let err = AuditChain::verify(&path).expect_err("deletion must fail verify");
        assert!(
            err.contains("seq") || err.contains("prev_hash"),
            "deletion surfaces via seq or prev_hash: {err}"
        );
    }

    #[test]
    fn verify_detects_reordered_entries() {
        let (chain, dir) = fresh_chain();
        chain.append("set", None, 1000, "alice", "ok").unwrap();
        chain.append("get", None, 1000, "alice", "ok").unwrap();
        let path = dir.path().join("audit.log");
        let body = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        let swapped = format!("{}\n{}\n", lines[1], lines[0]);
        fs::write(&path, swapped).unwrap();
        let err = AuditChain::verify(&path).expect_err("reorder must fail");
        assert!(
            err.contains("seq") || err.contains("prev_hash"),
            "got: {err}"
        );
    }

    #[test]
    fn verify_detects_fabricated_entry() {
        // Insert a brand-new line with self-consistent contents but
        // invalid hash chain. Even though seq + prev_hash look
        // plausible, the recomputed H_n won't match.
        let (chain, dir) = fresh_chain();
        chain.append("set", None, 1000, "alice", "ok").unwrap();
        let path = dir.path().join("audit.log");
        let body = fs::read_to_string(&path).unwrap();
        // Fake a second entry with seq=2, prev_hash=correct, but
        // a hash chosen by the attacker (here, ZERO_HASH).
        let first: ChainEntry = serde_json::from_str(body.trim()).unwrap();
        let fake = ChainEntry {
            seq: 2,
            timestamp_unix: 0,
            op: "ATTACK".into(),
            name: None,
            uid: 0,
            username: "root".into(),
            result: "ok".into(),
            prev_hash: first.hash.clone(),
            hash: ZERO_HASH.to_string(), // wrong on purpose
        };
        let appended = format!("{body}{}\n", serde_json::to_string(&fake).unwrap());
        fs::write(&path, appended).unwrap();
        let err = AuditChain::verify(&path).expect_err("fabricated hash fails");
        assert!(err.contains("hash mismatch"), "got: {err}");
    }

    #[test]
    fn open_recovers_state_from_existing_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        // First run: append two entries and drop the chain.
        {
            let chain = AuditChain::open(path.clone()).unwrap();
            chain.append("set", None, 1000, "alice", "ok").unwrap();
            chain.append("get", None, 1000, "alice", "ok").unwrap();
        }
        // Second run: open the same file, append a third entry,
        // verify the whole chain.
        {
            let chain = AuditChain::open(path.clone()).unwrap();
            let st = chain.state.lock().unwrap();
            assert_eq!(st.next_seq, 3, "next_seq recovered from disk");
            drop(st);
            chain.append("delete", None, 1000, "alice", "ok").unwrap();
        }
        let report = AuditChain::verify(&path).unwrap();
        assert_eq!(report.entries, 3);
    }

    #[test]
    fn open_refuses_corrupted_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        fs::write(&path, "this is not valid json\n").unwrap();
        let err = AuditChain::open(path).expect_err("bad chain refused");
        assert!(
            err.contains("parse chain") || err.contains("hash"),
            "got: {err}"
        );
    }

    #[test]
    fn append_uses_0640_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (chain, dir) = fresh_chain();
        chain.append("set", None, 1000, "alice", "ok").unwrap();
        let mode = fs::metadata(dir.path().join("audit.log"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "audit chain must be 0o640, got {mode:o}");
    }

    #[test]
    fn hex_encode_decode_round_trip() {
        for bytes in [
            [0u8; 32].to_vec(),
            [0xffu8; 32].to_vec(),
            (0u8..32).collect(),
        ] {
            let s = hex_encode(&bytes);
            assert_eq!(s.len(), 64);
            assert_eq!(hex_decode(&s).unwrap(), bytes);
        }
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_rejects_non_hex_chars() {
        assert!(hex_decode("zz").is_err());
    }
}
