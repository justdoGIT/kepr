// audit_verify.rs — walking the audit chain (split out of audit_chain.rs).
//
// `verify` checks the whole file; `verify_from` starts at a trusted
// checkpoint (audit_checkpoint.rs) so a start-up only reads what was
// appended since the last one.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::audit_chain::{compute_hash, AuditChain, CanonicalEvent, ChainEntry, ZERO_HASH};

/// Summary of a verification pass. `entries` is the count of
/// chain entries successfully validated; `last_hash` is the head
/// (matches the chain's authoritative head if the file is intact).
#[derive(Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub entries: usize,
    pub last_hash: String,
    /// Bytes of the file the verified entries end at.
    pub end_offset: u64,
}

impl AuditChain {
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
        Self::verify_from(path, None)
    }

    /// [`verify`](Self::verify) from a trusted checkpoint: the entries
    /// before `start.offset` are not re-read.
    pub fn verify_from(
        path: &Path,
        start: Option<&crate::audit_checkpoint::Checkpoint>,
    ) -> Result<VerifyReport, String> {
        use std::io::{Seek, SeekFrom};
        let mut f = fs::File::open(path).map_err(|e| format!("open chain for verify: {e}"))?;
        let (mut entries, mut prev_hash, mut offset) = (0usize, ZERO_HASH.to_string(), 0u64);
        if let Some(c) = start {
            f.seek(SeekFrom::Start(c.offset))
                .map_err(|e| format!("seek chain: {e}"))?;
            (entries, prev_hash, offset) = (c.entries as usize, c.hash.clone(), c.offset);
        }
        let mut reader = BufReader::new(f);
        let mut expected_seq = entries as u64 + 1;
        let mut idx = entries;
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader
                .read_line(&mut line)
                .map_err(|e| format!("read chain line {}: {e}", idx + 1))?;
            if n == 0 {
                break;
            }
            idx += 1;
            offset += n as u64;
            let text = line.trim_end_matches(['\n', '\r']);
            if text.is_empty() {
                continue; // tolerant of stray trailing newline
            }
            let entry: ChainEntry =
                serde_json::from_str(text).map_err(|e| format!("parse chain line {idx}: {e}"))?;
            if entry.seq != expected_seq {
                return Err(format!(
                    "chain line {idx}: seq {} != expected {expected_seq} (reordered or dropped entry)",
                    entry.seq
                ));
            }
            if entry.prev_hash != prev_hash {
                return Err(format!(
                    "chain line {idx}: prev_hash mismatch (expected {prev_hash}, found {})",
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
                .map_err(|e| format!("canonicalise line {idx}: {e}"))?;
            let computed = compute_hash(&prev_hash, &canonical_bytes)?;
            if computed != entry.hash {
                return Err(format!(
                    "chain line {idx}: hash mismatch — entry has been edited"
                ));
            }
            prev_hash = entry.hash;
            entries += 1;
            expected_seq += 1;
        }
        Ok(VerifyReport {
            entries,
            last_hash: prev_hash,
            end_offset: offset,
        })
    }
}
