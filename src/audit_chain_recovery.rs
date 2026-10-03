//! Crash recovery for an append-only audit chain.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Repair only a final record that was cut off before its newline.
///
/// A newline-terminated malformed line remains a hard failure. That
/// distinction preserves tamper detection while allowing a daemon to
/// recover from a process dying during `write_all`.
pub(super) fn repair_incomplete_tail(path: &Path) -> Result<bool, String> {
    let bytes = fs::read(path).map_err(|e| format!("read audit chain: {e}"))?;
    if bytes.is_empty() || bytes.ends_with(b"\n") {
        return Ok(false);
    }
    let Some(tail_start) = bytes.iter().rposition(|byte| *byte == b'\n').map(|i| i + 1) else {
        return Ok(false);
    };
    let tail = &bytes[tail_start..];
    if serde_json::from_slice::<serde_json::Value>(tail).is_ok() {
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| format!("open audit chain for recovery: {e}"))?;
        file.write_all(b"\n")
            .map_err(|e| format!("complete audit chain record: {e}"))?;
    } else {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| format!("open audit chain for truncation: {e}"))?;
        file.set_len(tail_start as u64)
            .map_err(|e| format!("truncate audit chain: {e}"))?;
    }
    Ok(true)
}
