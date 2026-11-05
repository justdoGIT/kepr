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

#[cfg(test)]
mod tests {
    use crate::audit_chain::AuditChain;
    use std::fs::OpenOptions;
    use std::io::Write;

    #[test]
    fn open_recovers_nul_padded_final_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        {
            let chain = AuditChain::open(path.clone()).unwrap();
            chain.append("set", None, 1000, "alice", "ok").unwrap();
        }

        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0; 275]).unwrap();
        drop(file);

        let chain = AuditChain::open(path.clone()).expect("NUL-padded tail is recoverable");
        chain.append("get", None, 1000, "alice", "ok").unwrap();
        drop(chain);
        assert_eq!(AuditChain::verify(&path).unwrap().entries, 2);
    }
}
