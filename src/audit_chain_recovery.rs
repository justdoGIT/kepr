//! Crash recovery for an append-only audit chain.

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
