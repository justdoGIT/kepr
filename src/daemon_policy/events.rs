// daemon_policy/events.rs — the audit chain as the event source for
// access reports (T6.12): every entry, parsed; unreadable lines skipped.

use std::io::{BufRead, BufReader};

use crate::audit_chain::ChainEntry;

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
