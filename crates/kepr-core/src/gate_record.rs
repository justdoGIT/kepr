//! Agent session recording (T7.09): what a gate hands the daemon to keep,
//! over its private channel (`GateRequest::Record`). A chunk is a piece
//! of what the agent sent or received on one connection: placeholders as
//! the agent wrote them, never a value the gate substituted. The daemon
//! stores the chunks encrypted; `kepr agent replay` reads them back.

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Largest body piece in one chunk; longer writes are split.
pub const MAX_PIECE: usize = 8 * 1024;
/// Budget (estimated JSON bytes) of one `GateRecord`: it must fit one
/// frame on the daemon channel, and one replay page on the socket.
pub const MAX_BATCH: usize = 40 * 1024;

/// Who sent a chunk's bytes.
pub const FROM_AGENT: &str = "i";
pub const TO_AGENT: &str = "o";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecChunk {
    /// Milliseconds since the session started.
    pub t: u64,
    /// The connection (database, tunnel) or request (HTTP), numbered
    /// per session.
    pub conn: u64,
    /// The route key: `anthropic`, `db:NAME`, `tcp:NAME`.
    pub route: String,
    /// `http`, `postgres`, `mysql`, `redis` or `tcp`.
    pub kind: String,
    /// `FROM_AGENT` or `TO_AGENT`.
    pub dir: String,
    /// The bytes, base64.
    pub data: String,
}

impl RecChunk {
    pub fn new(t: u64, conn: u64, route: &str, kind: &str, dir: &str, bytes: &[u8]) -> Self {
        RecChunk {
            t,
            conn,
            route: route.to_string(),
            kind: kind.to_string(),
            dir: dir.to_string(),
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    /// The bytes (empty when the data is not base64).
    pub fn bytes(&self) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.data)
            .unwrap_or_default()
    }

    /// Estimated size in a JSON batch.
    pub fn cost(&self) -> usize {
        self.data.len() + self.route.len() + self.kind.len() + 64
    }
}

/// One batch from a gate.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRecord {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<RecChunk>,
    /// Body bytes the gate could not keep (its buffer was full).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dropped: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl GateRecord {
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty() && self.dropped == 0
    }

    /// Split `chunks` into batches within `MAX_BATCH`; `dropped` rides
    /// on the first.
    pub fn batches(chunks: Vec<RecChunk>, dropped: u64) -> Vec<GateRecord> {
        let mut out = vec![GateRecord {
            chunks: Vec::new(),
            dropped,
        }];
        let mut size = 0;
        for c in chunks {
            let cost = c.cost();
            if size + cost > MAX_BATCH && !out.last().is_some_and(|b| b.chunks.is_empty()) {
                out.push(GateRecord::default());
                size = 0;
            }
            size += cost;
            out.last_mut().expect("never empty").chunks.push(c);
        }
        out.retain(|b| !b.is_empty());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_round_trip_and_batches_fit_a_frame() {
        let c = RecChunk::new(5, 1, "db:APP", "postgres", FROM_AGENT, b"SELECT 1");
        assert_eq!(c.bytes(), b"SELECT 1");
        let piece = vec![b'x'; MAX_PIECE];
        let chunks: Vec<_> = (0..40)
            .map(|i| RecChunk::new(i, 1, "anthropic", "http", TO_AGENT, &piece))
            .collect();
        let batches = GateRecord::batches(chunks.clone(), 7);
        assert!(batches.len() > 1);
        assert_eq!(batches[0].dropped, 7);
        assert!(batches[1..].iter().all(|b| b.dropped == 0));
        let back: Vec<RecChunk> = batches.iter().flat_map(|b| b.chunks.clone()).collect();
        assert_eq!(back, chunks);
        for b in &batches {
            let json = serde_json::to_vec(b).unwrap();
            assert!(
                json.len() < crate::protocol::MAX_MSG_BYTES - 1024,
                "{}",
                json.len()
            );
        }
        assert!(GateRecord::batches(Vec::new(), 0).is_empty());
        assert_eq!(GateRecord::batches(Vec::new(), 3).len(), 1);
    }
}
