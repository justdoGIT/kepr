// protocol_gatex.rs — wire types of the `gate` ticket batch (P7 PAM-lite,
// P11.22): agent session recordings. Carried by `Request::Gatex` /
// `Response::Gatex` (untagged, after every tagged variant), so the
// command names here must not collide with any other `cmd` / `kind`.

use crate::gate_journal::JournalEntry;
use crate::gate_record::RecChunk;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum GatexRequest {
    /// T7.09: the caller's recorded agent sessions.
    AgentRecordings,
    /// T7.09: one stored batch of a recording: frame `frame`, found at
    /// byte `offset` of the file (0: search from the start). Pass back
    /// the `next` / `offset` of the previous reply to read on.
    AgentReplay {
        session: String,
        #[serde(default)]
        frame: u64,
        #[serde(default)]
        offset: u64,
    },
    /// T11.22: the caller's gate request journal (`kepr agent logs`),
    /// only `session`'s entries when given. Read on from `from`; without
    /// it, from the start, or from the last `last` entries.
    AgentLogs {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from: Option<LogCursor>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last: Option<u32>,
    },
}

/// Where a `kepr agent logs` reader is: journal file generation and byte
/// offset in it. `Default` is the start of the journal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogCursor {
    pub gen: u64,
    pub offset: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GatexResponse {
    AgentRecordingsOk {
        sessions: Vec<RecordingInfo>,
    },
    AgentReplayOk {
        session: String,
        /// When the session started, `YYYY-MM-DD HH:MM` UTC.
        #[serde(default)]
        started: String,
        chunks: Vec<RecChunk>,
        /// Bytes the gate could not record in this batch.
        #[serde(default)]
        dropped: u64,
        /// The next frame to ask for; `None` at the end.
        next: Option<u64>,
        /// Where the next frame starts.
        #[serde(default)]
        offset: u64,
    },
    AgentLogsOk {
        entries: Vec<JournalEntry>,
        /// Ask from here for what comes next.
        next: LogCursor,
        /// More is there already (the reply was full): ask again now.
        #[serde(default)]
        more: bool,
    },
}

impl From<GatexResponse> for crate::protocol::Response {
    fn from(r: GatexResponse) -> Self {
        crate::protocol::Response::Gatex(r)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingInfo {
    pub session: String,
    pub started_unix: u64,
    /// `started_unix` as `YYYY-MM-DD HH:MM` UTC.
    #[serde(default)]
    pub started: String,
    /// Size on disk (encrypted).
    pub bytes: u64,
}

/// A session id as the gate makes them: 16 lowercase hex chars. Also
/// the only names the daemon turns into recording paths.
pub fn valid_session(s: &str) -> bool {
    s.len() == 16
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    #[test]
    fn requests_and_responses_survive_json_through_the_outer_enums() {
        let reqs = [
            GatexRequest::AgentRecordings,
            GatexRequest::AgentReplay {
                session: "0123456789abcdef".into(),
                frame: 3,
                offset: 1234,
            },
            GatexRequest::AgentLogs {
                session: Some("0123456789abcdef".into()),
                from: Some(LogCursor { gen: 2, offset: 9 }),
                last: Some(100),
            },
            GatexRequest::AgentLogs {
                session: None,
                from: None,
                last: None,
            },
        ];
        for r in reqs {
            let json = serde_json::to_string(&Request::Gatex(r)).unwrap();
            let back: Request = serde_json::from_str(&json).unwrap();
            assert!(matches!(back, Request::Gatex(_)), "{json}");
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
        }
        let resps = [
            GatexResponse::AgentRecordingsOk {
                sessions: vec![RecordingInfo {
                    session: "0123456789abcdef".into(),
                    started_unix: 1,
                    started: "1970-01-01 00:00".into(),
                    bytes: 2,
                }],
            },
            GatexResponse::AgentReplayOk {
                session: "0123456789abcdef".into(),
                started: "1970-01-01 00:00".into(),
                chunks: vec![RecChunk::new(1, 2, "db:A", "postgres", "i", b"Q")],
                dropped: 0,
                next: Some(1),
                offset: 99,
            },
            GatexResponse::AgentLogsOk {
                entries: vec![JournalEntry {
                    ts: 1,
                    session: "0123456789abcdef".into(),
                    provider: "anthropic".into(),
                    host: "api.anthropic.com".into(),
                    method: "POST".into(),
                    path: "/v1/messages".into(),
                    status: 403,
                    bytes_out: 2,
                    ms: 3,
                    blocked: Some("dlp".into()),
                }],
                next: LogCursor {
                    gen: 1,
                    offset: 200,
                },
                more: true,
            },
            GatexResponse::AgentLogsOk {
                entries: vec![],
                next: LogCursor::default(),
                more: false,
            },
        ];
        for r in resps {
            let json = serde_json::to_string(&Response::Gatex(r)).unwrap();
            let back: Response = serde_json::from_str(&json).unwrap();
            assert!(matches!(back, Response::Gatex(_)), "{json}");
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
        }
        let ping: Request = serde_json::from_str(r#"{"cmd":"ping"}"#).unwrap();
        assert!(matches!(ping, Request::Ping));
    }

    #[test]
    fn session_ids() {
        assert!(valid_session("0123456789abcdef"));
        for bad in [
            "",
            "0123456789ABCDEF",
            "../../etc/passwd",
            "0123456789abcde",
        ] {
            assert!(!valid_session(bad), "{bad}");
        }
    }
}
