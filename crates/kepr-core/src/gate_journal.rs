//! The gate's request journal (T1.11, T11.22): one entry per proxied
//! request or database / tunnel connection. Metadata only: never headers,
//! query strings or bodies, and the path as the agent sent it, reduced to
//! a template, so a value the gate substituted can never appear in it.
//!
//! The gate prints each entry on stderr and hands them to the daemon over
//! its private channel in batches; the daemon keeps them per user for
//! `kepr agent logs`. Both ends run `sanitized`, so a line from a
//! misbehaving gate is still bounded and printable.

use serde::{Deserialize, Serialize};

/// Entries per `GateRequest::Journal` batch. A sanitized entry is at most
/// ~1 KiB of JSON, so a batch fits one channel frame.
pub const MAX_BATCH: usize = 40;

const MAX_PATH: usize = 512;
const MAX_HOST: usize = 255;
const MAX_PROVIDER: usize = 64;
const MAX_METHOD: usize = 16;
const MAX_BLOCKED: usize = 32;
/// A pre-execution authorization decision. The daemon persists this record
/// before it acknowledges the gate, so a consequential call has a durable
/// intent or does not run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub session: String,
    pub intent_id: String,
    pub actor_ref: String,
    pub tenant: String,
    pub policy_version: String,
    pub sensitivity: String,
    pub destination: String,
    pub action: String,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
}

impl DecisionRecord {
    /// Bound metadata before it crosses the private channel or reaches disk.
    pub fn sanitized(self) -> Self {
        Self {
            session: bounded(&self.session, 16),
            intent_id: bounded(&self.intent_id, 128),
            actor_ref: bounded(&self.actor_ref, 128),
            tenant: bounded(&self.tenant, 128),
            policy_version: bounded(&self.policy_version, 64),
            sensitivity: bounded(&self.sensitivity, 32),
            destination: bounded(&self.destination, MAX_HOST),
            action: bounded(&self.action, 32),
            decision: bounded(&self.decision, 32),
            approval_ref: self.approval_ref.map(|v| bounded(&v, 128)),
            expiry: self.expiry,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultOutcome {
    Ok,
    Err,
    Unknown,
}

/// The post-execution outcome paired with a `DecisionRecord`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultRecord {
    pub intent_id: String,
    pub outcome: ResultOutcome,
    pub digest: String,
}

impl ResultRecord {
    pub fn sanitized(self) -> Self {
        Self {
            intent_id: bounded(&self.intent_id, 128),
            outcome: self.outcome,
            digest: bounded(&self.digest, 128),
        }
    }
}

fn digest_parts(parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"kepr-gate-journal-v1\0");
    for part in parts {
        h.update(&(part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().to_hex().to_string()
}

/// Stable digest of canonical tool arguments and their destination.
pub fn canonical_args_digest(tool: &str, destination: &str, action: &str, args: &[u8]) -> String {
    digest_parts(&[
        tool.as_bytes(),
        destination.as_bytes(),
        action.as_bytes(),
        args,
    ])
}

/// Stable intent identifier for one session/tool/argument tuple.
pub fn intent_id(session: &str, tool: &str, canonical_args_digest: &str, nonce: &str) -> String {
    digest_parts(&[
        session.as_bytes(),
        tool.as_bytes(),
        canonical_args_digest.as_bytes(),
        nonce.as_bytes(),
    ])
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Unix seconds.
    pub ts: u64,
    pub session: String,
    /// Route: provider name, `db:NAME`, `tcp:NAME` or `egress`.
    pub provider: String,
    /// Upstream host (`host:port` for database routes and CONNECTs).
    #[serde(default)]
    pub host: String,
    pub method: String,
    /// Path template (see `template_path`).
    pub path: String,
    pub status: u16,
    /// Request body bytes the agent sent.
    pub bytes_out: u64,
    pub ms: u64,
    /// Why the gate refused it (`dlp`, `limit`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    /// T9.07: tokens the provider reported in the response's `usage`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u64>,
}

/// A path as a template: no query or fragment, and every segment that
/// identifies one object (a number, UUID, hex digest or random-looking
/// token) replaced by `{id}`; a key-shaped segment by `{redacted}`.
pub fn template_path(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let out = path
        .split('/')
        .map(|seg| {
            if crate::leak::looks_like_key(seg.as_bytes()) {
                "{redacted}"
            } else if is_identifier(seg) {
                "{id}"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    bounded(&out, MAX_PATH)
}

/// One object's id rather than part of the route: all digits, a UUID, a
/// hex digest, or a long random-looking token (letters of both cases and
/// digits, e.g. `msg_01XFDUDYJgAACzvnptvVoYEL`). Model names such as
/// `gpt-4o-mini-2024-07-18` are kept.
fn is_identifier(seg: &str) -> bool {
    let b = seg.as_bytes();
    let all = |f: fn(&u8) -> bool| !b.is_empty() && b.iter().all(f);
    let any = |f: fn(&u8) -> bool| b.iter().any(f);
    let uuid = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        });
    let token = b.len() >= 20
        && all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
        && any(u8::is_ascii_uppercase)
        && any(u8::is_ascii_lowercase)
        && any(u8::is_ascii_digit);
    all(u8::is_ascii_digit) || uuid || (b.len() >= 16 && all(u8::is_ascii_hexdigit)) || token
}

/// At most `max` chars, control characters shown as `?`.
fn bounded(s: &str, max: usize) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(max)
        .collect()
}

impl JournalEntry {
    /// Bounded, printable fields; `path` reduced to its template.
    pub fn sanitized(self) -> Self {
        JournalEntry {
            session: bounded(&self.session, 16),
            provider: bounded(&self.provider, MAX_PROVIDER),
            host: bounded(&self.host, MAX_HOST),
            method: bounded(&self.method, MAX_METHOD),
            path: template_path(&self.path),
            blocked: self.blocked.map(|b| bounded(&b, MAX_BLOCKED)),
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_keep_the_route_and_drop_identifiers() {
        let cases = [
            ("/v1/messages", "/v1/messages"),
            ("/v1/x?key=secret#frag", "/v1/x"),
            (
                "/repos/acme/app/issues/42/comments",
                "/repos/acme/app/issues/{id}/comments",
            ),
            (
                "/v1/files/3f2b8c1e-9d4a-4f6b-8a2e-1c3d5e7f9a0b",
                "/v1/files/{id}",
            ),
            (
                "/repos/a/b/commits/9fceb02d0ae598e95dc970b74767f19372d61af8",
                "/repos/a/b/commits/{id}",
            ),
            (
                "/v1/messages/msg_01XFDUDYJgAACzvnptvVoYEL",
                "/v1/messages/{id}",
            ),
            (
                "/v1beta/models/gemini-1.5-pro:generateContent",
                "/v1beta/models/gemini-1.5-pro:generateContent",
            ),
            (
                "/v1/models/gpt-4o-mini-2024-07-18",
                "/v1/models/gpt-4o-mini-2024-07-18",
            ),
            ("", ""),
            ("/", "/"),
        ];
        for (input, want) in cases {
            assert_eq!(template_path(input), want, "{input}");
        }
    }

    #[test]
    fn key_shaped_segments_are_redacted() {
        let key = format!("sk-ant-api03-{}", "a".repeat(93));
        let t = template_path(&format!("/bot/{key}/send"));
        assert_eq!(t, "/bot/{redacted}/send");
        assert!(!t.contains("sk-ant"));
    }

    #[test]
    fn sanitized_bounds_and_cleans_every_field() {
        let e = JournalEntry {
            ts: 1,
            session: "0123456789abcdef".into(),
            provider: "p\u{1b}[31m".repeat(40),
            host: "h".repeat(300),
            method: "POST\nX".into(),
            path: format!("/a/{}?q=1", "b".repeat(600)),
            status: 200,
            bytes_out: 3,
            ms: 4,
            blocked: Some("dlp\r".repeat(20)),
            tokens: None,
        }
        .sanitized();
        assert!(e.provider.chars().count() <= MAX_PROVIDER);
        assert!(e.host.chars().count() <= MAX_HOST);
        assert!(e.method.chars().count() <= MAX_METHOD);
        assert!(e.path.chars().count() <= MAX_PATH);
        assert!(e.blocked.as_ref().unwrap().chars().count() <= MAX_BLOCKED);
        for s in [
            &e.provider,
            &e.host,
            &e.method,
            &e.path,
            e.blocked.as_ref().unwrap(),
        ] {
            assert!(!s.chars().any(char::is_control), "{s:?}");
        }
        assert!(!e.path.contains('?'), "query dropped before bounding");
        let line = serde_json::to_string(&e).unwrap();
        assert!(line.len() < 1200, "{}", line.len());
    }

    #[test]
    fn a_worst_case_batch_fits_one_frame() {
        let e = JournalEntry {
            provider: "p".repeat(999),
            host: "h".repeat(999),
            method: "m".repeat(99),
            path: "/".repeat(9999),
            blocked: Some("b".repeat(99)),
            session: "s".repeat(99),
            ts: u64::MAX,
            bytes_out: u64::MAX,
            ms: u64::MAX,
            status: u16::MAX,
            tokens: Some(u64::MAX),
        }
        .sanitized();
        let batch = vec![e; MAX_BATCH];
        let json = serde_json::to_vec(&batch).unwrap();
        assert!(
            json.len() + 200 < crate::protocol::MAX_MSG_BYTES,
            "{}",
            json.len()
        );
    }

    #[test]
    fn old_lines_without_host_still_parse() {
        let line = r#"{"ts":1,"session":"s","provider":"anthropic","method":"POST","path":"/v1/messages","status":200,"bytes_out":5,"ms":1}"#;
        let e: JournalEntry = serde_json::from_str(line).unwrap();
        assert_eq!(e.host, "");
        assert_eq!(e.blocked, None);
    }
    #[test]
    fn intent_ids_are_stable_for_same_arguments_and_change_with_arguments() {
        let one = canonical_args_digest(
            "db_query",
            "db.example.test",
            "read",
            br#"{"sql":"select 1"}"#,
        );
        let two = canonical_args_digest(
            "db_query",
            "db.example.test",
            "read",
            br#"{"sql":"select 2"}"#,
        );
        assert_eq!(
            intent_id("session", "db_query", &one, "nonce"),
            intent_id("session", "db_query", &one, "nonce")
        );
        assert_ne!(
            intent_id("session", "db_query", &one, "nonce"),
            intent_id("session", "db_query", &two, "nonce")
        );
    }
}
