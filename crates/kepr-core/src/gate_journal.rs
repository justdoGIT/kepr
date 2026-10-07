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
}
