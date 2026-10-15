// daemon_policy/usage.rs — T9.07 `kepr usage --report`: the governance
// view of the caller's agent traffic. From the gate journal the daemon
// keeps (daemon_gatex/logs.rs) and the session records (sessions.rs):
// requests, refusals and provider-reported tokens per harness ×
// credential × host; and, from the sealed credentials' bindings, every
// bound host no request reached in `unused_days` (over-scoped bindings).
// The CLI prices the tokens. Metadata only: no values, no paths.

use std::collections::{BTreeMap, HashMap};

use kepr_core::gate_journal::JournalEntry;
use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{PolicyResponse, UnusedBinding, UsageRow};

use super::sessions::{self, SessionRec};
use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry;

/// Rows per reply (each well under 300 bytes of JSON).
const MAX_ROWS: usize = 150;
const MAX_UNUSED: usize = 50;

/// `host` without a `:port` suffix.
fn host_only(h: &str) -> &str {
    match h.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => h,
    }
}

/// The (harness, credential) of one journal line.
fn owner(e: &JournalEntry, by_session: &HashMap<&str, &SessionRec>) -> (String, String) {
    let rec = by_session.get(e.session.as_str());
    let harness = rec
        .and_then(|r| r.harness.clone())
        .unwrap_or_else(|| "unknown".into());
    let cred = rec
        .and_then(|r| r.routes.get(&e.provider).cloned())
        .or_else(|| e.provider.strip_prefix("db:").map(str::to_string))
        .unwrap_or_else(|| "-".into());
    (harness, cred)
}

fn index(sessions: &[SessionRec]) -> HashMap<&str, &SessionRec> {
    sessions.iter().map(|s| (s.session.as_str(), s)).collect()
}

/// Lines since `since`, grouped and sorted by requests (most first).
pub fn rows(entries: &[JournalEntry], sessions: &[SessionRec], since: u64) -> Vec<UsageRow> {
    let by_session = index(sessions);
    let mut groups: BTreeMap<(String, String, String), UsageRow> = BTreeMap::new();
    for e in entries.iter().filter(|e| e.ts >= since) {
        let (harness, cred) = owner(e, &by_session);
        let host = e.host.clone();
        let row = groups
            .entry((harness.clone(), cred.clone(), host.clone()))
            .or_insert_with(|| UsageRow {
                harness,
                cred,
                host,
                ..Default::default()
            });
        row.requests += 1;
        row.blocked += u64::from(e.blocked.is_some());
        row.tokens = row.tokens.saturating_add(e.tokens.unwrap_or(0));
    }
    let mut out: Vec<UsageRow> = groups.into_values().collect();
    out.sort_by_key(|r| std::cmp::Reverse(r.requests));
    out
}

/// Each `(credential, host)` binding no forwarded request reached since
/// `since`, with its last use in the journal (unix seconds).
pub fn unused(
    entries: &[JournalEntry],
    sessions: &[SessionRec],
    bound: &[(String, String)],
    since: u64,
) -> Vec<(String, String, Option<u64>)> {
    let by_session = index(sessions);
    let mut last: HashMap<(String, String), u64> = HashMap::new();
    for e in entries.iter().filter(|e| e.blocked.is_none()) {
        let (_, cred) = owner(e, &by_session);
        let key = (cred, host_only(&e.host).to_ascii_lowercase());
        let t = last.entry(key).or_default();
        *t = (*t).max(e.ts);
    }
    bound
        .iter()
        .filter_map(|(cred, host)| {
            let seen = last
                .get(&(cred.clone(), host.to_ascii_lowercase()))
                .copied();
            (seen.is_none_or(|t| t < since)).then(|| (cred.clone(), host.clone(), seen))
        })
        .collect()
}

/// The caller's sealed credentials' bound hosts.
fn bound_hosts(uid: u32) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, path) in crate::daemon_cache::list_for_uid(uid) {
        let Some(Ok(meta)) = expiry::read_meta(&expiry::meta_path_for(&path)) else {
            continue;
        };
        if meta.sealed != Some(true) {
            continue;
        }
        for b in meta.bindings.iter().flatten() {
            out.push((name.clone(), b.host.clone()));
        }
    }
    out
}

pub fn handle_report(uid: u32, username: &str, days: Option<u32>, unused_days: u32) -> Response {
    let now = expiry::now_unix();
    let ago = |d: u32| now.saturating_sub(u64::from(d) * 86_400);
    let since = days.map_or(0, ago);
    let entries = crate::daemon_gatex::logs::all_entries(uid);
    let sessions = sessions::load(uid);
    let mut rows = rows(&entries, &sessions, since);
    let truncated = rows.len() > MAX_ROWS;
    rows.truncate(MAX_ROWS);
    let unused = unused(&entries, &sessions, &bound_hosts(uid), ago(unused_days))
        .into_iter()
        .take(MAX_UNUSED)
        .map(|(cred, host, last)| UnusedBinding {
            cred,
            host,
            last_used: last.map(expiry::format_expires_at),
        })
        .collect();
    audit::log(&AuditEvent {
        op: "usage-report",
        name: None,
        uid,
        username,
        result: AuditResult::Ok,
    });
    Response::Policy(PolicyResponse::UsageReportOk {
        since: (since > 0).then(|| expiry::format_expires_at(since)),
        rows,
        unused,
        unused_days,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0123456789abcdef";
    const B: &str = "fedcba9876543210";

    fn line(ts: u64, session: &str, provider: &str, host: &str, tokens: u64) -> JournalEntry {
        JournalEntry {
            ts,
            session: session.into(),
            provider: provider.into(),
            host: host.into(),
            method: "POST".into(),
            path: "/v1/x".into(),
            status: 200,
            tokens: (tokens > 0).then_some(tokens),
            ..Default::default()
        }
    }

    fn sessions() -> Vec<SessionRec> {
        let rec = |s: &str, h: Option<&str>, routes: &[(&str, &str)]| SessionRec {
            session: s.into(),
            harness: h.map(str::to_string),
            routes: routes
                .iter()
                .map(|(p, c)| (p.to_string(), c.to_string()))
                .collect(),
            ..Default::default()
        };
        vec![
            rec(A, Some("claude"), &[("anthropic", "ANTHROPIC_API_KEY")]),
            rec(B, Some("aider"), &[("openai", "OPENAI_API_KEY")]),
        ]
    }

    /// A fixture journal: two harnesses, a database login, a tunnel, a
    /// refused request and a line from a session without a record.
    fn journal() -> Vec<JournalEntry> {
        let mut blocked = line(500, A, "anthropic", "api.anthropic.com", 0);
        blocked.blocked = Some("dlp".into());
        vec![
            line(100, A, "anthropic", "api.anthropic.com", 1_200),
            line(200, A, "anthropic", "api.anthropic.com", 800),
            blocked,
            line(300, B, "openai", "api.openai.com", 50),
            line(400, B, "db:APP_DB", "db.internal:5432", 0),
            line(450, B, "egress", "example.com:443", 0),
            line(460, "aaaaaaaaaaaaaaaa", "anthropic", "api.anthropic.com", 7),
            line(10, A, "anthropic", "api.anthropic.com", 99_999),
        ]
    }

    #[test]
    fn a_fixture_journal_gives_the_expected_table() {
        let got: Vec<(String, String, String, u64, u64, u64)> = rows(&journal(), &sessions(), 50)
            .into_iter()
            .map(|r| (r.harness, r.cred, r.host, r.requests, r.blocked, r.tokens))
            .collect();
        let row = |h: &str, c: &str, host: &str, n, b, t| {
            (h.to_string(), c.to_string(), host.to_string(), n, b, t)
        };
        assert_eq!(
            got,
            vec![
                row(
                    "claude",
                    "ANTHROPIC_API_KEY",
                    "api.anthropic.com",
                    3,
                    1,
                    2_000
                ),
                row("aider", "-", "example.com:443", 1, 0, 0),
                row("aider", "APP_DB", "db.internal:5432", 1, 0, 0),
                row("aider", "OPENAI_API_KEY", "api.openai.com", 1, 0, 50),
                row("unknown", "-", "api.anthropic.com", 1, 0, 7),
            ]
        );
    }

    #[test]
    fn an_unused_binding_is_flagged() {
        let bound = [
            (
                "ANTHROPIC_API_KEY".to_string(),
                "api.anthropic.com".to_string(),
            ),
            ("OPENAI_API_KEY".to_string(), "api.openai.com".to_string()),
            (
                "OPENAI_API_KEY".to_string(),
                "uploads.openai.com".to_string(),
            ),
            ("APP_DB".to_string(), "DB.internal".to_string()),
        ];
        let got = unused(&journal(), &sessions(), &bound, 250);
        assert_eq!(
            got,
            vec![
                ("ANTHROPIC_API_KEY".into(), "api.anthropic.com".into(), Some(200)),
                ("OPENAI_API_KEY".into(), "uploads.openai.com".into(), None),
            ],
            "anthropic's last forwarded use (200) is before the window; the DLP refusal at 500 is not a use"
        );
        assert_eq!(host_only("db.internal:5432"), "db.internal");
        assert_eq!(host_only("api.x.ai"), "api.x.ai");
    }
}
