// daemon_policy/sessions.rs — T9.07: what each gate session was, so the
// usage report can put a harness and a credential on gate-journal lines
// (which name only the route and the host). The daemon writes the record
// when it starts the gate (route → credential, from the StartGate it
// checked); `kepr agent run` names the harness once, right after, before
// the harness starts, and the first name stays. A user's newest
// MAX_SESSIONS records are kept in one 0600 file in the state dir.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use kepr_core::gate_protocol::{resolvable_creds, GateRoute};
use kepr_core::protocol::Response;
use kepr_core::protocol_gatex::valid_session;
use kepr_core::protocol_policy::PolicyResponse;

const MAX_SESSIONS: usize = 1000;
const MAX_HARNESS: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRec {
    pub session: String,
    pub started: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// Route (the journal's `provider`) → credential NAME.
    pub routes: BTreeMap<String, String>,
}

static LOCK: Mutex<()> = Mutex::new(());

fn path(uid: u32) -> PathBuf {
    #[cfg(test)]
    let root = std::env::temp_dir().join(format!("kepr-sessions-tests-{}", std::process::id()));
    #[cfg(not(test))]
    let root = crate::state_dir();
    root.join(format!("agent-sessions-{uid}.json"))
}

pub fn load(uid: u32) -> Vec<SessionRec> {
    std::fs::read(path(uid))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save(uid: u32, recs: &[SessionRec]) -> Result<(), String> {
    let skip = recs.len().saturating_sub(MAX_SESSIONS);
    let bytes = serde_json::to_vec(&recs[skip..]).map_err(|e| e.to_string())?;
    let p = path(uid);
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    crate::atomic_file::write(&p, &bytes, 0o600).map_err(|e| e.to_string())
}

/// A gate for `session` started with `routes` (tunnels carry no credential).
pub fn started(uid: u32, session: &str, routes: &[GateRoute]) {
    let creds = resolvable_creds(routes);
    let rec = SessionRec {
        session: session.to_string(),
        started: crate::expiry::now_unix(),
        harness: None,
        routes: routes
            .iter()
            .filter(|r| creds.contains(&r.cred))
            .map(|r| (r.provider.clone(), r.cred.clone()))
            .collect(),
    };
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut recs = load(uid);
    recs.push(rec);
    let _ = save(uid, &recs); // a lost record only leaves lines unattributed
}

fn valid_harness(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= MAX_HARNESS
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// `PolicyRequest::SessionHarness`: name the harness of one of the
/// caller's sessions, once.
pub fn handle_harness(uid: u32, session: &str, harness: &str) -> Response {
    if !valid_session(session) {
        return Response::fail("SESSION is a 16-character session id");
    }
    if !valid_harness(harness) {
        return Response::fail("HARNESS: up to 64 letters, digits, '.', '_' or '-'");
    }
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut recs = load(uid);
    let Some(rec) = recs.iter_mut().rev().find(|r| r.session == session) else {
        return Response::fail("no such agent session");
    };
    if rec.harness.is_some() {
        return Response::fail("this session's harness is already named");
    }
    rec.harness = Some(harness.to_string());
    match save(uid, &recs) {
        Ok(()) => Response::Policy(PolicyResponse::PolicyDone {
            message: format!("session {session}: {harness}"),
        }),
        Err(_) => Response::fail("could not save the session record"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "0123456789abcdef";

    fn route(provider: &str, cred: &str) -> GateRoute {
        GateRoute {
            provider: provider.into(),
            cred: cred.into(),
            slot: 0,
            target: None,
        }
    }

    #[test]
    fn a_session_is_recorded_and_named_once() {
        let uid = 8_201;
        started(uid, S, &[route("anthropic", "ANTHROPIC_API_KEY")]);
        let rec = load(uid).pop().unwrap();
        assert_eq!(rec.routes["anthropic"], "ANTHROPIC_API_KEY");
        assert_eq!(rec.harness, None);
        assert!(matches!(
            handle_harness(uid, S, "claude"),
            Response::Policy(_)
        ));
        assert_eq!(load(uid)[0].harness.as_deref(), Some("claude"));
        // The first name stays; other users' and unknown sessions fail.
        assert!(matches!(
            handle_harness(uid, S, "evil"),
            Response::Err { .. }
        ));
        assert!(matches!(
            handle_harness(8_202, S, "x"),
            Response::Err { .. }
        ));
        assert!(matches!(
            handle_harness(uid, "nope", "x"),
            Response::Err { .. }
        ));
        assert!(matches!(
            handle_harness(uid, S, "a b"),
            Response::Err { .. }
        ));
        let _ = std::fs::remove_file(path(uid));
    }

    #[test]
    fn only_the_newest_sessions_are_kept() {
        let uid = 8_203;
        let recs: Vec<SessionRec> = (0..MAX_SESSIONS + 5)
            .map(|i| SessionRec {
                session: format!("{i:016x}"),
                ..Default::default()
            })
            .collect();
        save(uid, &recs).unwrap();
        let kept = load(uid);
        assert_eq!(kept.len(), MAX_SESSIONS);
        assert_eq!(kept[0].session, format!("{:016x}", 5));
        let _ = std::fs::remove_file(path(uid));
    }
}
