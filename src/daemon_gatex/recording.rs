// daemon_gatex/recording.rs — agent session recordings, daemon side
// (T7.09): the per-gate recorder fed over the gate's private channel,
// and `kepr agent replay`'s requests. The file format is recfile.rs.
//
// A gate only gets to store anything when its session was started with
// `--record`; the recording file is created at its first batch, under
// the caller's uid (from SO_PEERCRED at StartGate), and only that uid's
// directory is ever listed or read back.

use std::path::Path;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_gatex::recfile::{self, Page, Writer};
use kepr_core::gate_protocol::GateResponse;
use kepr_core::gate_record::GateRecord;
use kepr_core::protocol::Response;
use kepr_core::protocol_gatex::{valid_session, GatexResponse};

/// One gate session's recording state, held by the daemon's channel
/// thread for that gate. The file is created at the first batch.
pub struct Recorder {
    uid: u32,
    session: String,
    started_unix: u64,
    on: bool,
    writer: Option<Writer>,
}

impl Recorder {
    pub fn new(uid: u32, session: &str, on: bool) -> Self {
        Recorder {
            uid,
            session: session.to_string(),
            started_unix: crate::expiry::now_unix(),
            on,
            writer: None,
        }
    }

    /// The session this gate was started as.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Store one batch; the gate only ever sees a generic failure.
    pub fn handle(&mut self, id: u64, batch: GateRecord) -> GateResponse {
        match self.store(&crate::state_dir(), batch) {
            Ok(()) => GateResponse::Recorded { id },
            Err(_) => GateResponse::Err {
                id,
                error: "recording unavailable".into(),
            },
        }
    }

    fn store(&mut self, root: &Path, batch: GateRecord) -> Result<(), String> {
        if !self.on {
            return Err("this session does not record".into());
        }
        if self.writer.is_none() {
            let kek = crate::crypto::snapshot_key()?;
            let w = Writer::create(root, self.uid, &self.session, self.started_unix, &kek);
            log("agent-record", Some(&self.session), self.uid, &w);
            self.writer = Some(w?);
        }
        let w = self.writer.as_mut().expect("just set");
        w.append(&batch)
    }
}

fn log<T>(op: &str, session: Option<&str>, uid: u32, result: &Result<T, String>) {
    audit::log(&AuditEvent {
        op,
        name: session,
        uid,
        username: &audit::username_for_uid(uid),
        result: match result {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}

/// `kepr agent replay` with no session: the caller's recordings.
pub fn handle_list(uid: u32) -> Response {
    let sessions = recfile::list(&crate::state_dir(), uid);
    log::<()>("agent-recordings", None, uid, &Ok(()));
    GatexResponse::AgentRecordingsOk { sessions }.into()
}

/// One page of the caller's recording `session`. Audited once per
/// replay (at its first frame), not once per page.
pub fn handle_replay(uid: u32, session: &str, at: (u64, u64)) -> Response {
    let result = replay(&crate::state_dir(), uid, session, at);
    if at.0 == 0 {
        let name = valid_session(session).then_some(session);
        log("agent-replay", name, uid, &result);
    }
    match result {
        Ok(page) => GatexResponse::AgentReplayOk {
            session: session.to_string(),
            started: crate::expiry::format_expires_at(page.started_unix),
            chunks: page.batch.chunks,
            dropped: page.batch.dropped,
            next: page.next,
            offset: page.offset,
        }
        .into(),
        Err(e) => Response::fail(e),
    }
}

fn replay(root: &Path, uid: u32, session: &str, at: (u64, u64)) -> Result<Page, String> {
    // The session id becomes a file name: only the gate's own format.
    if !valid_session(session) {
        return Err("no such recording".into());
    }
    let kek = crate::crypto::snapshot_key()?;
    recfile::read(root, uid, session, &kek, at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_gatex::recfile::tests::{batch, root, SID};
    use crate::daemon_gatex::recfile::user_dir;

    #[test]
    fn a_session_without_record_stores_nothing() {
        let root = root();
        let mut r = Recorder::new(1000, SID, false);
        assert!(r.store(&root, batch("x")).is_err());
        assert!(!user_dir(&root, 1000).exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn replay_refuses_session_names_that_are_not_gate_ids() {
        let root = root();
        for bad in ["../1001/0123456789abcdef", "", "0123456789ABCDEF", "x.rec"] {
            assert_eq!(
                replay(&root, 1000, bad, (0, 0)).unwrap_err(),
                "no such recording"
            );
        }
        std::fs::remove_dir_all(&root).unwrap();
    }
}
