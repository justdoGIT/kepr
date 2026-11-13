//! Durable pre-execution decisions and post-execution results.
//!
//! A gate must persist a decision before a consequential operation runs. The
//! records are metadata only; arguments and response bodies are represented by
//! digests. The daemon owns this file and fsyncs every append. On startup,
//! intents without a result are reconciled as `unknown` rather than silently
//! disappearing.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kepr_core::gate_journal::{DecisionRecord, ResultOutcome, ResultRecord};
use kepr_core::gate_protocol::GateResponse;

const MAX_FILE: u64 = 8 << 20;
const MAX_LINE: usize = 16 << 10;
static WRITING: Mutex<()> = Mutex::new(());

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "record", rename_all = "snake_case")]
enum RecordKind {
    Decision(DecisionRecord),
    Result(ResultRecord),
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Envelope {
    session: String,
    #[serde(flatten)]
    kind: RecordKind,
}

fn dir(root: &Path, uid: u32) -> PathBuf {
    root.join("agent-decisions").join(uid.to_string())
}

fn path(root: &Path, uid: u32, generation: u32) -> PathBuf {
    dir(root, uid).join(if generation == 0 {
        "records.jsonl".to_string()
    } else {
        format!("records.{generation}.jsonl")
    })
}

fn paths(root: &Path, uid: u32) -> Vec<PathBuf> {
    let d = dir(root, uid);
    let mut out = fs::read_dir(d)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let generation = name
                .strip_prefix("records")?
                .strip_suffix(".jsonl")?
                .strip_prefix('.')
                .unwrap_or("0")
                .parse::<u32>()
                .ok()?;
            Some((generation, entry.path()))
        })
        .collect::<Vec<_>>();
    out.sort_by_key(|(generation, _)| *generation);
    out.into_iter().map(|(_, path)| path).collect()
}

fn ensure_dir(root: &Path, uid: u32) -> Result<PathBuf, String> {
    let parent = root.join("agent-decisions");
    fs::create_dir_all(&parent).map_err(|e| format!("decision journal: {e}"))?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("decision journal permissions: {e}"))?;
    let d = dir(root, uid);
    fs::create_dir_all(&d).map_err(|e| format!("decision journal: {e}"))?;
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("decision journal permissions: {e}"))?;
    Ok(d)
}

fn append(root: &Path, uid: u32, envelope: Envelope) -> Result<(), String> {
    let mut line = serde_json::to_vec(&envelope).map_err(|e| format!("decision encode: {e}"))?;
    if line.len() > MAX_LINE {
        return Err("decision record too large".into());
    }
    line.push(b'\n');
    let _writing = WRITING.lock().map_err(|_| "decision journal poisoned")?;
    let d = ensure_dir(root, uid)?;
    let current = path(root, uid, 0);
    if fs::metadata(&current)
        .map(|m| m.len().saturating_add(line.len() as u64) > MAX_FILE)
        .unwrap_or(false)
    {
        let old = path(root, uid, 1);
        let _ = fs::remove_file(&old);
        fs::rename(&current, &old).map_err(|e| format!("decision journal rotate: {e}"))?;
        crate::atomic_file::sync_dir(&d)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&current)
        .map_err(|e| format!("decision journal open: {e}"))?;
    file.write_all(&line)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("decision journal sync: {e}"))
}

fn response<T>(id: u64, result: Result<(), String>, ok: T) -> GateResponse
where
    T: FnOnce(u64) -> GateResponse,
{
    match result {
        Ok(()) => ok(id),
        Err(_) => GateResponse::Err {
            id,
            error: "decision journal unavailable".into(),
        },
    }
}

pub fn handle_decision(
    uid: u32,
    session: &str,
    id: u64,
    mut record: DecisionRecord,
) -> GateResponse {
    record.session = session.to_string();
    let result = if record.intent_id.is_empty() {
        Err("missing intent id".into())
    } else {
        append(
            &crate::state_dir(),
            uid,
            Envelope {
                session: session.to_string(),
                kind: RecordKind::Decision(record.sanitized()),
            },
        )
    };
    response(id, result, |id| GateResponse::DecisionRecorded { id })
}

pub fn handle_result(uid: u32, session: &str, id: u64, record: ResultRecord) -> GateResponse {
    let result = if record.intent_id.is_empty() {
        Err("missing intent id".into())
    } else {
        append(
            &crate::state_dir(),
            uid,
            Envelope {
                session: session.to_string(),
                kind: RecordKind::Result(record.sanitized()),
            },
        )
    };
    response(id, result, |id| GateResponse::ResultRecorded { id })
}

fn read(path: &Path) -> Result<Vec<Envelope>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("decision journal open: {e}"))?;
    BufReader::new(file)
        .lines()
        .map(|line| {
            let line = line.map_err(|e| format!("decision journal read: {e}"))?;
            if line.len() > MAX_LINE {
                return Err("decision record too large".into());
            }
            serde_json::from_str(&line).map_err(|e| format!("decision journal parse: {e}"))
        })
        .collect()
}

/// Mark intents left by a terminated daemon or gate as explicitly unknown.
pub fn reconcile(root: &Path) -> Result<(), String> {
    let parent = root.join("agent-decisions");
    let entries = match fs::read_dir(&parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("decision journal scan: {error}")),
    };
    let mut pending = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("decision journal scan: {e}"))?;
        let uid = entry
            .file_name()
            .to_string_lossy()
            .parse::<u32>()
            .map_err(|_| "invalid decision journal owner".to_string())?;
        let mut decisions = HashMap::<String, String>::new();
        let mut results = HashSet::new();
        for file in paths(root, uid) {
            for envelope in read(&file)? {
                match envelope.kind {
                    RecordKind::Decision(record) => {
                        decisions.insert(record.intent_id, envelope.session);
                    }
                    RecordKind::Result(record) => {
                        results.insert(record.intent_id);
                    }
                }
            }
        }
        for (intent_id, session) in decisions {
            if !results.contains(&intent_id) {
                pending.push((uid, session, intent_id));
            }
        }
    }
    for (uid, session, intent_id) in pending {
        append(
            root,
            uid,
            Envelope {
                session,
                kind: RecordKind::Result(ResultRecord {
                    intent_id,
                    outcome: ResultOutcome::Unknown,
                    digest: "reconciled-after-restart".into(),
                }),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn decision(intent_id: &str) -> DecisionRecord {
        DecisionRecord {
            session: "claimed-by-gate".into(),
            intent_id: intent_id.into(),
            actor_ref: "actor-ref".into(),
            tenant: "tenant".into(),
            policy_version: "v1".into(),
            sensitivity: "private".into(),
            destination: "api.example.test".into(),
            action: "write".into(),
            decision: "allow".into(),
            approval_ref: None,
            expiry: None,
        }
    }

    #[test]
    fn decision_is_before_result_and_missing_result_is_reconciled() {
        let root = root();
        append(
            root.path(),
            1000,
            Envelope {
                session: "session".into(),
                kind: RecordKind::Decision(decision("intent-1")),
            },
        )
        .unwrap();
        let records = read(&path(root.path(), 1000, 0)).unwrap();
        assert!(matches!(records[0].kind, RecordKind::Decision(_)));
        reconcile(root.path()).unwrap();
        let records = read(&path(root.path(), 1000, 0)).unwrap();
        assert!(matches!(
            records[1].kind,
            RecordKind::Result(ResultRecord {
                outcome: ResultOutcome::Unknown,
                ..
            })
        ));
    }

    #[test]
    fn repeated_reconciliation_is_idempotent() {
        let root = root();
        append(
            root.path(),
            1000,
            Envelope {
                session: "session".into(),
                kind: RecordKind::Decision(decision("intent-1")),
            },
        )
        .unwrap();
        reconcile(root.path()).unwrap();
        reconcile(root.path()).unwrap();
        let records = read(&path(root.path(), 1000, 0)).unwrap();
        assert_eq!(records.len(), 2);
    }
}
