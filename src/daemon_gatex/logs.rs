// daemon_gatex/logs.rs — the gate request journal, daemon side (T11.22).
// Every gate hands its journal entries (metadata only, see
// kepr_core::gate_journal) to the daemon over its private channel; they
// are kept per user as JSON lines for `kepr agent logs`:
//
//   <state>/agent-logs/<uid>/requests.<gen>.jsonl   (0600, dirs 0700)
//
// A file past MAX_FILE starts generation gen+1, and anything older than
// the previous generation is removed, so a user's journal stays under
// about 2 × MAX_FILE. Readers hold a cursor (generation, byte offset):
// one left inside a rotated-out file finishes it and carries on in the
// next, so following the journal loses and repeats nothing across a
// rotation. The session id stored with each entry is the one the daemon
// gave the gate, never one the gate claims.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::audit::{self, AuditEvent, AuditResult};
use kepr_core::gate_journal::{JournalEntry, MAX_BATCH};
use kepr_core::gate_protocol::GateResponse;
use kepr_core::protocol::Response;
use kepr_core::protocol_gatex::{valid_session, GatexResponse, LogCursor};

/// One journal generation grows to about this size.
const MAX_FILE: u64 = 512 << 10;
/// Entry bytes per reply: one reply must fit a socket frame.
const PAGE_BYTES: usize = 40 << 10;
/// `kepr agent logs -n` at most.
pub const MAX_LAST: u32 = 10_000;

/// Appends and rotations of every gate's channel thread, one at a time.
static WRITING: Mutex<()> = Mutex::new(());

fn user_dir(root: &Path, uid: u32) -> PathBuf {
    root.join("agent-logs").join(uid.to_string())
}

fn gen_path(dir: &Path, gen: u64) -> PathBuf {
    dir.join(format!("requests.{gen}.jsonl"))
}

/// The generations present, oldest first.
fn gens(dir: &Path) -> Vec<u64> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<u64> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let n = name.strip_prefix("requests.")?.strip_suffix(".jsonl")?;
            n.parse().ok().filter(|g| *g > 0)
        })
        .collect();
    out.sort_unstable();
    out
}

/// Append one gate's batch for `uid`, as `session`.
fn append(
    root: &Path,
    uid: u32,
    session: &str,
    entries: Vec<JournalEntry>,
    max_file: u64,
) -> Result<(), String> {
    if entries.len() > MAX_BATCH {
        return Err("journal batch too large".into());
    }
    let mut lines = Vec::new();
    for e in entries {
        let e = JournalEntry {
            session: session.to_string(),
            ..e
        }
        .sanitized();
        serde_json::to_writer(&mut lines, &e).map_err(|e| e.to_string())?;
        lines.push(b'\n');
    }
    if lines.is_empty() {
        return Ok(());
    }
    let _one = WRITING.lock().map_err(|_| "journal lock poisoned")?;
    let dir = user_dir(root, uid);
    fs::create_dir_all(&dir).map_err(|e| format!("journal: {e}"))?;
    for d in [dir.parent().unwrap_or(&dir), &dir] {
        let _ = fs::set_permissions(d, fs::Permissions::from_mode(0o700));
    }
    let present = gens(&dir);
    let mut gen = present.last().copied().unwrap_or(1);
    let size = fs::metadata(gen_path(&dir, gen)).map_or(0, |m| m.len());
    if size > 0 && size + lines.len() as u64 > max_file {
        gen += 1;
        for old in present.iter().filter(|g| **g + 1 < gen) {
            let _ = fs::remove_file(gen_path(&dir, *old));
        }
    }
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(gen_path(&dir, gen))
        .and_then(|mut f| f.write_all(&lines))
        .map_err(|e| format!("journal: {e}"))
}

/// A gate's `Journal` batch: stored under the gate owner's uid and the
/// session the daemon started. The gate sees only a generic failure.
pub fn handle_journal(
    uid: u32,
    session: &str,
    id: u64,
    entries: Vec<JournalEntry>,
) -> GateResponse {
    match append(&crate::state_dir(), uid, session, entries, MAX_FILE) {
        Ok(()) => GateResponse::Recorded { id },
        Err(_) => GateResponse::Err {
            id,
            error: "journal unavailable".into(),
        },
    }
}

/// The complete lines of generation `gen` from `offset`, each with the
/// offset just past it. An offset past the end (a file replaced under
/// the reader) starts the file again.
fn lines_from(dir: &Path, gen: u64, offset: u64) -> Vec<(Vec<u8>, u64)> {
    let Ok(mut f) = fs::File::open(gen_path(dir, gen)) else {
        return Vec::new();
    };
    let len = f.metadata().map_or(0, |m| m.len());
    let start = if offset > len { 0 } else { offset };
    let mut raw = Vec::new();
    // A follower polls often: read only what it hasn't seen.
    if f.seek(SeekFrom::Start(start))
        .and_then(|_| f.take(MAX_FILE * 2).read_to_end(&mut raw))
        .is_err()
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut at = start as usize;
    for line in raw.split_inclusive(|b| *b == b'\n') {
        if !line.ends_with(b"\n") {
            break; // still being written: read it next time
        }
        at += line.len();
        out.push((line[..line.len() - 1].to_vec(), at as u64));
    }
    out
}

fn wanted(line: &[u8], session: Option<&str>) -> Option<JournalEntry> {
    let e: JournalEntry = serde_json::from_slice(line).ok()?;
    session.is_none_or(|s| e.session == s).then_some(e)
}

/// Where to start for the last `n` entries (of `session`).
fn last_cursor(dir: &Path, session: Option<&str>, n: u32) -> LogCursor {
    let mut starts = Vec::new();
    for gen in gens(dir) {
        let mut begin = 0;
        for (line, end) in lines_from(dir, gen, 0) {
            if wanted(&line, session).is_some() {
                starts.push(LogCursor { gen, offset: begin });
            }
            begin = end;
        }
    }
    let skip = starts.len().saturating_sub(n as usize);
    starts.get(skip).copied().unwrap_or_default()
}

/// One page of entries from `at`: `(entries, next, more)`.
fn read_page(
    dir: &Path,
    session: Option<&str>,
    at: LogCursor,
    budget: usize,
) -> (Vec<JournalEntry>, LogCursor, bool) {
    let present = gens(dir);
    let (Some(&oldest), Some(&newest)) = (present.first(), present.last()) else {
        return (Vec::new(), LogCursor::default(), false);
    };
    // Rotated away (or the journal was removed): from the oldest kept.
    let mut at = match at.gen < oldest || at.gen > newest {
        true => LogCursor {
            gen: oldest,
            offset: 0,
        },
        false => at,
    };
    let (mut out, mut used, first) = (Vec::new(), 0, at.gen);
    for gen in present.into_iter().filter(|g| *g >= first) {
        let offset = if gen == at.gen { at.offset } else { 0 };
        at = LogCursor { gen, offset };
        for (line, end) in lines_from(dir, gen, offset) {
            if let Some(e) = wanted(&line, session) {
                if used + line.len() > budget && !out.is_empty() {
                    return (out, at, true);
                }
                used += line.len();
                out.push(e);
            }
            at.offset = end;
        }
    }
    (out, at, false)
}

/// `kepr agent logs`: one page of the caller's journal. Audited once per
/// command (its first page), not for every page or follow poll.
pub fn handle_logs(
    uid: u32,
    session: Option<String>,
    from: Option<LogCursor>,
    last: Option<u32>,
) -> Response {
    if session.as_deref().is_some_and(|s| !valid_session(s)) {
        return Response::fail("SESSION is a 16-character session id");
    }
    let dir = user_dir(&crate::state_dir(), uid);
    if from.is_none() {
        audit::log(&AuditEvent {
            op: "agent-logs",
            name: session.as_deref(),
            uid,
            username: &audit::username_for_uid(uid),
            result: AuditResult::Ok,
        });
    }
    let at = match (from, last) {
        (Some(c), _) => c,
        (None, Some(n)) => last_cursor(&dir, session.as_deref(), n.min(MAX_LAST)),
        (None, None) => LogCursor::default(),
    };
    let (entries, next, more) = read_page(&dir, session.as_deref(), at, PAGE_BYTES);
    GatexResponse::AgentLogsOk {
        entries,
        next,
        more,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_gatex::recfile::tests::root;

    const A: &str = "0123456789abcdef";
    const B: &str = "fedcba9876543210";

    fn e(path: &str) -> JournalEntry {
        JournalEntry {
            ts: 1,
            session: "ffffffffffffffff".into(),
            provider: "anthropic".into(),
            host: "api.anthropic.com".into(),
            method: "POST".into(),
            path: path.into(),
            status: 200,
            bytes_out: 2,
            ms: 3,
            blocked: None,
        }
    }

    fn paths(es: &[JournalEntry]) -> Vec<String> {
        es.iter().map(|e| e.path.clone()).collect()
    }

    /// Everything from `at`, page by page: (paths, final cursor).
    fn drain(dir: &Path, session: Option<&str>, mut at: LogCursor) -> (Vec<String>, LogCursor) {
        let mut got = Vec::new();
        loop {
            let (es, next, more) = read_page(dir, session, at, 300);
            got.extend(paths(&es));
            at = next;
            if !more {
                return (got, at);
            }
        }
    }

    #[test]
    fn entries_are_kept_under_the_owners_session_privately() {
        let root = root();
        append(&root, 1000, A, vec![e("/v1/a"), e("/v1/b")], MAX_FILE).unwrap();
        let dir = user_dir(&root, 1000);
        let (es, next, more) = read_page(&dir, None, LogCursor::default(), PAGE_BYTES);
        assert_eq!(paths(&es), ["/v1/a", "/v1/b"]);
        assert!(
            es.iter().all(|e| e.session == A),
            "the gate's claim is replaced"
        );
        assert!(!more);
        assert_eq!(next.gen, 1);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&gen_path(&dir, 1)), 0o600);
        assert_eq!(mode(&dir), 0o700);
        assert!(
            read_page(&user_dir(&root, 1001), None, LogCursor::default(), 9)
                .0
                .is_empty()
        );
        assert!(append(&root, 1000, A, vec![e("/x"); MAX_BATCH + 1], MAX_FILE).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn filters_by_session_and_finds_the_last_entries() {
        let root = root();
        append(&root, 1000, A, vec![e("/a1"), e("/a2"), e("/a3")], MAX_FILE).unwrap();
        append(&root, 1000, B, vec![e("/b1")], MAX_FILE).unwrap();
        append(&root, 1000, A, vec![e("/a4")], MAX_FILE).unwrap();
        let dir = user_dir(&root, 1000);
        assert_eq!(drain(&dir, Some(B), LogCursor::default()).0, ["/b1"]);
        let at = last_cursor(&dir, Some(A), 2);
        assert_eq!(drain(&dir, Some(A), at).0, ["/a3", "/a4"]);
        let at = last_cursor(&dir, None, 99);
        assert_eq!(drain(&dir, None, at).0.len(), 5);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn pages_stay_within_the_budget_and_lose_nothing() {
        let root = root();
        let all: Vec<String> = (0..30).map(|i| format!("/v1/p{i}")).collect();
        for chunk in all.chunks(7) {
            append(
                &root,
                1000,
                A,
                chunk.iter().map(|p| e(p)).collect(),
                MAX_FILE,
            )
            .unwrap();
        }
        let dir = user_dir(&root, 1000);
        let (es, _, more) = read_page(&dir, None, LogCursor::default(), 300);
        assert!(more && es.len() < 30 && !es.is_empty());
        assert_eq!(drain(&dir, None, LogCursor::default()).0, all);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn follow_carries_on_across_a_rotation() {
        let root = root();
        let dir = user_dir(&root, 1000);
        let max = 600; // a few entries per generation
        append(&root, 1000, A, vec![e("/n1"), e("/n2")], max).unwrap();
        let (got, at) = drain(&dir, None, LogCursor::default());
        assert_eq!(got, ["/n1", "/n2"]);
        // Rotate once while the reader sits in generation 1.
        for p in ["/n3", "/n4", "/n5", "/n6"] {
            append(&root, 1000, A, vec![e(p)], max).unwrap();
        }
        assert!(gens(&dir).len() >= 2, "{:?}", gens(&dir));
        let (got, at) = drain(&dir, None, at);
        assert_eq!(got, ["/n3", "/n4", "/n5", "/n6"], "no gap, no repeat");
        // Rotate past the reader's generation entirely: it restarts at
        // the oldest kept, and the oldest beyond two generations is gone.
        for i in 7..30 {
            append(&root, 1000, A, vec![e(&format!("/n{i}"))], max).unwrap();
        }
        let kept = gens(&dir);
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(kept[0] > at.gen);
        let (got, end) = drain(&dir, None, at);
        assert_eq!(got.last().map(String::as_str), Some("/n29"));
        assert_eq!(drain(&dir, None, end).0, Vec::<String>::new());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_torn_or_damaged_line_is_not_taken() {
        let root = root();
        append(&root, 1000, A, vec![e("/n1")], MAX_FILE).unwrap();
        let dir = user_dir(&root, 1000);
        let mut f = OpenOptions::new()
            .append(true)
            .open(gen_path(&dir, 1))
            .unwrap();
        f.write_all(b"not json\n{\"ts\":").unwrap();
        let (got, at) = drain(&dir, None, LogCursor::default());
        assert_eq!(got, ["/n1"]);
        f.write_all(b"2,\"session\":\"0123456789abcdef\",\"provider\":\"p\",\"method\":\"GET\",\"path\":\"/n2\",\"status\":200,\"bytes_out\":0,\"ms\":0}\n").unwrap();
        assert_eq!(drain(&dir, None, at).0, ["/n2"], "finished line read once");
        fs::remove_dir_all(&root).unwrap();
    }
}
