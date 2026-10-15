// cli_gatex/replay.rs — `kepr agent replay` (T7.09).
//
//   kepr agent replay                       list recorded sessions
//   kepr agent replay SESSION               print one
//   kepr agent replay SESSION --typescript FILE --timing FILE
//                                           its PostgreSQL traffic as a
//                                           scriptreplay typescript + timing
//
// The daemon decrypts a recording one stored batch at a time; this pages
// through them. A recording holds what the agent sent and received
// (placeholders, never keys), so nothing here is a credential.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use kepr_core::gate_record::{RecChunk, FROM_AGENT};
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_gatex::{GatexRequest, GatexResponse, RecordingInfo};

use super::pg_script::{printable, typescript, Transcript};
use crate::{cli_ui, client};

const USAGE: &str = "usage: kepr agent replay [SESSION] [--typescript FILE --timing FILE]";

#[derive(Debug, Default, PartialEq)]
struct Args {
    session: Option<String>,
    typescript: Option<String>,
    timing: Option<String>,
}

fn parse(raw: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = raw.iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().cloned().ok_or(format!("{arg} needs a FILE"));
        match arg.as_str() {
            "--typescript" => a.typescript = Some(value()?),
            "--timing" => a.timing = Some(value()?),
            "--json" => {}
            s if !s.starts_with('-') && a.session.is_none() => a.session = Some(s.to_string()),
            other => return Err(format!("unexpected argument: {other}\n{USAGE}")),
        }
    }
    if a.typescript.is_some() != a.timing.is_some() {
        return Err(format!("--typescript and --timing go together\n{USAGE}"));
    }
    if a.typescript.is_some() && a.session.is_none() {
        return Err(USAGE.into());
    }
    Ok(a)
}

pub fn main(raw: &[String]) -> Response {
    let a = match parse(raw) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    let result = match (&a.session, &a.typescript, &a.timing) {
        (None, _, _) => return list(),
        (Some(s), Some(ts), Some(tm)) => export(s, ts, tm),
        (Some(s), _, _) => print(s),
    };
    match result {
        Ok(r) => r,
        Err(e) => Response::fail(e),
    }
}

fn list() -> Response {
    let resp = match client::send_request(&Request::Gatex(GatexRequest::AgentRecordings)) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    if let Response::Gatex(GatexResponse::AgentRecordingsOk { sessions }) = &resp {
        if !cli_ui::json_mode() {
            print_list(sessions);
        }
    }
    resp
}

fn print_list(sessions: &[RecordingInfo]) {
    if sessions.is_empty() {
        cli_ui::info("no recorded sessions; record one with: kepr agent run HARNESS --record");
        return;
    }
    println!("{:<18} {:<18} SIZE", "SESSION", "STARTED (UTC)");
    for s in sessions {
        let kib = s.bytes.div_ceil(1024);
        println!("{:<18} {:<18} {kib} KiB", s.session, s.started);
    }
}

/// Every stored batch of `session`, in order: `each(chunks, dropped)`.
/// Returns the session's start time.
fn pages(session: &str, mut each: impl FnMut(&[RecChunk], u64)) -> Result<String, String> {
    let (mut frame, mut offset) = (0, 0);
    loop {
        let req = Request::Gatex(GatexRequest::AgentReplay {
            session: session.to_string(),
            frame,
            offset,
        });
        match client::send_request(&req)? {
            Response::Gatex(GatexResponse::AgentReplayOk {
                started,
                chunks,
                dropped,
                next,
                offset: at,
                ..
            }) => {
                each(&chunks, dropped);
                match next {
                    Some(n) => (frame, offset) = (n, at),
                    None => return Ok(started),
                }
            }
            Response::Err { error } => return Err(error),
            _ => return Err("unexpected daemon response".into()),
        }
    }
}

/// Prints chunks for a person: PostgreSQL traffic decoded, everything
/// else as text with control characters escaped, and a heading whenever
/// the connection or direction changes.
#[derive(Default)]
struct Printer {
    pg: Transcript,
    shown: usize,
    last: Option<(u64, bool)>,
}

impl Printer {
    fn chunk(&mut self, c: &RecChunk, out: &mut impl Write) -> std::io::Result<()> {
        if c.kind == "postgres" {
            self.pg.feed(c);
            for p in &self.pg.pieces[self.shown..] {
                out.write_all(p.text.as_bytes())?;
            }
            self.shown = self.pg.pieces.len();
            self.last = None;
            return Ok(());
        }
        let from_agent = c.dir == FROM_AGENT;
        if self.last != Some((c.conn, from_agent)) {
            self.last = Some((c.conn, from_agent));
            let arrow = if from_agent { "agent >>>" } else { "<<< agent" };
            let (secs, ms) = (c.t / 1000, c.t % 1000);
            let route = printable(&c.route);
            writeln!(
                out,
                "\n[+{secs}.{ms:03}s] #{} {route} ({}) {arrow}",
                c.conn, c.kind
            )?;
        }
        out.write_all(printable(&String::from_utf8_lossy(&c.bytes())).as_bytes())
    }
}

fn print(session: &str) -> Result<Response, String> {
    let (mut printer, mut dropped) = (Printer::default(), 0);
    let json = cli_ui::json_mode();
    let mut out = std::io::stdout().lock();
    let started = pages(session, |chunks, d| {
        dropped += d;
        for c in chunks {
            let _ = match json {
                true => serde_json::to_writer(&mut out, c).map_err(std::io::Error::other),
                false => printer.chunk(c, &mut out),
            };
            if json {
                let _ = out.write_all(b"\n");
            }
        }
    })?;
    drop(out);
    if dropped > 0 && !json {
        cli_ui::warn(&format!(
            "{dropped} bytes were not recorded (the gate's buffer was full)"
        ));
    }
    Ok(done(session, started, dropped))
}

fn done(session: &str, started: String, dropped: u64) -> Response {
    GatexResponse::AgentReplayOk {
        session: session.to_string(),
        started,
        chunks: Vec::new(),
        dropped,
        next: None,
        offset: 0,
    }
    .into()
}

fn export(session: &str, ts_path: &str, timing_path: &str) -> Result<Response, String> {
    let mut tr = Transcript::default();
    let mut dropped = 0;
    let started = pages(session, |chunks, d| {
        dropped += d;
        chunks
            .iter()
            .filter(|c| c.kind == "postgres")
            .for_each(|c| tr.feed(c));
    })?;
    if tr.pieces.is_empty() {
        return Err(format!(
            "session {session} has no recorded PostgreSQL traffic"
        ));
    }
    let header = format!("{started} UTC [kepr agent session {session}]");
    let (ts, timing) = typescript(&tr.pieces, &header);
    // Query results are sensitive: owner-only, and never over a file.
    for (path, bytes) in [(ts_path, &ts[..]), (timing_path, timing.as_bytes())] {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| f.write_all(bytes))
            .map_err(|e| format!("{path}: {e}"))?;
    }
    if !cli_ui::json_mode() {
        cli_ui::ok(&format!("wrote {ts_path} and {timing_path}"));
        cli_ui::info(&format!(
            "play it with: scriptreplay --timing {timing_path} {ts_path}"
        ));
    }
    Ok(done(session, started, dropped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::gate_record::TO_AGENT;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_list_print_and_export() {
        assert_eq!(parse(&[]).unwrap(), Args::default());
        let a = parse(&v(&["0123456789abcdef"])).unwrap();
        assert_eq!(a.session.as_deref(), Some("0123456789abcdef"));
        let a = parse(&v(&["s", "--typescript", "t", "--timing", "m"])).unwrap();
        assert_eq!(
            (a.typescript.as_deref(), a.timing.as_deref()),
            (Some("t"), Some("m"))
        );
        assert!(parse(&v(&["s", "--typescript", "t"])).is_err());
        assert!(parse(&v(&["--typescript", "t", "--timing", "m"])).is_err());
        assert!(parse(&v(&["s", "--timing"])).is_err());
        assert!(parse(&v(&["a", "b"])).is_err());
    }

    #[test]
    fn prints_headings_and_escapes_what_it_prints() {
        let mut p = Printer::default();
        let mut out = Vec::new();
        for c in [
            RecChunk::new(
                1500,
                1,
                "anthropic",
                "http",
                FROM_AGENT,
                b"POST /v1/messages\n\n",
            ),
            RecChunk::new(1600, 1, "anthropic", "http", FROM_AGENT, b"{}"),
            RecChunk::new(
                2042,
                1,
                "anthropic",
                "http",
                TO_AGENT,
                b"\x1b]0;pwned\x07ok",
            ),
        ] {
            p.chunk(&c, &mut out).unwrap();
        }
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "\n[+1.500s] #1 anthropic (http) agent >>>\nPOST /v1/messages\n\n{}\n[+2.042s] #1 anthropic (http) <<< agent\n\\x1b]0;pwned\\x07ok"
        );
    }
}
