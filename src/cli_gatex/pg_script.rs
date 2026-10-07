// cli_gatex/pg_script.rs — a recorded PostgreSQL session as text (T7.09).
// The recording holds the wire bytes each side sent after login; this
// decodes them into a psql-like transcript (queries, rows, command tags,
// errors) and writes that transcript as a `scriptreplay` typescript plus
// timing file:
//
//   typescript: "Script started on …\n" (skipped by scriptreplay), then
//               the transcript bytes
//   timing:     one "SECONDS.MICROS BYTES\n" line per piece: the delay
//               since the previous piece, and how many typescript bytes
//               to print after it (util-linux's classic format)
//
// Everything printed is untrusted (the agent's queries, the server's
// rows), so control characters are escaped: a replay can't drive the
// viewer's terminal.

use std::collections::HashMap;

use kepr_core::gate_record::{RecChunk, FROM_AGENT};

/// A message larger than this is taken as a desynchronised stream.
const MAX_MSG: usize = 64 << 20;

/// One piece of transcript and when (ms into the session) it happened.
#[derive(Debug, PartialEq)]
pub struct Piece {
    pub t: u64,
    pub text: String,
}

/// One direction of one connection: bytes not yet a whole message.
#[derive(Default)]
struct Stream {
    buf: Vec<u8>,
    broken: bool,
}

impl Stream {
    fn feed(&mut self, data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        if self.broken {
            return out;
        }
        self.buf.extend_from_slice(data);
        while self.buf.len() >= 5 {
            let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]);
            let len = len as usize;
            if !(4..=MAX_MSG).contains(&len) {
                self.broken = true;
                self.buf.clear();
                break;
            }
            if self.buf.len() < 1 + len {
                break;
            }
            let msg: Vec<u8> = self.buf.drain(..1 + len).collect();
            out.push((msg[0], msg[5..].to_vec()));
        }
        out
    }
}

/// Decodes the PostgreSQL chunks of a recording, in order.
#[derive(Default)]
pub struct Transcript {
    streams: HashMap<(u64, bool), Stream>,
    last_conn: Option<u64>,
    pub pieces: Vec<Piece>,
}

impl Transcript {
    pub fn feed(&mut self, c: &RecChunk) {
        let from_agent = c.dir == FROM_AGENT;
        let msgs = (self.streams.entry((c.conn, from_agent)).or_default()).feed(&c.bytes());
        for (kind, body) in msgs {
            let text = match from_agent {
                true => frontend(kind, &body),
                false => backend(kind, &body),
            };
            let Some(text) = text else { continue };
            if self.last_conn != Some(c.conn) {
                self.last_conn = Some(c.conn);
                let banner = format!("-- connection #{} ({})\n", c.conn, printable(&c.route));
                self.pieces.push(Piece {
                    t: c.t,
                    text: banner,
                });
            }
            self.pieces.push(Piece { t: c.t, text });
        }
    }
}

fn cstr(b: &[u8]) -> (&[u8], &[u8]) {
    match b.iter().position(|&x| x == 0) {
        Some(i) => (&b[..i], &b[i + 1..]),
        None => (b, &[]),
    }
}

/// A query as the agent sent it (simple query or Parse).
fn frontend(kind: u8, body: &[u8]) -> Option<String> {
    let sql = match kind {
        b'Q' => cstr(body).0,
        b'P' => cstr(cstr(body).1).0, // statement name, then the query
        _ => return None,
    };
    let sql = printable(&String::from_utf8_lossy(sql));
    Some(format!("=> {}\n", sql.trim_end()))
}

fn backend(kind: u8, body: &[u8]) -> Option<String> {
    match kind {
        b'T' => Some(columns(body)),
        b'D' => Some(row(body)),
        b'C' => Some(format!("({})\n\n", value(cstr(body).0))),
        b'E' | b'N' => Some(notice(kind, body)),
        b'd' => Some(printable(&String::from_utf8_lossy(body))),
        _ => None,
    }
}

fn columns(body: &[u8]) -> String {
    let n = body
        .get(..2)
        .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    let mut rest = body.get(2..).unwrap_or_default();
    let mut names = Vec::new();
    for _ in 0..n {
        let (name, after) = cstr(rest);
        names.push(value(name));
        rest = after.get(18..).unwrap_or_default(); // table, column, type, size, mod, format
    }
    let line = names.join(" | ");
    format!("{line}\n{}\n", "-".repeat(line.chars().count().max(1)))
}

fn row(body: &[u8]) -> String {
    let n = body
        .get(..2)
        .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    let mut rest = body.get(2..).unwrap_or_default();
    let mut values = Vec::new();
    for _ in 0..n {
        let Some(len) = rest.get(..4) else { break };
        let len = i32::from_be_bytes([len[0], len[1], len[2], len[3]]);
        rest = &rest[4..];
        if len < 0 {
            values.push(String::new()); // NULL, shown empty as psql does
            continue;
        }
        let len = (len as usize).min(rest.len());
        values.push(value(&rest[..len]));
        rest = &rest[len..];
    }
    format!("{}\n", values.join(" | "))
}

fn notice(kind: u8, body: &[u8]) -> String {
    let (mut severity, mut message) = (String::new(), String::new());
    let mut rest = body;
    while let Some((&field, after)) = rest.split_first() {
        if field == 0 {
            break;
        }
        let (text, after) = cstr(after);
        match field {
            b'V' => severity = value(text),
            b'S' if severity.is_empty() => severity = value(text),
            b'M' => message = value(text),
            _ => {}
        }
        rest = after;
    }
    if severity.is_empty() {
        severity = if kind == b'E' { "ERROR" } else { "NOTICE" }.into();
    }
    let gap = if kind == b'E' { "\n" } else { "" };
    format!("{severity}:  {message}\n{gap}")
}

/// One field: text with every control character escaped, or `\x…` hex
/// when it isn't UTF-8 (a binary-format value).
fn value(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.chars().map(escape).collect(),
        Err(_) => format!("\\x{}", hex::encode(b)),
    }
}

fn escape(c: char) -> String {
    match c {
        c if c.is_control() => format!("\\x{:02x}", c as u32),
        c => c.to_string(),
    }
}

/// Multi-line text: newlines and tabs kept, other control characters
/// escaped.
pub fn printable(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' | '\t' => c.to_string(),
            c => escape(c),
        })
        .collect()
}

/// The transcript as a typescript and its timing file. `started` names
/// the session on the header line, which scriptreplay skips.
pub fn typescript(pieces: &[Piece], started: &str) -> (Vec<u8>, String) {
    let mut ts = format!("Script started on {started}\n").into_bytes();
    let mut timing = String::new();
    let mut last = pieces.first().map_or(0, |p| p.t);
    for p in pieces.iter().filter(|p| !p.text.is_empty()) {
        let ms = p.t.saturating_sub(last);
        let line = format!("{}.{:06} {}\n", ms / 1000, (ms % 1000) * 1000, p.text.len());
        timing.push_str(&line);
        ts.extend_from_slice(p.text.as_bytes());
        last = p.t;
    }
    (ts, timing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::gate_record::TO_AGENT;

    fn msg(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut m = vec![kind];
        m.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        m.extend_from_slice(body);
        m
    }

    impl Transcript {
        fn text(&self) -> String {
            self.pieces.iter().map(|p| p.text.as_str()).collect()
        }
    }

    fn chunk(t: u64, dir: &str, bytes: &[u8]) -> RecChunk {
        RecChunk::new(t, 3, "db:APP", "postgres", dir, bytes)
    }

    fn select_one() -> Vec<u8> {
        let mut t = 1u16.to_be_bytes().to_vec();
        t.extend_from_slice(b"n\0");
        t.extend_from_slice(&[0u8; 18]);
        let mut d = 2u16.to_be_bytes().to_vec();
        d.extend_from_slice(&1i32.to_be_bytes());
        d.push(b'1');
        d.extend_from_slice(&(-1i32).to_be_bytes());
        [
            msg(b'T', &t),
            msg(b'D', &d),
            msg(b'C', b"SELECT 1\0"),
            msg(b'Z', b"I"),
        ]
        .concat()
    }

    #[test]
    fn decodes_queries_rows_and_errors_across_chunk_boundaries() {
        let mut tr = Transcript::default();
        let q = msg(b'Q', b"SELECT 1 AS n\0");
        tr.feed(&chunk(10, FROM_AGENT, &q[..3]));
        tr.feed(&chunk(11, FROM_AGENT, &q[3..]));
        let rows = select_one();
        tr.feed(&chunk(20, TO_AGENT, &rows[..9]));
        tr.feed(&chunk(25, TO_AGENT, &rows[9..]));
        let err = msg(
            b'E',
            b"SERROR\0VERROR\0C42P01\0Mrelation \"x\" does not exist\0\0",
        );
        tr.feed(&chunk(30, TO_AGENT, &err));
        assert_eq!(
            tr.text(),
            "-- connection #3 (db:APP)\n=> SELECT 1 AS n\nn\n-\n1 | \n(SELECT 1)\n\nERROR:  relation \"x\" does not exist\n\n"
        );
        assert_eq!(tr.pieces[1].t, 11, "a piece takes the time it completed");
    }

    #[test]
    fn control_characters_never_reach_the_terminal() {
        let mut tr = Transcript::default();
        tr.feed(&chunk(1, FROM_AGENT, &msg(b'Q', b"SELECT '\x1b[2J'\0")));
        let mut d = 1u16.to_be_bytes().to_vec();
        d.extend_from_slice(&3i32.to_be_bytes());
        d.extend_from_slice(b"a\nb");
        tr.feed(&chunk(2, TO_AGENT, &msg(b'D', &d)));
        let text = tr.text();
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(text.contains("SELECT '\\x1b[2J'") && text.contains("a\\x0ab\n"));
    }

    #[test]
    fn a_desynchronised_stream_stops_instead_of_printing_garbage() {
        let mut tr = Transcript::default();
        tr.feed(&chunk(1, TO_AGENT, b"Z\xff\xff\xff\xffjunk"));
        tr.feed(&chunk(2, TO_AGENT, &msg(b'C', b"SELECT 1\0")));
        assert!(tr.pieces.is_empty());
    }

    #[test]
    fn timing_lines_follow_the_classic_scriptreplay_format() {
        let pieces = vec![
            Piece {
                t: 1000,
                text: "=> SELECT 1\n".into(),
            },
            Piece {
                t: 1250,
                text: "n\n".into(),
            },
            Piece {
                t: 3500,
                text: "(SELECT 1)\n\n".into(),
            },
        ];
        let (ts, timing) = typescript(&pieces, "2026-10-05 12:00 UTC [kepr]");
        assert_eq!(timing, "0.000000 12\n0.250000 2\n2.250000 12\n");
        let header_end = ts.iter().position(|&b| b == b'\n').unwrap() + 1;
        assert!(ts.starts_with(b"Script started on "));
        let counted: usize = timing
            .lines()
            .map(|l| {
                let (delay, n) = l.split_once(' ').unwrap();
                let (s, us) = delay.split_once('.').unwrap();
                assert!(s.parse::<u64>().is_ok() && us.len() == 6);
                n.parse::<usize>().unwrap()
            })
            .sum();
        assert_eq!(counted, ts.len() - header_end);
    }
}
