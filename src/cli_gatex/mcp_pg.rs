// cli_gatex/mcp_pg.rs — the PostgreSQL client behind `kepr mcp`'s
// db_query (T9.05). It talks only to the gate's loopback database proxy
// (P7.1), with the session placeholder as its password: the gate logs in
// to the real server with the sealed record, so neither this process nor
// the agent ever holds the database password.
//
// One statement per call, sent with the extended query protocol (Parse /
// Bind / Execute), which the server refuses to run as more than one
// command. Read-only calls first `SET default_transaction_read_only = on`
// and wrap the statement in `BEGIN READ ONLY … ROLLBACK`, so a statement
// can neither write nor end the transaction and write afterwards. That is
// a guard against mistakes; a role without write grants is the boundary.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const PROTOCOL_3: u32 = 196_608;
const MAX_MSG: usize = 1 << 20;
/// Rows fetched per statement; more are reported as truncated.
pub const MAX_ROWS: u32 = 500;
/// Row bytes kept per statement.
const MAX_KEPT: usize = 256 << 10;
const TIMEOUT: Duration = Duration::from_secs(120);

pub const READ_ONLY_SET: &str = "SET default_transaction_read_only = on";

#[derive(Debug, Default, PartialEq)]
pub struct Outcome {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    /// The command tag, e.g. `SELECT 2`, `INSERT 0 1`.
    pub tag: String,
    /// More rows than were fetched or kept.
    pub truncated: bool,
}

fn msg(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn cstr(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

fn startup() -> Vec<u8> {
    let mut body = PROTOCOL_3.to_be_bytes().to_vec();
    for (k, v) in [
        ("user", "kepr"),
        ("database", "kepr"),
        ("application_name", "kepr-mcp"),
        ("client_encoding", "UTF8"),
    ] {
        cstr(&mut body, k);
        cstr(&mut body, v);
    }
    body.push(0);
    let mut out = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

fn read_msg(s: &mut impl Read) -> Result<(u8, Vec<u8>), String> {
    let mut head = [0u8; 5];
    s.read_exact(&mut head)
        .map_err(|e| format!("database: {e}"))?;
    let len = u32::from_be_bytes(head[1..].try_into().expect("4 bytes")) as usize;
    if !(4..=MAX_MSG).contains(&len) {
        return Err("database: malformed message".into());
    }
    let mut body = vec![0u8; len - 4];
    s.read_exact(&mut body)
        .map_err(|e| format!("database: {e}"))?;
    Ok((head[0], body))
}

/// An ErrorResponse as `ERROR 42P01: message (detail)`.
pub fn error_text(body: &[u8]) -> String {
    let mut f = std::collections::HashMap::new();
    for field in body.split(|b| *b == 0).filter(|f| !f.is_empty()) {
        f.insert(field[0], String::from_utf8_lossy(&field[1..]).to_string());
    }
    let get = |k: u8| f.get(&k).cloned().unwrap_or_default();
    let mut out = format!("{} {}: {}", get(b'S'), get(b'C'), get(b'M'));
    for (k, label) in [(b'D', "detail"), (b'H', "hint")] {
        if let Some(v) = f.get(&k) {
            out.push_str(&format!("\n{label}: {v}"));
        }
    }
    out
}

/// Read up to ReadyForQuery; `Err` carries the first ErrorResponse.
fn until_ready(s: &mut impl Read, out: &mut Outcome) -> Result<(), String> {
    let mut error = None;
    let mut kept = 0;
    loop {
        let (kind, body) = read_msg(s)?;
        match kind {
            b'Z' => return error.map_or(Ok(()), Err),
            b'E' if error.is_none() => error = Some(error_text(&body)),
            b'T' => out.columns = row_description(&body)?,
            b'D' if kept + body.len() > MAX_KEPT => out.truncated = true,
            b'D' => {
                kept += body.len();
                out.rows.push(data_row(&body)?);
            }
            b'C' => {
                out.tag = String::from_utf8_lossy(body.strip_suffix(&[0]).unwrap_or(&body)).into()
            }
            b's' => out.truncated = true,
            _ => {} // ParseComplete, BindComplete, NoData, notices, parameters
        }
    }
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
    if b.len() < n {
        return Err("database: malformed message".into());
    }
    let (head, rest) = b.split_at(n);
    *b = rest;
    Ok(head)
}

fn row_description(mut b: &[u8]) -> Result<Vec<String>, String> {
    let n = u16::from_be_bytes(take(&mut b, 2)?.try_into().expect("2 bytes"));
    let mut cols = Vec::new();
    for _ in 0..n {
        let end = b
            .iter()
            .position(|c| *c == 0)
            .ok_or("database: malformed message")?;
        cols.push(String::from_utf8_lossy(&b[..end]).to_string());
        b = &b[end + 1..];
        take(&mut b, 18)?; // table oid, column, type oid, size, modifier, format
    }
    Ok(cols)
}

fn data_row(mut b: &[u8]) -> Result<Vec<Option<String>>, String> {
    let n = u16::from_be_bytes(take(&mut b, 2)?.try_into().expect("2 bytes"));
    let mut row = Vec::new();
    for _ in 0..n {
        let len = i32::from_be_bytes(take(&mut b, 4)?.try_into().expect("4 bytes"));
        row.push(match len {
            -1 => None,
            n if n < 0 => return Err("database: malformed message".into()),
            n => Some(String::from_utf8_lossy(take(&mut b, n as usize)?).to_string()),
        });
    }
    Ok(row)
}

fn simple(s: &mut TcpStream, sql: &str) -> Result<(), String> {
    let mut body = Vec::new();
    cstr(&mut body, sql);
    s.write_all(&msg(b'Q', &body))
        .map_err(|e| format!("database: {e}"))?;
    until_ready(s, &mut Outcome::default())
}

/// The extended-protocol messages for one statement, text results.
pub fn statement(sql: &str) -> Vec<u8> {
    let mut parse = Vec::new();
    cstr(&mut parse, "");
    cstr(&mut parse, sql);
    parse.extend_from_slice(&0u16.to_be_bytes());
    let mut bind = vec![0, 0]; // unnamed portal and statement
    bind.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no formats, params, result formats
    let mut exec = vec![0];
    exec.extend_from_slice(&MAX_ROWS.to_be_bytes());
    [
        msg(b'P', &parse),
        msg(b'B', &bind),
        msg(b'D', b"P\0"),
        msg(b'E', &exec),
        msg(b'S', &[]),
    ]
    .concat()
}

/// Log in to the gate's proxy over `s` with `placeholder`.
fn login(mut s: TcpStream, placeholder: &str) -> Result<TcpStream, String> {
    let _ = s.set_read_timeout(Some(TIMEOUT));
    let _ = s.set_write_timeout(Some(TIMEOUT));
    s.write_all(&startup())
        .map_err(|e| format!("database: {e}"))?;
    loop {
        let (kind, body) = read_msg(&mut s)?;
        match (kind, body.get(..4)) {
            (b'R', Some([0, 0, 0, 3])) => {
                let mut p = Vec::new();
                cstr(&mut p, placeholder);
                s.write_all(&msg(b'p', &p))
                    .map_err(|e| format!("database: {e}"))?;
            }
            (b'R', Some([0, 0, 0, 0])) => {}
            (b'R', _) => return Err("database: unexpected login request".into()),
            (b'E', _) => return Err(error_text(&body)),
            (b'Z', _) => return Ok(s),
            _ => {}
        }
    }
}

/// Run `sql` (one statement) over `conn`, a connection to the gate's
/// proxy for the target.
pub fn query(
    conn: TcpStream,
    placeholder: &str,
    sql: &str,
    read_only: bool,
) -> Result<Outcome, String> {
    let mut s = login(conn, placeholder)?;
    if read_only {
        simple(&mut s, READ_ONLY_SET)?;
        simple(&mut s, "BEGIN READ ONLY")?;
    }
    s.write_all(&statement(sql))
        .map_err(|e| format!("database: {e}"))?;
    let mut out = Outcome::default();
    let result = until_ready(&mut s, &mut out);
    if read_only {
        let _ = simple(&mut s, "ROLLBACK");
    }
    let _ = s.write_all(&msg(b'X', &[]));
    result.map(|()| out)
}

/// Rows as `a | b` lines under a header, then the command tag.
pub fn format(o: &Outcome) -> String {
    let mut out = String::new();
    if !o.columns.is_empty() {
        out.push_str(&o.columns.join(" | "));
        out.push('\n');
        for r in &o.rows {
            let cells: Vec<&str> = r.iter().map(|c| c.as_deref().unwrap_or("NULL")).collect();
            out.push_str(&cells.join(" | "));
            out.push('\n');
        }
    }
    out.push_str(&format!("({})", o.tag));
    if o.truncated {
        out.push_str(&format!(
            " (truncated: at most {MAX_ROWS} rows are fetched)"
        ));
    }
    out
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    pub const PH: &str = "kepr-ph-0123456789abcdef-0001-00112233aabbccdd";

    fn send(s: &mut TcpStream, kind: u8, body: &[u8]) {
        s.write_all(&msg(kind, body)).unwrap();
    }

    fn tag(s: &mut TcpStream, t: &str) {
        let mut b = Vec::new();
        cstr(&mut b, t);
        send(s, b'C', &b);
    }

    fn error(s: &mut TcpStream, code: &str, m: &str) {
        let mut b = Vec::new();
        for (k, v) in [(b'S', "ERROR"), (b'C', code), (b'M', m)] {
            b.push(k);
            cstr(&mut b, v);
        }
        b.push(0);
        send(s, b'E', &b);
    }

    fn rows(s: &mut TcpStream) {
        let mut t = 2u16.to_be_bytes().to_vec();
        for name in ["id", "name"] {
            cstr(&mut t, name);
            t.extend_from_slice(&[0; 18]);
        }
        send(s, b'T', &t);
        for (id, name) in [("1", Some("alice")), ("2", None)] {
            let mut d = 2u16.to_be_bytes().to_vec();
            d.extend_from_slice(&(id.len() as i32).to_be_bytes());
            d.extend_from_slice(id.as_bytes());
            match name {
                Some(n) => {
                    d.extend_from_slice(&(n.len() as i32).to_be_bytes());
                    d.extend_from_slice(n.as_bytes());
                }
                None => d.extend_from_slice(&(-1i32).to_be_bytes()),
            }
            send(s, b'D', &d);
        }
    }

    fn text(body: &[u8]) -> String {
        String::from_utf8_lossy(body.split(|b| *b == 0).next().unwrap()).to_string()
    }

    /// A gate's PostgreSQL proxy on loopback, as the client sees it:
    /// asks for the cleartext placeholder, then answers. Reports what it
    /// was sent: `Q <sql>` for simple queries, `P <sql>` for statements.
    /// A statement containing "fail" gets an error that quotes `PH`.
    pub fn fake_gate() -> (u16, mpsc::Receiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut len = [0u8; 4];
            s.read_exact(&mut len).unwrap();
            let mut startup = vec![0u8; u32::from_be_bytes(len) as usize - 4];
            s.read_exact(&mut startup).unwrap();
            send(&mut s, b'R', &3u32.to_be_bytes());
            let (_, p) = read_msg(&mut s).unwrap();
            if text(&p) != PH {
                error(&mut s, "28P01", "kepr: invalid or missing kepr placeholder");
                return;
            }
            send(&mut s, b'R', &0u32.to_be_bytes());
            send(&mut s, b'Z', b"I");
            while let Ok((kind, body)) = read_msg(&mut s) {
                match kind {
                    b'Q' => {
                        let q = text(&body);
                        tx.send(format!("Q {q}")).unwrap();
                        tag(&mut s, q.split(' ').next().unwrap());
                        send(&mut s, b'Z', b"T");
                    }
                    b'P' => {
                        let sql = text(&body[1..]);
                        tx.send(format!("P {sql}")).unwrap();
                        send(&mut s, b'1', &[]);
                        send(&mut s, b'2', &[]);
                        if sql.contains("fail") {
                            error(&mut s, "42P01", &format!("bad password {PH}"));
                        } else {
                            rows(&mut s);
                            tag(&mut s, "SELECT 2");
                        }
                    }
                    b'S' => send(&mut s, b'Z', b"I"),
                    b'X' => return,
                    _ => {} // Bind, Describe, Execute
                }
            }
        });
        (port, rx)
    }

    fn conn(port: u16) -> TcpStream {
        TcpStream::connect(("127.0.0.1", port)).unwrap()
    }

    #[test]
    fn read_only_sets_the_session_and_wraps_the_one_statement() {
        let (port, rx) = fake_gate();
        let o = query(conn(port), PH, "select id, name from t", true).unwrap();
        assert_eq!(o.columns, ["id", "name"]);
        assert_eq!(
            o.rows,
            [
                vec![Some("1".into()), Some("alice".into())],
                vec![Some("2".into()), None]
            ]
        );
        let seen: Vec<String> = rx.iter().collect();
        assert_eq!(
            seen,
            [
                "Q SET default_transaction_read_only = on",
                "Q BEGIN READ ONLY",
                "P select id, name from t",
                "Q ROLLBACK"
            ]
        );
    }

    #[test]
    fn without_read_only_only_the_statement_runs() {
        let (port, rx) = fake_gate();
        let o = query(conn(port), PH, "select 1", false).unwrap();
        assert_eq!(o.tag, "SELECT 2");
        assert_eq!(rx.iter().collect::<Vec<_>>(), ["P select 1"]);
    }

    #[test]
    fn errors_come_back_as_text() {
        let (port, _rx) = fake_gate();
        let e = query(conn(port), PH, "select fail", false).unwrap_err();
        assert!(e.starts_with("ERROR 42P01: bad password"), "{e}");
        let (port, _rx) = fake_gate();
        let e = query(conn(port), "kepr-ph-wrong", "select 1", false).unwrap_err();
        assert!(e.contains("28P01"), "{e}");
    }

    #[test]
    fn one_statement_per_parse_message() {
        let m = statement("select 1");
        assert_eq!(m[0], b'P');
        let kinds: Vec<u8> = {
            let mut at = 0;
            let mut out = Vec::new();
            while at < m.len() {
                out.push(m[at]);
                at += 1 + u32::from_be_bytes(m[at + 1..at + 5].try_into().unwrap()) as usize;
            }
            out
        };
        assert_eq!(kinds, b"PBDES");
    }

    #[test]
    fn formats_rows_nulls_and_truncation() {
        let o = Outcome {
            columns: vec!["id".into(), "name".into()],
            rows: vec![vec![Some("1".into()), None]],
            tag: "SELECT 1".into(),
            truncated: true,
        };
        let f = format(&o);
        assert!(
            f.starts_with("id | name\n1 | NULL\n(SELECT 1) (truncated"),
            "{f}"
        );
        let o = Outcome {
            tag: "INSERT 0 1".into(),
            ..Outcome::default()
        };
        assert_eq!(format(&o), "(INSERT 0 1)");
    }
}
