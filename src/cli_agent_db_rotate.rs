// cli_agent_db_rotate.rs — `kepr agent rotate-db NAME [--abort]` (agent
// vault P7.2): change a sealed PostgreSQL (or, T7.04, MySQL) login's
// password without anyone seeing either the old or the new one.
//
//   1. the daemon adds a random `pending_password` to the record (or keeps
//      the one an unfinished run left);
//   2. a gate is started for this one database; we log in through it with
//      the `kepr_rotate` startup parameter, and the gate runs
//      `ALTER ROLE CURRENT_USER PASSWORD '<SCRAM verifier>'` upstream
//      (MySQL: user `kepr_rotate`, cli_gatex/mysql_login.rs, and
//      `ALTER USER CURRENT_USER() IDENTIFIED BY …`);
//   3. on success the daemon commits the pending password.
//
// A failure leaves the pending password in place, so running the command
// again resumes safely, whether or not the server already changed.
// `--abort` drops the pending password, but only after a normal login
// through the gate proves the server still takes the current one.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use kepr_core::gate_protocol::{db_route_key, GateLimits, TargetKind};
use kepr_core::protocol::{Request, Response};

use crate::{cli_ui, client};

const USAGE: &str = "usage: kepr agent rotate-db NAME [--abort]";
const PROTOCOL_3: u32 = 196_608;

fn phase(name: &str, phase: &str) -> Result<(), String> {
    match client::send_request(&Request::DbRotate {
        name: name.into(),
        phase: phase.into(),
    })? {
        Response::DbRotateOk { .. } => Ok(()),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// StartupMessage for the gate; `rotate` adds `kepr_rotate=1`.
pub fn startup(rotate: bool) -> Vec<u8> {
    let mut body = PROTOCOL_3.to_be_bytes().to_vec();
    let kv: &[&str] = if rotate {
        &["user", "kepr", "database", "kepr", "kepr_rotate", "1"]
    } else {
        &["user", "kepr", "database", "kepr"]
    };
    for kv in kv {
        body.extend_from_slice(kv.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut out = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

fn read_msg(s: &mut impl Read) -> Result<(u8, Vec<u8>), String> {
    let mut head = [0u8; 5];
    s.read_exact(&mut head).map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(head[1..].try_into().expect("4 bytes")) as usize;
    if !(4..=1 << 20).contains(&len) {
        return Err("malformed reply from the gate".into());
    }
    let mut body = vec![0u8; len - 4];
    s.read_exact(&mut body).map_err(|e| e.to_string())?;
    Ok((head[0], body))
}

/// The `M` field of an ErrorResponse.
pub fn error_text(body: &[u8]) -> String {
    body.split(|b| *b == 0)
        .find_map(|f| f.strip_prefix(b"M"))
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .unwrap_or_else(|| "the database refused".into())
}

/// Log in through the gate; Ok at ReadyForQuery. With `rotate`, that
/// means the server now has the pending password; without, that the
/// current password still works.
pub fn drive(s: &mut (impl Read + Write), placeholder: &str, rotate: bool) -> Result<(), String> {
    s.write_all(&startup(rotate)).map_err(|e| e.to_string())?;
    loop {
        match read_msg(s)? {
            (b'R', b) if b.get(..4) == Some(&3u32.to_be_bytes()[..]) => {
                let mut p = placeholder.as_bytes().to_vec();
                p.push(0);
                s.write_all(&message(b'p', &p)).map_err(|e| e.to_string())?;
            }
            (b'E', b) => return Err(error_text(&b)),
            (b'Z', _) => return Ok(()),
            _ => {}
        }
    }
}

/// A gate for this one database: (placeholder, loopback port, kind).
fn start_gate(name: &str) -> Result<(String, u16, TargetKind), String> {
    let creds = crate::cli_agent_run::sealed_creds()?;
    let mine: Vec<_> = creds.into_iter().filter(|c| c.name == name).collect();
    let mut routes = crate::cli_agent_db::routes(&[], &mine);
    let mut kind = TargetKind::Postgres;
    for r in &mut routes {
        if let Some(t) = &mut r.target {
            t.rotate = true;
            kind = t.kind;
        }
    }
    if routes.is_empty() {
        return Err(format!(
            "{name} is not a sealed database login (kepr agent add-db)"
        ));
    }
    if !matches!(kind, TargetKind::Postgres | TargetKind::Mysql) {
        return Err(format!(
            "{name}: only PostgreSQL and MySQL logins can be rotated"
        ));
    }
    let key = db_route_key(name);
    let (ph, port) = match client::send_request(&Request::StartGate {
        privacy: None,
        routes,
        port: None,
        limits: GateLimits::default(),
        tunnel: false,
        record: false,
        harness: None, // T7.10: no harness, so no just-in-time credential
    })? {
        Response::GateStarted {
            placeholders,
            extras,
            ..
        } => (
            placeholders.get(&key).cloned(),
            extras.db_ports.get(&key).copied(),
        ),
        Response::Err { error } => return Err(error),
        _ => return Err("unexpected daemon response".into()),
    };
    ph.zip(port)
        .map(|(ph, port)| (ph, port, kind))
        .ok_or_else(|| "the gate did not open a database port".into())
}

fn login(name: &str, rotate: bool) -> Result<(), String> {
    let (ph, port, kind) = start_gate(name)?;
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| e.to_string())?;
    match kind {
        TargetKind::Mysql => crate::cli_gatex::mysql_login::drive(&mut s, &ph, rotate),
        _ => drive(&mut s, &ph, rotate),
    }
}

fn rotate(name: &str) -> Result<(), String> {
    start_gate(name)?; // fail early, before a pending password exists
    phase(name, "begin")?;
    login(name, true).map_err(|e| {
        format!("{e}\nthe new password is kept pending; run the command again to finish (safe whether or not the server already changed)")
    })?;
    phase(name, "commit")
}

/// Drop a pending password, but only while the current one still works.
fn abort(name: &str) -> Result<(), String> {
    login(name, false).map_err(|e| {
        format!("{e}\nthe server no longer takes the current password, so the pending one is probably in effect: run `kepr agent rotate-db {name}` to finish instead")
    })?;
    phase(name, "abort")
}

pub fn cmd_rotate_db(args: &[String]) -> Response {
    let Some(name) = args.first().filter(|a| !a.starts_with('-')) else {
        return Response::fail(USAGE);
    };
    let name = name.to_uppercase();
    if args.iter().any(|a| a == "--abort") {
        return match abort(&name) {
            Ok(()) => {
                cli_ui::ok(&format!("{name}: pending password dropped"));
                Response::DbRotateOk {
                    name,
                    phase: "abort".into(),
                }
            }
            Err(e) => Response::fail(e),
        };
    }
    match rotate(&name) {
        Ok(()) => {
            cli_ui::ok(&format!(
                "{name}: database password rotated; the old one no longer works"
            ));
            Response::DbRotateOk {
                name,
                phase: "commit".into(),
            }
        }
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Duplex {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn startup_carries_the_rotate_flag() {
        let s = startup(true);
        assert_eq!(
            u32::from_be_bytes(s[..4].try_into().unwrap()) as usize,
            s.len()
        );
        assert_eq!(&s[4..8], &PROTOCOL_3.to_be_bytes());
        assert!(s.windows(14).any(|w| w == b"kepr_rotate\x001\x00"));
        assert!(!startup(false).windows(11).any(|w| w == b"kepr_rotate"));
    }

    #[test]
    fn answers_cleartext_auth_with_the_placeholder() {
        let input = [
            message(b'R', &3u32.to_be_bytes()),
            message(b'R', &0u32.to_be_bytes()),
            message(b'Z', b"I"),
        ]
        .concat();
        let mut d = Duplex {
            input: Cursor::new(input),
            output: Vec::new(),
        };
        drive(&mut d, "kepr-ph-1", true).unwrap();
        assert!(d.output.ends_with(&message(b'p', b"kepr-ph-1\0")));
    }

    #[test]
    fn reports_the_server_error() {
        let mut d = Duplex {
            input: Cursor::new(message(b'E', b"SFATAL\0C28000\0Mkepr rotate: nope\0\0")),
            output: Vec::new(),
        };
        assert_eq!(drive(&mut d, "x", true).unwrap_err(), "kepr rotate: nope");
    }
}
