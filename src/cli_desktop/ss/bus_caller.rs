// cli_desktop/ss/bus_caller.rs — who is behind a bus connection.
//
// The bus daemon knows each connection's process id and user id
// (`GetConnectionCredentials`); the program and its sandbox state are read
// from /proc on every call, not cached, so a process that execs another
// program is judged by what it is now.
//
// The bus names the process that opened the connection. A child that
// inherited the socket can go on using it after that process has exited, and
// the pid may by then belong to another program. So the process is pinned by
// its start time (field 22 of /proc/PID/stat) when it is first seen, and a
// connection whose process is gone or replaced is refused (`Caller::unknown`).
// While the opener lives, a child sharing its socket is judged as the opener:
// the bus gives no finer identity.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use super::caller::{self, Caller};
use crate::cli_desktop::dbus::conn::{Conn, BUS, BUS_PATH};
use crate::cli_desktop::dbus::{Message, Value};

#[derive(Default)]
pub struct Callers {
    ids: Mutex<HashMap<String, Opener>>,
}

/// The process that opened a connection: pid, user id and start time.
type Opener = (u32, Option<u32>, u64);

/// Field 22 of a `/proc/PID/stat` line: the start time in clock ticks. The
/// command name in field 2 may hold spaces and parentheses, so the fields are
/// counted from the last `)`.
pub fn start_time(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// When process `pid` started, or None if it is gone.
pub fn proc_start(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| start_time(&s))
}

/// Process and user ids out of the `a{sv}` the bus returns.
pub fn parse_credentials(body: &[Value]) -> Option<(u32, Option<u32>)> {
    let pairs = body.first()?.pairs_sv()?;
    let get = |k: &str| {
        pairs
            .iter()
            .find(|(n, _)| n == k)
            .and_then(|(_, v)| v.unwrap_variant().as_u32())
    };
    Some((get("ProcessID")?, get("UnixUserID")))
}

impl Callers {
    /// Ask the bus once per connection. Must not run on the reader thread.
    pub fn who(&self, conn: &Conn, name: &str) -> Caller {
        let known = self
            .ids
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(name)
            .copied();
        let ids = known.or_else(|| {
            let m = Message::call(
                BUS,
                BUS_PATH,
                BUS,
                "GetConnectionCredentials",
                vec![Value::str(name)],
            );
            let r = conn.call(m, Duration::from_secs(5)).ok()?;
            let (pid, uid) = parse_credentials(&r.body)?;
            // A process already gone cannot be pinned: unknown.
            let ids = (pid, uid, proc_start(pid)?);
            self.ids
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(name.to_string(), ids);
            Some(ids)
        });
        match ids {
            // Still the process that opened the connection.
            Some((pid, uid, start)) if proc_start(pid) == Some(start) => {
                caller::from_proc(name, pid, uid)
            }
            _ => Caller::unknown(name),
        }
    }

    pub fn forget(&self, name: &str) {
        self.ids
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(name);
    }
}

/// Who owns the well-known `name` right now.
pub struct Owner {
    pub unique: String,
    pub pid: Option<u32>,
    pub exe: Option<String>,
}

impl Owner {
    pub fn describe(&self) -> String {
        match (&self.exe, self.pid) {
            (Some(e), Some(p)) => format!("{e} (pid {p})"),
            (None, Some(p)) => format!("pid {p}"),
            _ => format!("connection {}", self.unique),
        }
    }

    /// Is the owner a kepr binary?
    pub fn is_kepr(&self) -> bool {
        self.exe
            .as_deref()
            .and_then(|e| e.rsplit('/').next())
            .is_some_and(|f| f == "kepr")
    }
}

pub fn owner_of(conn: &Conn, name: &str) -> Option<Owner> {
    let ask = |member: &str, arg: &str| {
        conn.call(
            Message::call(BUS, BUS_PATH, BUS, member, vec![Value::str(arg)]),
            Duration::from_secs(5),
        )
        .ok()
    };
    let unique = ask("GetNameOwner", name)?
        .body
        .first()?
        .as_str()?
        .to_string();
    let ids = ask("GetConnectionCredentials", &unique).and_then(|r| parse_credentials(&r.body));
    let pid = ids.map(|i| i.0);
    Some(Owner {
        exe: pid.and_then(caller::exe_of),
        pid,
        unique,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_start_time_is_found_whatever_the_command_is_called() {
        let line = "4242 (evil) S 1) 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 777 23 24";
        assert_eq!(start_time(line), Some(777));
        let plain = "1 (init) S 0 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 55 1000 2 3";
        assert_eq!(start_time(plain), Some(55));
        assert_eq!(start_time("garbage"), None);
        assert_eq!(start_time("1 (x) S 0"), None);
    }

    #[test]
    fn a_process_is_pinned_by_its_start_time() {
        let me = std::process::id();
        let start = proc_start(me).expect("this process has a stat line");
        assert_eq!(proc_start(me), Some(start), "stable while it runs");
        assert_ne!(proc_start(me), Some(start + 1));
        assert_eq!(
            proc_start(u32::MAX),
            None,
            "no such process: unknown caller"
        );
    }

    #[test]
    fn ids_come_out_of_the_credentials_dictionary() {
        let d = Value::dict_sv(vec![
            ("ProcessID".into(), Value::U32(4242)),
            ("UnixUserID".into(), Value::U32(1000)),
            (
                "LinuxSecurityLabel".into(),
                Value::Bytes(b"unconfined\0".to_vec()),
            ),
        ]);
        assert_eq!(parse_credentials(&[d]), Some((4242, Some(1000))));
        let no_pid = Value::dict_sv(vec![("UnixUserID".into(), Value::U32(1000))]);
        assert_eq!(parse_credentials(&[no_pid]), None);
        assert_eq!(parse_credentials(&[]), None);
    }
}
