// cli_desktop/ss/bus_caller.rs — who is behind a bus connection.
//
// The bus daemon knows each connection's process id and user id
// (`GetConnectionCredentials`); the program and its sandbox state are read
// from /proc on every call, not cached, so a process that execs another
// program is judged by what it is now.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use super::caller::{self, Caller};
use crate::cli_desktop::dbus::conn::{Conn, BUS, BUS_PATH};
use crate::cli_desktop::dbus::{Message, Value};

#[derive(Default)]
pub struct Callers {
    ids: Mutex<HashMap<String, (u32, Option<u32>)>>,
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
            let ids = parse_credentials(&r.body)?;
            self.ids
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(name.to_string(), ids);
            Some(ids)
        });
        match ids {
            Some((pid, uid)) => caller::from_proc(name, pid, uid),
            None => Caller::unknown(name),
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
