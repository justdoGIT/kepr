// cli_desktop/ss/caller.rs — who is on the other end of a call.
//
// The bus knows each connection's process (GetConnectionCredentials);
// /proc/PID knows its program and whether it lives inside another PID
// namespace (a container, or a sandbox started by `kepr agent run`). All
// of it is best effort and used for rules and the audit trail only.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The connection's unique bus name (`:1.42`).
    pub name: String,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub exe: Option<String>,
    /// In a PID namespace other than the server's.
    pub sandboxed: bool,
}

impl Caller {
    pub fn unknown(name: &str) -> Caller {
        Caller {
            name: name.into(),
            pid: None,
            uid: None,
            exe: None,
            sandboxed: false,
        }
    }

    /// Short text for logs: `/usr/bin/chromium (pid 1234)`.
    pub fn describe(&self) -> String {
        let exe = self.exe.as_deref().unwrap_or("unknown program");
        match self.pid {
            Some(p) => format!("{exe} (pid {p})"),
            None => exe.to_string(),
        }
    }
}

/// `/proc/PID/exe`, if it can be read.
pub fn exe_of(pid: u32) -> Option<String> {
    std::fs::read_link(PathBuf::from(format!("/proc/{pid}/exe")))
        .ok()
        .map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        })
}

/// More than one entry in the `NSpid:` line of /proc/PID/status means the
/// process is in a nested PID namespace.
pub fn in_nested_pid_namespace(status: &str) -> bool {
    status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))
        .is_some_and(|rest| rest.split_whitespace().count() > 1)
}

pub fn sandboxed(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .is_ok_and(|s| in_nested_pid_namespace(&s))
}

pub fn from_proc(name: &str, pid: u32, uid: Option<u32>) -> Caller {
    Caller {
        name: name.into(),
        pid: Some(pid),
        uid,
        exe: exe_of(pid),
        sandboxed: sandboxed(pid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_pid_namespaces_show_as_several_pids() {
        assert!(!in_nested_pid_namespace(
            "Name:\tx\nNSpid:\t1234\nNSsid:\t1\n"
        ));
        assert!(in_nested_pid_namespace("Name:\tx\nNSpid:\t1234\t7\n"));
        assert!(
            !in_nested_pid_namespace("Name:\tx\n"),
            "no NSpid line (old kernels)"
        );
    }

    #[test]
    fn this_process_is_found_in_proc() {
        let me = std::process::id();
        let c = from_proc(":1.1", me, Some(0));
        assert!(
            c.exe.as_deref().is_some_and(|e| e.contains("kepr")),
            "{:?}",
            c.exe
        );
        assert!(
            !c.sandboxed
                || std::fs::read_to_string("/proc/self/status")
                    .unwrap()
                    .matches("NSpid")
                    .count()
                    > 0
        );
        assert!(c.describe().contains(&format!("pid {me}")));
        assert_eq!(Caller::unknown(":1.9").describe(), "unknown program");
        assert_eq!(exe_of(u32::MAX), None);
    }
}
