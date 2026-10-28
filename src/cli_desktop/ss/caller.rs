// cli_desktop/ss/caller.rs — who is on the other end of a call.
//
// The bus knows each connection's process (GetConnectionCredentials);
// /proc/PID knows its program and whether it lives inside another PID
// namespace (a container, or a sandbox started by `kepr agent run`). All
// of it is best effort and used for rules and the audit trail only.
//
// A process whose /proc entries cannot be read (it made itself non-dumpable,
// say) cannot be judged by its program or its sandbox: it is left without an
// `exe`, and a policy that restricts anything refuses such a caller instead
// of letting it slip past the rules that name a program.

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
        let exe = printable(self.exe.as_deref().unwrap_or("unknown program"));
        match self.pid {
            Some(p) => format!("{exe} (pid {p})"),
            None => exe,
        }
    }

    /// Do we know which program this is? Without it no rule can judge it.
    pub fn identified(&self) -> bool {
        self.exe.is_some()
    }
}

/// `s` fit for a terminal: a program's path, an item's label or an attribute
/// value is chosen by whoever made it, and may carry escape sequences.
pub fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
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

/// Is `pid` in a nested PID namespace? None if /proc cannot say.
pub fn sandboxed(pid: u32) -> Option<bool> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .map(|s| in_nested_pid_namespace(&s))
}

pub fn from_proc(name: &str, pid: u32, uid: Option<u32>) -> Caller {
    match (exe_of(pid), sandboxed(pid)) {
        (Some(exe), Some(sandboxed)) => Caller {
            name: name.into(),
            pid: Some(pid),
            uid,
            exe: Some(exe),
            sandboxed,
        },
        _ => Caller {
            pid: Some(pid),
            uid,
            ..Caller::unknown(name)
        },
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

    #[test]
    fn a_process_that_cannot_be_read_is_left_unidentified() {
        let gone = from_proc(":1.2", u32::MAX, Some(1000));
        assert!(!gone.identified());
        assert_eq!((gone.pid, gone.uid), (Some(u32::MAX), Some(1000)));
        assert!(from_proc(":1.1", std::process::id(), Some(0)).identified());
        assert_eq!(sandboxed(u32::MAX), None);
    }

    #[test]
    fn control_characters_never_reach_the_terminal() {
        assert_eq!(printable("/bin/x\x1b[2J\n\u{7}ok"), "/bin/x?[2J??ok");
        let c = Caller {
            exe: Some("/tmp/\x1b]0;pwned\x07".into()),
            ..Caller::unknown(":1.3")
        };
        assert!(!c.describe().chars().any(char::is_control));
    }
}
