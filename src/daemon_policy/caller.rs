// daemon_policy/caller.rs — who is asking (T6.11): the calling program,
// its parent, whether it runs inside `kepr agent run`, and which kepr
// verb a `Get` came from. Everything is read from /proc for the
// SO_PEERCRED pid, never from the request.
//
// Limits (documented in the policy guide): a field the daemon can't read
// is `None`, and a rule that names it doesn't match (deny by default).
// The system-mode unit hides other users' processes (ProtectProc=), so
// there only name / op / TTL / host rules apply. Agent detection walks
// up to MAX_DEPTH ancestors for the variables `kepr agent run` sets; a
// same-uid process that daemonises and clears them is not detected, so
// treat `agent` / `harness` as a routing aid, not an isolation boundary
// (the sandbox and sealed credentials are that).

use std::path::Path;

const MAX_DEPTH: usize = 32;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Caller {
    pub exe: Option<String>,
    pub parent: Option<String>,
    /// `Some(name)` inside an agent session (`unknown` if unnamed).
    pub harness: Option<String>,
    /// kepr verb behind a `Get`: get | exec | export.
    pub get_op: &'static str,
}

fn exe_of(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Field 4 of /proc/PID/stat (the comm field may hold spaces / parens).
pub fn parse_ppid(stat: &str) -> Option<i32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

fn ppid_of(pid: i32) -> Option<i32> {
    parse_ppid(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// The harness named by `kepr agent run`'s variables in one environ block.
pub fn harness_in_environ(environ: &[u8]) -> Option<String> {
    let mut in_session = false;
    for var in environ.split(|b| *b == 0) {
        if let Some(v) = var.strip_prefix(b"KEPR_AGENT_HARNESS=") {
            let name: String = String::from_utf8_lossy(v)
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .take(64)
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
        in_session |= var.starts_with(b"KEPR_GATE_URL=");
    }
    in_session.then(|| "unknown".to_string())
}

/// The verb a kepr CLI was run with, as a policy op.
pub fn verb_op(args: &[String]) -> &'static str {
    let mut rest = args.iter().skip(1).skip_while(|a| a.starts_with("--"));
    match rest.next().map(String::as_str) {
        Some("exec") => "exec",
        Some("env") => "export",
        Some("get") if rest.any(|a| a == "--export") => "export",
        _ => "get",
    }
}

fn cmdline_of(pid: i32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            b.split(|c| *c == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The outermost ancestor's harness: a descendant can't rename it.
fn harness_of(pid: i32) -> Option<String> {
    let mut found = None;
    let mut p = pid;
    for _ in 0..MAX_DEPTH {
        if p <= 1 {
            break;
        }
        if let Some(h) = std::fs::read(format!("/proc/{p}/environ"))
            .ok()
            .and_then(|e| harness_in_environ(&e))
        {
            found = Some(h);
        }
        match ppid_of(p) {
            Some(pp) => p = pp,
            None => break,
        }
    }
    found
}

pub fn inspect(pid: i32) -> Caller {
    let exe = exe_of(pid);
    // Only the kepr CLI's own argv is trusted to name the verb: the
    // kernel vouches for /proc/PID/exe, and kepr never rewrites argv.
    let is_cli = exe
        .as_deref()
        .and_then(|e| Path::new(e).file_name())
        .is_some_and(|n| n == "kepr");
    Caller {
        parent: ppid_of(pid).and_then(exe_of),
        harness: harness_of(pid),
        get_op: if is_cli {
            verb_op(&cmdline_of(pid))
        } else {
            "get"
        },
        exe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn verbs_map_to_ops() {
        assert_eq!(verb_op(&v(&["kepr", "get", "A"])), "get");
        assert_eq!(
            verb_op(&v(&["kepr", "--json", "get", "A", "--export"])),
            "export"
        );
        assert_eq!(
            verb_op(&v(&["kepr", "exec", "--env", "A", "--", "sh"])),
            "exec"
        );
        assert_eq!(verb_op(&v(&["kepr", "env", "--env", "A"])), "export");
        assert_eq!(verb_op(&v(&["kepr", "inject", "-i", "t"])), "get");
        assert_eq!(verb_op(&v(&["kepr"])), "get");
    }

    #[test]
    fn ppid_survives_odd_comm() {
        assert_eq!(parse_ppid("42 (a) b) S 7 42 42 0"), Some(7));
        assert_eq!(parse_ppid("garbage"), None);
    }

    #[test]
    fn harness_from_environ() {
        assert_eq!(harness_in_environ(b"A=1\0B=2\0"), None);
        assert_eq!(
            harness_in_environ(b"KEPR_GATE_URL=http://x\0"),
            Some("unknown".into())
        );
        assert_eq!(
            harness_in_environ(b"KEPR_GATE_URL=x\0KEPR_AGENT_HARNESS=claude\0"),
            Some("claude".into())
        );
        assert_eq!(
            harness_in_environ(b"KEPR_AGENT_HARNESS=a b/../c\0"),
            Some("ab..c".into())
        );
    }

    #[test]
    fn inspects_this_process() {
        let me = inspect(std::process::id() as i32);
        assert!(me.exe.is_some());
        assert!(me.parent.is_some());
        assert_eq!(me.get_op, "get"); // a test binary is not the kepr CLI
    }
}
