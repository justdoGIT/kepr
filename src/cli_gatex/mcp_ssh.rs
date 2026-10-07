// cli_gatex/mcp_ssh.rs — `kepr mcp`'s ssh_run (T9.05). ssh signs with
// keys that never leave the daemon (P2.4): this process serves an
// ssh-agent socket of its own, in a private directory, whose sign
// requests go to the daemon (cli_ssh_agent.rs), and runs `ssh` with
// IdentityAgent pointing at it. Only hosts the user listed with
// `kepr mcp --ssh HOST` are reachable; ssh runs in batch mode (no prompts,
// unknown host keys refused) with forwarding and local commands off.

use std::io::Read;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cli_ssh_agent::{same_user, serve_conn, Keys};

const TIMEOUT: Duration = Duration::from_secs(120);
/// Output bytes kept per stream.
const MAX_OUT: u64 = 64 << 10;

/// `[user@]host`: letters, digits, `.`, `_`, `-` (and one `@`); never an
/// option.
pub fn valid_host(h: &str) -> bool {
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 253
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    !h.starts_with('-')
        && match h.split_once('@') {
            Some((user, host)) => ok(user) && ok(host) && !host.starts_with('-'),
            None => ok(h),
        }
}

/// The agent socket this process serves, removed with its directory on
/// drop. The accept thread keeps running until the process exits.
pub struct Agent {
    dir: PathBuf,
    pub sock: PathBuf,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn start_agent(keys: Arc<dyn Keys + Send + Sync>) -> Result<Agent, String> {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| format!("CSPRNG failure: {e}"))?;
    // The per-user runtime dir, unless the socket path would not fit a
    // sockaddr_un (108 bytes); then a fresh 0700 directory in /tmp.
    let name = format!("kepr-mcp-{}", hex::encode(rnd));
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| PathBuf::from(d).join(&name))
        .filter(|d| d.as_os_str().len() + "/agent.sock".len() < 100)
        .unwrap_or_else(|| std::env::temp_dir().join(&name));
    std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
        .create(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let sock = dir.join("agent.sock");
    let listener = UnixListener::bind(&sock).map_err(|e| format!("ssh agent: {e}"))?;
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            if same_user(&conn) {
                let keys = keys.clone();
                std::thread::spawn(move || serve_conn(conn, &*keys));
            }
        }
    });
    Ok(Agent { dir, sock })
}

/// ssh's arguments: kepr's agent only, batch mode, nothing forwarded.
pub fn ssh_args(sock: &Path, host: &str, cmd: &str) -> Vec<String> {
    let mut a: Vec<String> = vec!["-T".into()];
    for o in [
        "BatchMode=yes".to_string(),
        format!("IdentityAgent={}", sock.display()),
        "ForwardAgent=no".into(),
        "ForwardX11=no".into(),
        "ClearAllForwardings=yes".into(),
        "PermitLocalCommand=no".into(),
        "ControlMaster=no".into(),
        "ControlPath=none".into(),
        "ConnectTimeout=15".into(),
    ] {
        a.push("-o".into());
        a.push(o);
    }
    a.extend(["--".into(), host.into(), cmd.into()]);
    a
}

fn collect(r: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(r) = r {
            let _ = r.take(MAX_OUT).read_to_end(&mut buf);
        }
        String::from_utf8_lossy(&buf).to_string()
    })
}

/// Run `program args`, stdin closed, killed after `timeout`: the exit
/// status with stdout and stderr.
pub fn run(program: &Path, args: &[String], timeout: Duration) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", program.display()))?;
    let (out, err) = (collect(child.stdout.take()), collect(child.stderr.take()));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(e.to_string()),
        }
    };
    let (out, err) = (
        out.join().unwrap_or_default(),
        err.join().unwrap_or_default(),
    );
    let head = match status.and_then(|s| s.code()) {
        Some(c) => format!("exit {c}"),
        None if status.is_none() => format!("timed out after {}s", timeout.as_secs()),
        None => "killed by a signal".into(),
    };
    Ok(format!("{head}\n--- stdout\n{out}\n--- stderr\n{err}"))
}

/// ssh_run for `host` (already checked against the allowed list),
/// starting the agent socket on first use.
pub fn ssh_run(
    agent: &mut Option<Agent>,
    keys: impl FnOnce() -> Arc<dyn Keys + Send + Sync>,
    program: &Path,
    host: &str,
    cmd: &str,
) -> Result<String, String> {
    if agent.is_none() {
        *agent = Some(start_agent(keys())?);
    }
    let sock = &agent.as_ref().expect("just started").sock;
    run(program, &ssh_args(sock, host, cmd), TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::protocol::SshKeyInfo;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;

    struct FakeKeys;
    impl Keys for FakeKeys {
        fn list(&self) -> Result<Vec<SshKeyInfo>, String> {
            Ok(vec![SshKeyInfo {
                name: "DEPLOY".into(),
                public_b64: kepr_core::ssh_wire::b64(b"public-blob"),
                comment: "deploy key".into(),
            }])
        }
        fn sign(&self, _: &str, _: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b"sig".to_vec())
        }
    }

    #[test]
    fn hosts() {
        for ok in ["web1", "deploy@web1.example.com", "a-b_c.d"] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in [
            "",
            "-oProxyCommand=x",
            "u@-x",
            "a b",
            "h;rm",
            "@h",
            "u@",
            "h:22",
            "a@b@c",
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
    }

    #[test]
    fn ssh_uses_only_kepr_s_agent_and_forwards_nothing() {
        let a = ssh_args(Path::new("/run/x/agent.sock"), "deploy@web1", "uptime");
        let opts: Vec<&str> = a.iter().map(String::as_str).collect();
        for o in [
            "BatchMode=yes",
            "IdentityAgent=/run/x/agent.sock",
            "ForwardAgent=no",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "ControlPath=none",
        ] {
            assert!(opts.contains(&o), "{o}");
        }
        assert_eq!(&opts[opts.len() - 3..], ["--", "deploy@web1", "uptime"]);
    }

    #[test]
    fn runs_with_status_output_and_a_timeout() {
        let sh = Path::new("/bin/sh");
        let args = |s: &str| vec!["-c".to_string(), s.to_string()];
        let out = run(sh, &args("echo out; echo err >&2; exit 3"), TIMEOUT).unwrap();
        assert_eq!(out, "exit 3\n--- stdout\nout\n\n--- stderr\nerr\n");
        let slow = run(sh, &args("sleep 5"), Duration::from_millis(200)).unwrap();
        assert!(slow.starts_with("timed out"), "{slow}");
        assert!(run(Path::new("/nonexistent/ssh"), &[], TIMEOUT).is_err());
    }

    #[test]
    fn the_agent_socket_is_private_and_answers_from_the_daemon_keys() {
        let agent = start_agent(Arc::new(FakeKeys)).unwrap();
        let dir = agent.sock.parent().unwrap().to_path_buf();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let mut s = UnixStream::connect(&agent.sock).unwrap();
        s.write_all(&[0, 0, 0, 1, 11]).unwrap(); // REQUEST_IDENTITIES
        let mut len = [0u8; 4];
        s.read_exact(&mut len).unwrap();
        let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut reply).unwrap();
        assert_eq!(reply[0], 12, "IDENTITIES_ANSWER");
        assert!(reply.windows(11).any(|w| w == b"public-blob"));
        drop(agent);
        assert!(!dir.exists());
    }
}
