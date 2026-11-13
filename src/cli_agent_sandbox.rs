// cli_agent_sandbox.rs — run an agent harness inside a sandbox (agent
// vault T1.18). Process tree:
//
//   kepr (host namespaces) — non-dumpable; owns the gate (--owner-pid);
//   │                        relays sandbox connections to the gate
//   └ child: unshare(user, mount, pid[, net]); maps our own uid/gid
//      └ pid 1: private mounts; empty tmpfs over the vault, state and
//        │      socket dirs; fresh /proc (host processes invisible);
//        │      closes the caller's fds above stderr (T12.52)
//        ├ acceptor [--isolate-net]: listens on 127.0.0.1:PORT inside the
//        │   netns and hands each connection to the relay (SCM_RIGHTS)
//        └ harness: no capabilities, no_new_privs, Landlock (T1.23),
//                   seccomp filter
//
// Without --isolate-net, host networking remains available but the vault,
// daemon socket and host processes stay hidden. After the first fork,
// execution is single-threaded until exec, so allocation there is safe.

use std::ffi::CString;
use std::os::unix::net::UnixStream;

use crate::cli_sandbox_relay as relay;
use crate::cli_sandbox_seccomp as seccomp;
use crate::cli_sandbox_sys as sys;

#[path = "cli_sandbox_child.rs"]
mod child;
#[path = "cli_sandbox_probe.rs"]
mod preflight;
pub use preflight::probe;
pub(crate) use preflight::{probe_namespaces, probe_workspace};

pub struct Plan {
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    pub hide: Vec<CString>,
    /// Files covered with /dev/null: session bus and credential caches.
    pub hide_files: Vec<CString>,
    pub gate_port: u16,
    /// Database and tunnel ports (T7.03), relayed like the gate's port.
    pub extra_ports: Vec<u16>,
    pub isolate_net: bool,
    pub workspace: Option<crate::cli_sandbox_workspace::WorkspaceMounts>,
    filter: Vec<libc::sock_filter>,
}
pub use crate::cli_sandbox_dirs::hide_dirs;

fn cstrings(items: impl IntoIterator<Item = String>) -> Result<Vec<CString>, String> {
    items
        .into_iter()
        .map(|s| CString::new(s).map_err(|_| "argument or environment contains a NUL byte".into()))
        .collect()
}

impl Plan {
    pub(crate) fn private(
        argv: &[String],
        env: Vec<(String, String)>,
        gate_port: u16,
        workspace: crate::cli_sandbox_workspace::WorkspaceMounts,
    ) -> Result<Self, String> {
        crate::cli_sandbox_stdio::validate()?;
        Ok(Self {
            argv: cstrings(argv.iter().cloned())?,
            envp: cstrings(env.into_iter().map(|(k, v)| format!("{k}={v}")))?,
            hide: Vec::new(),
            hide_files: Vec::new(),
            gate_port,
            extra_ports: Vec::new(),
            isolate_net: true,
            workspace: Some(workspace),
            filter: seccomp::workspace_program(),
        })
    }
    pub fn new(
        argv: &[String],
        env: Vec<(String, String)>,
        gate_port: u16,
        isolate_net: bool,
    ) -> Result<Self, String> {
        crate::cli_sandbox_bus::warn_if_abstract(isolate_net);
        let hidden_dirs = hide_dirs();
        let hide_files = crate::cli_sandbox_auth::hidden_cstrings(&env, &hidden_dirs)?;
        let hide = hidden_dirs
            .into_iter()
            .map(|p| {
                CString::new(p.as_os_str().as_encoded_bytes()).map_err(|_| "bad path".to_string())
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            argv: cstrings(argv.iter().cloned())?,
            envp: cstrings(env.into_iter().map(|(k, v)| format!("{k}={v}")))?,
            hide,
            hide_files,
            gate_port,
            extra_ports: Vec::new(),
            isolate_net,
            workspace: None,
            filter: seccomp::program(),
        })
    }

    /// The gate's port, then the database and tunnel ports.
    fn relay_ports(&self) -> Vec<u16> {
        std::iter::once(self.gate_port)
            .chain(self.extra_ports.iter().copied())
            .collect()
    }
}

fn ns_flags(isolate_net: bool) -> libc::c_int {
    let f = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID;
    if isolate_net {
        f | libc::CLONE_NEWNET
    } else {
        f
    }
}

fn decode_status(s: libc::c_int) -> i32 {
    if libc::WIFEXITED(s) {
        libc::WEXITSTATUS(s)
    } else if libc::WIFSIGNALED(s) {
        128 + libc::WTERMSIG(s)
    } else {
        125
    }
}

fn wait_code(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    // SAFETY: waitpid on own child with a valid status pointer.
    while unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 125;
        }
    }
    decode_status(status)
}

fn wait_init(harness: libc::pid_t) -> i32 {
    let (mut status, mut code) = (0, 125);
    loop {
        // SAFETY: waitpid(-1) reaps any child or orphan in this PID namespace.
        let r = unsafe { libc::waitpid(-1, &mut status, 0) };
        if r == harness {
            code = decode_status(status);
            // SAFETY: drain any remaining exited children with WNOHANG.
            while unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } > 0 {}
            break code;
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break code;
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("kepr: sandbox: {msg}");
    // SAFETY: _exit skips destructors; correct after fork.
    unsafe { libc::_exit(125) }
}

fn fork() -> libc::pid_t {
    // SAFETY: the caller is single-threaded (see module comment).
    unsafe { libc::fork() }
}

fn parent_death() -> Result<(), String> {
    // SAFETY: constant prctl arguments; kill this trusted bridge on parent exit.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err("sandbox parent-death guard unavailable".into());
    }
    Ok(())
}

/// Enter the namespaces (in the current, already-forked process).
fn enter_namespaces(isolate_net: bool, uid: u32, gid: u32) -> Result<(), String> {
    // SAFETY: unshare takes only flags.
    if unsafe { libc::unshare(ns_flags(isolate_net)) } != 0 {
        return Err(format!("unshare: {}", std::io::Error::last_os_error()));
    }
    sys::write_id_maps(uid, gid)?;
    if isolate_net {
        sys::loopback_up()?;
    }
    Ok(())
}

fn finish_probe(msg: String, status: i32) -> Result<(), String> {
    if status != 0 {
        Err("sandbox probe process failed".into())
    } else if msg.is_empty() {
        Ok(())
    } else {
        Err(msg)
    }
}

/// Run the harness sandboxed; exits the process with its status.
pub fn run(plan: Plan) -> ! {
    std::process::exit(run_status(plan))
}

/// Return only after the namespace tree is gone, so the host can seal completion.
pub(crate) fn run_status(plan: Plan) -> i32 {
    // SAFETY: getuid/getgid have no failure modes.
    let (uid, gid, owner) = unsafe { (libc::getuid(), libc::getgid(), libc::getpid()) };
    let (relay_host, relay_sandbox) = match plan.isolate_net.then(UnixStream::pair) {
        Some(Ok((a, b))) => (Some(a), Some(b)),
        Some(Err(e)) => die(&e.to_string()),
        None => (None, None),
    };
    // Ctrl-C / Ctrl-\ are for the harness. Ignore them *before* forking
    // so the namespace child and pid 1 never die of them (that would end
    // the session and kill the gate while the harness keeps running);
    // exec_harness restores the defaults.
    // SAFETY: signal(2) with constant arguments.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
    let child = fork();
    if child < 0 {
        die("fork failed");
    }
    if child == 0 {
        drop(relay_host);
        if let Err(e) = parent_death() {
            die(&e);
        }
        // SAFETY: getppid checks the fork owner's continued presence.
        if unsafe { libc::getppid() } != owner {
            die("sandbox owner ended");
        }
        if let Err(e) = enter_namespaces(plan.isolate_net, uid, gid) {
            die(&e);
        }
        let pid1 = fork();
        if pid1 == 0 {
            if let Err(e) = parent_death() {
                die(&e);
            }
            child::init(&plan, relay_sandbox);
        }
        drop(relay_sandbox);
        let code = wait_code(pid1);
        // SAFETY: _exit after fork.
        unsafe { libc::_exit(code) }
    }
    drop(relay_sandbox);
    // SAFETY: constant prctl arguments. Non-dumpable: the agent must
    // not reach the host mount namespace via /proc/<our pid>/root.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    if let Some(r) = relay_host {
        let ports = plan.relay_ports();
        std::thread::spawn(move || relay::relay_loop(r, ports));
    }
    wait_code(child)
}

#[cfg(test)]
#[path = "cli_agent_sandbox_tests.rs"]
mod tests;
