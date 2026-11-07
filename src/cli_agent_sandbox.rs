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
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::cli_sandbox_relay as relay;
use crate::cli_sandbox_seccomp as seccomp;
use crate::cli_sandbox_sys as sys;

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

/// Check, in a throwaway child, that the full sandbox can be set up.
pub fn probe(isolate_net: bool) -> Result<(), String> {
    // SAFETY: getuid/getgid have no failure modes.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let hide: Vec<CString> = hide_dirs()
        .into_iter()
        .filter_map(|p| CString::new(p.as_os_str().as_encoded_bytes()).ok())
        .collect();
    let files = crate::cli_sandbox_bus::hidden_cstrings();
    let (mut rd, wr) = UnixStream::pair().map_err(|e| e.to_string())?;
    let pid = fork();
    if pid < 0 {
        return Err("fork failed".into());
    }
    if pid == 0 {
        drop(rd);
        let report = |r: Result<(), String>| {
            let msg = r.err().unwrap_or_default();
            let _ = (&wr).write_all(msg.as_bytes());
            // SAFETY: _exit after fork.
            unsafe { libc::_exit(0) }
        };
        if let Err(e) = enter_namespaces(isolate_net, uid, gid) {
            report(Err(e));
        }
        let inner = fork();
        if inner == 0 {
            let keep = [wr.as_raw_fd()]; // T12.52: a failure makes the default warn
            report(
                sys::setup_mounts(&hide)
                    .and_then(|()| sys::mask_files(&files))
                    .and_then(|()| sys::close_inherited(&keep)),
            );
        }
        wait_code(inner);
        // SAFETY: _exit after fork.
        unsafe { libc::_exit(0) }
    }
    drop(wr);
    let mut msg = String::new();
    let _ = rd.read_to_string(&mut msg);
    wait_code(pid);
    if msg.is_empty() {
        Ok(())
    } else {
        Err(msg)
    }
}

fn exec_harness(plan: &Plan) -> ! {
    // Restore the signals the sandbox's own processes ignore, so Ctrl-C
    // and Ctrl-\ reach the harness normally.
    // SAFETY: signal(2) with constant default arguments.
    unsafe {
        for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGPIPE] {
            libc::signal(sig, libc::SIG_DFL);
        }
    }
    sys::drop_all_caps();
    if let Err(e) = crate::cli_sandbox_landlock::enforce(&plan.hide) {
        die(&e); // T1.23
    }
    if let Err(e) = seccomp::install(&plan.filter) {
        die(e);
    }
    let mut argv: Vec<*const libc::c_char> = plan.argv.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = plan.envp.iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());
    // SAFETY: NUL-terminated argv/envp arrays of valid C strings that
    // outlive the call; execvpe only returns on failure.
    unsafe { libc::execvpe(argv[0], argv.as_ptr(), envp.as_ptr()) };
    die(&format!(
        "exec {}: {}",
        plan.argv[0].to_string_lossy(),
        std::io::Error::last_os_error()
    ))
}

/// pid 1 of the sandbox: set up mounts, start the acceptor, run and reap.
fn init(plan: &Plan, relay: Option<UnixStream>) -> ! {
    if let Err(e) = sys::setup_mounts(&plan.hide).and_then(|()| sys::mask_files(&plan.hide_files)) {
        die(&e);
    }
    // T12.52: no fd the caller left open reaches pid 1, the acceptors or
    // the harness; only the acceptors' relay socket is kept (dropped
    // before the harness forks). It runs before the harness's Landlock
    // and seccomp, so the filter needs no new syscall.
    let keep: Vec<RawFd> = relay.iter().map(|r| r.as_raw_fd()).collect();
    if let Err(e) = sys::close_inherited(&keep) {
        die(&e);
    }
    // One acceptor per relayed port; each hands connections to the relay.
    let ports = if plan.isolate_net {
        plan.relay_ports()
    } else {
        Vec::new()
    };
    for port in ports {
        let l = TcpListener::bind(("127.0.0.1", port))
            .unwrap_or_else(|e| die(&format!("listen inside the sandbox: {e}")));
        let r = relay.as_ref().map(|r| r.try_clone());
        let Some(Ok(r)) = r else {
            die("sandbox relay missing")
        };
        if fork() == 0 {
            relay::acceptor(l, r);
        }
    }
    drop(relay);
    let harness = fork();
    if harness == 0 {
        exec_harness(plan);
    }
    // Reap everything (we are init); exit with the harness's status.
    let code = wait_init(harness);
    // SAFETY: _exit; the kernel kills the rest of the PID namespace.
    unsafe { libc::_exit(code) }
}

/// Run the harness sandboxed; exits the process with its status.
pub fn run(plan: Plan) -> ! {
    // SAFETY: getuid/getgid have no failure modes.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
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
        if let Err(e) = enter_namespaces(plan.isolate_net, uid, gid) {
            die(&e);
        }
        let pid1 = fork();
        if pid1 == 0 {
            init(&plan, relay_sandbox);
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
    std::process::exit(wait_code(child))
}

#[cfg(test)]
#[path = "cli_agent_sandbox_tests.rs"]
mod tests;
