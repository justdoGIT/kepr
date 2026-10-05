// cli_agent_sandbox.rs — run an agent harness inside a sandbox (agent
// vault T1.18). Process tree:
//
//   kepr (host namespaces) — non-dumpable; owns the gate (--owner-pid);
//   │                        relays sandbox connections to the gate
//   └ child: unshare(user, mount, pid[, net]); maps our own uid/gid
//      └ pid 1: private mounts; empty tmpfs over the vault, state and
//        │      socket dirs; fresh /proc (host processes invisible)
//        ├ acceptor [--isolate-net]: listens on 127.0.0.1:PORT inside the
//        │   netns and hands each connection to the relay (SCM_RIGHTS)
//        └ harness: no capabilities, no_new_privs, seccomp filter
//
// Without --isolate-net the harness keeps host networking (package
// installs keep working) but still cannot see the vault, the daemon
// socket or any host process. Everything after the first fork runs
// single-threaded until exec, so allocation there is safe.

use std::ffi::CString;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::cli_sandbox_relay as relay;
use crate::cli_sandbox_seccomp as seccomp;
use crate::cli_sandbox_sys as sys;

pub struct Plan {
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    pub hide: Vec<CString>,
    pub gate_port: u16,
    /// Database and tunnel ports (T7.03), relayed like the gate's port.
    pub extra_ports: Vec<u16>,
    pub isolate_net: bool,
    filter: Vec<libc::sock_filter>,
}

fn base(var: &str, default_rel: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(default_rel)))
}

/// Directories the agent must not see: credential store, daemon state
/// (master key, audit log), the daemon socket, and the system-mode paths.
pub fn hide_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [
        base("XDG_DATA_HOME", ".local/share"),
        base("XDG_STATE_HOME", ".local/state"),
    ]
    .into_iter()
    .flatten()
    .map(|b| b.join("kepr"))
    .collect();
    v.push(kepr_core::protocol::socket_dir());
    v.extend(["/etc/credstore.encrypted", "/var/lib/kepr", "/run/kepr"].map(PathBuf::from));
    v.sort();
    v.dedup();
    v.into_iter().filter(|p| p.is_dir()).collect()
}

fn cstrings(items: impl IntoIterator<Item = String>) -> Result<Vec<CString>, String> {
    items
        .into_iter()
        .map(|s| {
            CString::new(s).map_err(|_| "argument or environment contains a NUL byte".to_string())
        })
        .collect()
}

impl Plan {
    pub fn new(
        argv: &[String],
        env: Vec<(String, String)>,
        gate_port: u16,
        isolate_net: bool,
    ) -> Result<Self, String> {
        let hide = hide_dirs()
            .into_iter()
            .map(|p| {
                CString::new(p.as_os_str().as_encoded_bytes()).map_err(|_| "bad path".to_string())
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            argv: cstrings(argv.iter().cloned())?,
            envp: cstrings(env.into_iter().map(|(k, v)| format!("{k}={v}")))?,
            hide,
            gate_port,
            extra_ports: Vec::new(),
            isolate_net,
            filter: seccomp::program(),
        })
    }
}

impl Plan {
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

fn wait_code(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        // SAFETY: waitpid on our own child with a valid status pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            break;
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 125;
        }
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        125
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
            report(sys::setup_mounts(&hide));
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
    // SAFETY: signal(2) with constant arguments.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGQUIT, libc::SIG_DFL);
    }
    sys::drop_all_caps();
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
    if let Err(e) = sys::setup_mounts(&plan.hide) {
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
    let code = wait_code(harness);
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
mod tests {
    use super::*;

    #[test]
    fn hide_dirs_only_existing_and_include_socket_dir_when_present() {
        for d in hide_dirs() {
            assert!(d.is_dir(), "{}", d.display());
        }
    }

    #[test]
    fn relays_the_gate_port_then_database_and_tunnel_ports() {
        let mut plan = Plan::new(&["true".into()], vec![], 7000, true).unwrap();
        assert_eq!(plan.relay_ports(), vec![7000]);
        plan.extra_ports = vec![7001, 7002];
        assert_eq!(plan.relay_ports(), vec![7000, 7001, 7002]);
    }

    #[test]
    fn ns_flags_add_net_only_when_isolating() {
        assert_eq!(ns_flags(true) & libc::CLONE_NEWNET, libc::CLONE_NEWNET);
        assert_eq!(ns_flags(false) & libc::CLONE_NEWNET, 0);
        assert_ne!(ns_flags(false) & libc::CLONE_NEWPID, 0);
    }
}
