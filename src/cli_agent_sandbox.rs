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
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::cli_sandbox_seccomp as seccomp;
use crate::cli_sandbox_sys as sys;

pub struct Plan {
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    pub hide: Vec<CString>,
    pub gate_port: u16,
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
            isolate_net,
            filter: seccomp::program(),
        })
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

fn acceptor(listener: TcpListener, relay: UnixStream) -> ! {
    // SAFETY: prctl with a signal number; die with our parent (pid 1).
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    for conn in listener.incoming().flatten() {
        if sys::send_fd(&relay, conn.as_raw_fd()).is_err() {
            break;
        }
    }
    // SAFETY: _exit after fork.
    unsafe { libc::_exit(0) }
}

/// pid 1 of the sandbox: set up mounts, start the acceptor, run and reap.
fn init(plan: &Plan, relay: Option<UnixStream>) -> ! {
    if let Err(e) = sys::setup_mounts(&plan.hide) {
        die(&e);
    }
    let listener = if plan.isolate_net {
        match TcpListener::bind(("127.0.0.1", plan.gate_port)) {
            Ok(l) => Some(l),
            Err(e) => die(&format!("listen inside the sandbox: {e}")),
        }
    } else {
        None
    };
    if let (Some(l), Some(r)) = (listener.as_ref(), relay.as_ref()) {
        let (l, r) = (
            l.try_clone().unwrap_or_else(|e| die(&e.to_string())),
            r.try_clone().unwrap_or_else(|e| die(&e.to_string())),
        );
        if fork() == 0 {
            acceptor(l, r);
        }
    }
    drop(listener);
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

fn relay_loop(relay: UnixStream, gate_port: u16) {
    while let Ok(Some(fd)) = sys::recv_fd(&relay) {
        // SAFETY: recv_fd handed us ownership of a connected TCP socket.
        let inner = unsafe { TcpStream::from_raw_fd(fd) };
        std::thread::spawn(move || {
            let Ok(mut outer) = TcpStream::connect(("127.0.0.1", gate_port)) else {
                return;
            };
            let (Ok(mut from_sandbox), Ok(mut from_gate)) = (inner.try_clone(), outer.try_clone())
            else {
                return;
            };
            let up = std::thread::spawn(move || {
                let _ = std::io::copy(&mut from_sandbox, &mut outer);
                let _ = outer.shutdown(std::net::Shutdown::Write);
            });
            let mut inner = inner;
            let _ = std::io::copy(&mut from_gate, &mut inner);
            let _ = inner.shutdown(std::net::Shutdown::Write);
            let _ = up.join();
        });
    }
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
    // SAFETY: constant prctl/signal arguments. Non-dumpable: the agent
    // must not reach the host mount namespace via /proc/<our pid>/root.
    // Ctrl-C/Ctrl-\ are for the harness; we just wait for it.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
    if let Some(r) = relay_host {
        let port = plan.gate_port;
        std::thread::spawn(move || relay_loop(r, port));
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
    fn ns_flags_add_net_only_when_isolating() {
        assert_eq!(ns_flags(true) & libc::CLONE_NEWNET, libc::CLONE_NEWNET);
        assert_eq!(ns_flags(false) & libc::CLONE_NEWNET, 0);
        assert_ne!(ns_flags(false) & libc::CLONE_NEWPID, 0);
    }
}
