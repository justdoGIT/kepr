//! Namespace PID 1, relayed listeners, and the restricted harness child.

use super::{die, fork, wait_init, Plan};
use crate::cli_sandbox_relay as relay;
use crate::cli_sandbox_seccomp as seccomp;
use crate::cli_sandbox_sys as sys;
use std::net::TcpListener;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

fn exec_harness(
    plan: &Plan,
    workspace: Option<&kepr_core::workspace_policy::FilesystemPolicy>,
) -> ! {
    // Restore the signals the sandbox's own processes ignore, so Ctrl-C
    // and Ctrl-\ reach the harness normally.
    // SAFETY: signal(2) with constant default arguments.
    unsafe {
        for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGPIPE] {
            libc::signal(sig, libc::SIG_DFL);
        }
    }
    sys::drop_all_caps();
    let restricted = match workspace {
        Some(policy) => crate::cli_sandbox_workspace::restrict(policy),
        None => crate::cli_sandbox_landlock::enforce(&plan.hide),
    };
    if let Err(e) = restricted {
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
pub(super) fn init(plan: &Plan, relay: Option<UnixStream>) -> ! {
    if plan.workspace.is_some() {
        if let Err(e) = crate::cli_sandbox_stdio::validate() {
            die(e);
        }
    }
    if plan.workspace.is_some() && (!plan.isolate_net || !plan.extra_ports.is_empty()) {
        die("private workspace requires isolated networking and inspected gate routes");
    }
    // SAFETY: constant prctl and umask arguments, before untrusted execution.
    let guarded = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if guarded != 0 {
        die("sandbox process guard unavailable");
    }
    // SAFETY: owner-only creation mode for all subsequently executed tools.
    unsafe {
        libc::umask(0o077);
    }
    let workspace = match plan.workspace.as_ref() {
        Some(private) => {
            Some(crate::cli_sandbox_workspace::setup(private).unwrap_or_else(|e| die(&e)))
        }
        None => {
            if let Err(e) =
                sys::setup_mounts(&plan.hide).and_then(|()| sys::mask_files(&plan.hide_files))
            {
                die(&e);
            }
            None
        }
    };
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
        exec_harness(plan, workspace.as_ref());
    }
    // Reap everything (we are init); exit with the harness's status.
    let code = wait_init(harness);
    // SAFETY: _exit; the kernel kills the rest of the PID namespace.
    unsafe { libc::_exit(code) }
}
