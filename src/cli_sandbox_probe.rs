//! Throwaway preflight children; never start a gate or a harness here.

use super::{enter_namespaces, finish_probe, fork, hide_dirs, wait_code};
use crate::cli_sandbox_sys as sys;
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

/// Check, in a throwaway child, that the full sandbox can be set up.
pub fn probe(isolate_net: bool) -> Result<(), String> {
    let hide: Vec<CString> = hide_dirs()
        .into_iter()
        .filter_map(|p| CString::new(p.as_os_str().as_encoded_bytes()).ok())
        .collect();
    let files = crate::cli_sandbox_bus::hidden_cstrings();
    check(isolate_net, || {
        sys::setup_mounts(&hide).and_then(|()| sys::mask_files(&files))?;
        Ok(None)
    })
}

pub(crate) fn probe_namespaces() -> Result<(), String> {
    check(true, || Ok(None))
}

pub(crate) fn probe_workspace(
    workspace: &crate::cli_sandbox_workspace::WorkspaceMounts,
) -> Result<(), String> {
    if !kepr_core::workspace_policy::capability().filesystem_restriction_available {
        return Err("private workspace requires Landlock ABI 3 or newer".into());
    }
    check(true, || {
        crate::cli_sandbox_workspace::setup(workspace).map(Some)
    })
}

fn check(
    isolate_net: bool,
    setup: impl Fn() -> Result<Option<kepr_core::workspace_policy::FilesystemPolicy>, String>,
) -> Result<(), String> {
    // SAFETY: identity reads have no arguments or failure mode.
    let (uid, gid, parent) = unsafe { (libc::getuid(), libc::getgid(), libc::getpid()) };
    let (mut rd, wr) = UnixStream::pair().map_err(|e| e.to_string())?;
    rd.set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .map_err(|_| "sandbox probe timeout setup failed")?;
    let pid = fork();
    if pid < 0 {
        return Err("fork failed".into());
    }
    if pid == 0 {
        drop(rd);
        let report = |r: Result<(), String>| {
            let msg = r.err().unwrap_or_default();
            let code = if (&wr).write_all(msg.as_bytes()).is_ok() {
                0
            } else {
                125
            };
            // SAFETY: _exit after fork.
            unsafe { libc::_exit(code) }
        };
        if let Err(e) = super::parent_death() {
            report(Err(e));
        }
        // SAFETY: getppid has no preconditions; detects an already-dead parent.
        if unsafe { libc::getppid() } != parent {
            report(Err("sandbox probe owner ended".into()));
        }
        if let Err(e) = enter_namespaces(isolate_net, uid, gid) {
            report(Err(e));
        }
        let inner = fork();
        if inner < 0 {
            report(Err("sandbox probe fork failed".into()));
        }
        if inner == 0 {
            if let Err(e) = super::parent_death() {
                report(Err(e));
            }
            let keep = [wr.as_raw_fd()]; // T12.52: a failure makes the default warn
            report(setup().and_then(|policy| {
                sys::close_inherited(&keep)?;
                if let Some(policy) = policy {
                    sys::drop_all_caps();
                    crate::cli_sandbox_workspace::restrict(&policy)?;
                    crate::cli_sandbox_seccomp::install(
                        &crate::cli_sandbox_seccomp::workspace_program(),
                    )
                    .map_err(String::from)?;
                }
                Ok(())
            }));
        }
        if wait_code(inner) != 0 {
            report(Err("sandbox probe child failed".into()));
        }
        // SAFETY: _exit after fork.
        unsafe { libc::_exit(0) }
    }
    drop(wr);
    let mut msg = String::new();
    let read = rd.read_to_string(&mut msg);
    if read.is_err() {
        // SAFETY: kill only our own throwaway child; its PID 1 has PDEATHSIG.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    let status = wait_code(pid);
    if read.is_err() {
        return Err("sandbox probe communication failed".into());
    }
    finish_probe(msg, status)
}
