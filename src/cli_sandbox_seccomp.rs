// cli_sandbox_seccomp.rs — seccomp filter for sandboxed agent harnesses
// (agent vault T1.18). Denies, with EPERM, the syscalls an agent could
// use to read another process's memory or load kernel programs:
// ptrace, process_vm_readv/writev, bpf, perf_event_open, kexec_*,
// init/finit_module. Everything else is allowed. Requires
// PR_SET_NO_NEW_PRIVS (set here). Debuggers (gdb, strace) stop working
// inside a sandboxed session; that is intended.
//
// The filter itself lives in kepr_core::seccomp (T12.03), shared with
// kepr-gate sessions; these wrappers keep the sandbox's names.

use kepr_core::seccomp;

pub fn denied_syscalls() -> Vec<i64> {
    seccomp::sandbox_denied()
}

/// The BPF program: kill on a foreign arch (blocks the x32 / i386
/// syscall-table bypass), EPERM for denied syscalls, allow the rest.
pub fn program() -> Vec<libc::sock_filter> {
    seccomp::program(&denied_syscalls())
}

/// A private-workspace session's program: the sandbox's, plus
/// `socket(2)` limited to internet families so no Unix, netlink,
/// packet or vsock socket can reach a host service.
pub fn workspace_program() -> Vec<libc::sock_filter> {
    seccomp::workspace_program()
}

/// Install `prog` on the calling thread (inherited across exec). Takes
/// a prebuilt program so it is safe to call between fork and exec
/// (no allocation).
pub fn install(prog: &[libc::sock_filter]) -> Result<(), &'static str> {
    seccomp::install(prog)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_shape() {
        let p = program();
        assert_eq!(
            p.last().unwrap().k,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
        );
        assert_eq!(p[p.len() - 2].k, libc::SECCOMP_RET_ALLOW);
        // every denied-syscall jump lands exactly on the EPERM return
        let eperm = p.len() - 1;
        for (i, ins) in p.iter().enumerate() {
            if denied_syscalls().contains(&(ins.k as i64)) && ins.jt > 0 {
                assert_eq!(i + 1 + ins.jt as usize, eperm, "instruction {i}");
            }
        }
    }

    #[test]
    fn filter_blocks_ptrace_in_a_child() {
        // Install in a forked child so the test process is unaffected.
        // SAFETY: the child only calls async-signal-safe functions
        // (prctl via install(), syscall, _exit) before exiting.
        let prog = program();
        // SAFETY: test only; the child calls nothing but async-signal-safe functions before _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let code = match install(&prog) {
                Ok(()) => {
                    let r =
                        // SAFETY: test only; ptrace with plain integer arguments, expected to be refused by the filter.
                        unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) };
                    let e = std::io::Error::last_os_error().raw_os_error();
                    if r == -1 && e == Some(libc::EPERM) {
                        0
                    } else {
                        1
                    }
                }
                Err(_) => 2,
            };
            // SAFETY: _exit ends the forked test child without running destructors.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting for a child this code forked or spawned.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
