// cli_sandbox_seccomp.rs — seccomp filter for sandboxed agent harnesses
// (agent vault T1.18). Denies, with EPERM, the syscalls an agent could
// use to read another process's memory or load kernel programs:
// ptrace, process_vm_readv/writev, bpf, perf_event_open, kexec_*,
// init/finit_module. Everything else is allowed. Requires
// PR_SET_NO_NEW_PRIVS (set here). Debuggers (gdb, strace) stop working
// inside a sandboxed session; that is intended.

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

/// offsetof(struct seccomp_data, nr) and (…, arch)
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

pub fn denied_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
    ];
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_kexec_file_load);
    v
}

fn stmt(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

/// Build the BPF program: kill on a foreign arch (blocks the x32 /
/// i386 syscall-table bypass), EPERM for denied syscalls, allow the rest.
pub fn program() -> Vec<libc::sock_filter> {
    use libc::{BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W};
    let ld = |off| stmt(BPF_LD | BPF_W | BPF_ABS, off);
    let ret = |v| stmt(BPF_RET | BPF_K, v);
    let denied = denied_syscalls();
    let mut p = vec![
        ld(OFF_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0),
        ret(libc::SECCOMP_RET_KILL_PROCESS),
        ld(OFF_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // x32 ABI syscalls have bit 30 set: refuse them outright.
        p.push(jump(BPF_JMP | libc::BPF_JGE | BPF_K, 0x4000_0000, 0, 1));
        p.push(ret(libc::SECCOMP_RET_KILL_PROCESS));
    }
    let n = denied.len();
    for (i, nr) in denied.iter().enumerate() {
        // match → jump to the EPERM return after the remaining checks
        // and the ALLOW return.
        let to_deny = (n - i) as u8;
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *nr as u32, to_deny, 0));
    }
    p.push(ret(libc::SECCOMP_RET_ALLOW));
    p.push(ret(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
    p
}

/// Install `prog` on the calling thread (inherited across exec). Takes
/// a prebuilt program so it is safe to call between fork and exec
/// (no allocation).
pub fn install(prog: &[libc::sock_filter]) -> Result<(), &'static str> {
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: prctl with documented arguments; `fprog` points at `prog`,
    // which outlives the call (the kernel copies the program).
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err("cannot set no_new_privs");
        }
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &fprog as *const _,
            0,
            0,
        ) != 0
        {
            return Err("cannot install seccomp filter");
        }
    }
    Ok(())
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
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let code = match install(&prog) {
                Ok(()) => {
                    let r =
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
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
