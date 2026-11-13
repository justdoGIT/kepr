//! Seccomp deny-list filters, shared by the agent sandbox (T1.18,
//! `src/cli_sandbox_seccomp.rs`) and kepr-gate sessions (T12.03).
//!
//! A denied syscall fails with EPERM; a foreign architecture (the x32 /
//! i386 syscall-table bypass) kills the process; everything else is
//! allowed. Installing sets PR_SET_NO_NEW_PRIVS. A filter covers the
//! calling thread and what it starts later, so install it before any
//! thread exists.

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

/// offsetof(struct seccomp_data, nr), (…, arch) and the low half of
/// (…, args[0]) on these little-endian architectures.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0_LO: u32 = 16;

/// CLONE_NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET.
/// (CLONE_NEWTIME, 0x80, is unshare / clone3 only: in clone's flags that
/// bit belongs to the exit signal.)
const CLONE_NEW_ANY: u32 = 0x7E02_0000;

/// The agent sandbox's list: reading or writing another process's
/// memory, and loading kernel programs or modules.
pub fn sandbox_denied() -> Vec<i64> {
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

/// A gate session's list: the sandbox's, plus running programs,
/// userfaultfd (a classic exploit aid), namespaces and mounts, and the
/// kernel keyring. None of these is needed to proxy requests.
pub fn gate_denied() -> Vec<i64> {
    let mut v = sandbox_denied();
    v.extend([
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_userfaultfd,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_pivot_root,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
    ]);
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

/// The BPF program: kill on a foreign arch, EPERM for `denied`, allow
/// the rest.
pub fn program(denied: &[i64]) -> Vec<libc::sock_filter> {
    build(denied, false, &[])
}

/// A gate session's program: `program(&gate_denied())`, and no new
/// namespaces through clone either (unshare alone would leave that
/// door open): clone with a CLONE_NEW* flag fails with EPERM, and
/// clone3, whose flags sit behind a pointer a filter can't read, with
/// ENOSYS, so libc falls back to clone to start threads.
pub fn gate_program() -> Vec<libc::sock_filter> {
    build(&gate_denied(), true, &[])
}

/// Socket families a private-workspace harness never needs: host or
/// abstract Unix sockets, netlink, packet and vsock. Internet families
/// stay allowed, and `socketpair` is untouched, so local IPC and the
/// loopback gate relay keep working.
pub fn workspace_denied_families() -> [i64; 4] {
    [
        libc::AF_UNIX as i64,
        libc::AF_VSOCK as i64,
        libc::AF_NETLINK as i64,
        libc::AF_PACKET as i64,
    ]
}

/// A private-workspace session's program: the sandbox list, plus
/// `socket(2)` restricted to internet families.
pub fn workspace_program() -> Vec<libc::sock_filter> {
    build(&sandbox_denied(), false, &workspace_denied_families())
}

fn build(denied: &[i64], no_new_namespaces: bool, families: &[i64]) -> Vec<libc::sock_filter> {
    use libc::{BPF_ABS, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_RET, BPF_W};
    let ld = |off| stmt(BPF_LD | BPF_W | BPF_ABS, off);
    let ret = |v| stmt(BPF_RET | BPF_K, v);
    let eq = |nr: i64, jt, jf| jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, jt, jf);
    let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
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
    if no_new_namespaces {
        p.push(eq(libc::SYS_clone3, 0, 1));
        p.push(ret(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
        // Not clone: on to the list, past the four instructions below.
        p.push(eq(libc::SYS_clone, 0, 4));
        p.push(ld(OFF_ARG0_LO));
        p.push(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEW_ANY, 0, 1));
        p.push(ret(eperm));
        p.push(ret(libc::SECCOMP_RET_ALLOW));
    }
    if !families.is_empty() {
        // socket(2) family gate. Not socket: skip the block and continue
        // with the deny list. A listed family jumps to this block's EPERM
        // return; any other family (AF_INET, AF_INET6) skips that return
        // through the JA below and reaches the deny list too, so an entry
        // for `SYS_socket` still applies.
        let n = families.len();
        p.push(eq(libc::SYS_socket, 0, (n + 3) as u8));
        p.push(ld(OFF_ARG0_LO));
        for (i, family) in families.iter().enumerate() {
            p.push(eq(*family, (n - i) as u8, 0));
        }
        p.push(jump(BPF_JMP | libc::BPF_JA | BPF_K, 1, 0, 0));
        p.push(ret(eperm));
    }

    let n = denied.len();
    for (i, nr) in denied.iter().enumerate() {
        // match → jump to the EPERM return after the remaining checks
        // and the ALLOW return.
        p.push(eq(*nr, (n - i) as u8, 0));
    }
    p.push(ret(libc::SECCOMP_RET_ALLOW));
    p.push(ret(eperm));
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
    fn private_workspace_filter_blocks_unapproved_socket_families() {
        let filter = workspace_program();
        // SAFETY: the child performs only fixed libc calls before _exit.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            if install(&filter).is_err() {
                // SAFETY: terminate only this isolated test child.
                unsafe {
                    libc::_exit(2);
                }
            }
            for family in [
                libc::AF_UNIX,
                libc::AF_VSOCK,
                libc::AF_NETLINK,
                libc::AF_PACKET,
            ] {
                // SAFETY: fixed socket arguments; no connect or external traffic.
                let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
                if fd != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                    // SAFETY: terminate only this isolated test child.
                    unsafe {
                        libc::_exit(3);
                    }
                }
            }
            // SAFETY: create an ordinary TCP socket, without connecting it.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                // SAFETY: terminate only this isolated test child.
                unsafe {
                    libc::_exit(4);
                }
            }
            // SAFETY: close the newly owned socket.
            unsafe {
                libc::close(fd);
            }
            let mut pair = [-1; 2];
            // SAFETY: socketpair writes two descriptors to a valid array; local IPC only.
            let code =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
            // SAFETY: terminate the test child, closing its local IPC descriptors.
            unsafe {
                libc::_exit(if code == 0 { 0 } else { 5 });
            }
        }
        let mut status = 0;
        // SAFETY: reap the child this test created.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn program_shape() {
        let p = program(&sandbox_denied());
        assert_eq!(
            p.last().unwrap().k,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
        );
        assert_eq!(p[p.len() - 2].k, libc::SECCOMP_RET_ALLOW);
        // every denied-syscall jump lands exactly on the EPERM return
        let eperm = p.len() - 1;
        for (i, ins) in p.iter().enumerate() {
            if sandbox_denied().contains(&(ins.k as i64)) && ins.jt > 0 {
                assert_eq!(i + 1 + ins.jt as usize, eperm, "instruction {i}");
            }
        }
    }

    #[test]
    fn gate_list_extends_sandbox_list() {
        let gate = gate_denied();
        assert!(sandbox_denied().iter().all(|nr| gate.contains(nr)));
        for nr in [
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_userfaultfd,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_pivot_root,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
        ] {
            assert!(gate.contains(&nr), "{nr}");
        }
        // Threads are started with clone: the gate must never deny it.
        assert!(!gate.contains(&libc::SYS_clone));
    }

    /// What `p` returns for a syscall: a minimal evaluator for the
    /// instructions `build` emits.
    fn eval(p: &[libc::sock_filter], arch: u32, nr: i64, arg0: u64) -> u32 {
        let (mut pc, mut acc) = (0usize, 0u32);
        loop {
            let ins = p[pc];
            let code = u32::from(ins.code);
            let jump = |taken: bool| 1 + usize::from(if taken { ins.jt } else { ins.jf });
            pc += match code {
                c if c == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS => {
                    acc = match ins.k {
                        OFF_NR => nr as u32,
                        OFF_ARCH => arch,
                        OFF_ARG0_LO => arg0 as u32,
                        k => panic!("load at {k}"),
                    };
                    1
                }
                c if c == libc::BPF_RET | libc::BPF_K => return ins.k,
                c if c == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K => jump(acc == ins.k),
                c if c == libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K => jump(acc >= ins.k),
                c if c == libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K => jump(acc & ins.k != 0),
                c if c == libc::BPF_JMP | libc::BPF_JA => 1 + ins.k as usize,
                c => panic!("opcode {c:#x}"),
            };
        }
    }

    #[test]
    fn programs_decide_as_documented() {
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let enosys = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
        let (allow, kill) = (libc::SECCOMP_RET_ALLOW, libc::SECCOMP_RET_KILL_PROCESS);
        let new_user = libc::CLONE_NEWUSER as u64 | libc::SIGCHLD as u64;
        let thread = (libc::CLONE_VM | libc::CLONE_THREAD | libc::CLONE_SIGHAND) as u64;
        let (sandbox, gate) = (program(&sandbox_denied()), gate_program());
        for p in [&sandbox, &gate] {
            assert_eq!(
                eval(p, 0x4000_0003, libc::SYS_read, 0),
                kill,
                "foreign arch"
            );
            assert_eq!(eval(p, AUDIT_ARCH, libc::SYS_read, 0), allow);
            assert_eq!(eval(p, AUDIT_ARCH, libc::SYS_clone, thread), allow);
            for nr in sandbox_denied() {
                assert_eq!(eval(p, AUDIT_ARCH, nr, 0), eperm, "{nr}");
            }
            #[cfg(target_arch = "x86_64")]
            assert_eq!(eval(p, AUDIT_ARCH, 0x4000_0000 | libc::SYS_read, 0), kill);
        }
        for nr in gate_denied() {
            assert_eq!(eval(&gate, AUDIT_ARCH, nr, 0), eperm, "{nr}");
        }
        assert_eq!(eval(&gate, AUDIT_ARCH, libc::SYS_clone, new_user), eperm);
        assert_eq!(eval(&gate, AUDIT_ARCH, libc::SYS_clone3, 0), enosys);
        // The sandbox's program is unchanged: harnesses exec and clone3.
        assert_eq!(eval(&sandbox, AUDIT_ARCH, libc::SYS_execve, 0), allow);
        assert_eq!(eval(&sandbox, AUDIT_ARCH, libc::SYS_clone3, 0), allow);
        assert_eq!(eval(&sandbox, AUDIT_ARCH, libc::SYS_clone, new_user), allow);
    }

    #[test]
    fn workspace_gate_allows_only_internet_socket_families() {
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let allow = libc::SECCOMP_RET_ALLOW;
        let workspace = workspace_program();
        for family in workspace_denied_families() {
            assert_eq!(
                eval(&workspace, AUDIT_ARCH, libc::SYS_socket, family as u64),
                eperm,
                "family {family}"
            );
        }
        for family in [libc::AF_INET as u64, libc::AF_INET6 as u64] {
            assert_eq!(
                eval(&workspace, AUDIT_ARCH, libc::SYS_socket, family),
                allow
            );
        }
        // Local IPC needs no host socket: socketpair stays allowed.
        assert_eq!(
            eval(
                &workspace,
                AUDIT_ARCH,
                libc::SYS_socketpair,
                libc::AF_UNIX as u64
            ),
            allow
        );
        // The rest of the sandbox list still applies.
        for nr in sandbox_denied() {
            assert_eq!(eval(&workspace, AUDIT_ARCH, nr, 0), eperm, "{nr}");
        }
        assert_eq!(eval(&workspace, AUDIT_ARCH, libc::SYS_execve, 0), allow);
    }

    /// Run `check` in a forked child under `prog`; its exit code.
    /// SAFETY (for callers): `check` may only make raw syscalls and read
    /// errno (async-signal-safe) — the parent has other threads.
    fn in_child(prog: &[libc::sock_filter], check: impl Fn() -> bool) -> i32 {
        in_child_code(prog, || i32::from(!check()))
    }

    /// `in_child` with `check` choosing the exit code (0 = passed);
    /// 64 when the filter could not be installed.
    fn in_child_code(prog: &[libc::sock_filter], check: impl Fn() -> i32) -> i32 {
        // SAFETY: test only; the child calls nothing but async-signal-safe functions before _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let code = match install(prog) {
                Ok(()) => check(),
                Err(_) => 64,
            };
            // SAFETY: _exit ends the forked test child without running destructors.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting for a child this code forked or spawned.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(libc::WIFEXITED(status));
        libc::WEXITSTATUS(status)
    }

    fn fails_with(r: libc::c_long, errno: i32) -> bool {
        r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(errno)
    }

    #[test]
    fn filter_blocks_ptrace_in_a_child() {
        let prog = program(&sandbox_denied());
        let code = in_child(&prog, || {
            // SAFETY: test only; ptrace with plain integer arguments, expected to be refused by the filter.
            let r = unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) };
            fails_with(r, libc::EPERM)
        });
        assert_eq!(code, 0);
    }

    #[test]
    fn gate_filter_blocks_exec_and_ptrace() {
        let prog = gate_program();
        // Not /bin/true: an exec that got through would exit 0 and pass.
        let path = c"/bin/false";
        let argv = [path.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<libc::c_char>()];
        let code = in_child(&prog, || {
            // SAFETY: test only; a valid NUL-terminated path and argv / envp arrays that end in null.
            let r = unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            let exec = fails_with(r as libc::c_long, libc::EPERM);
            // SAFETY: test only; ptrace with plain integer arguments, expected to be refused by the filter.
            let r = unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) };
            exec && fails_with(r, libc::EPERM)
        });
        assert_eq!(code, 0);
    }

    #[test]
    fn gate_filter_blocks_new_namespaces_but_not_clone() {
        let prog = gate_program();
        // SAFETY: raw syscalls only; a clone child exits at once.
        let code = in_child_code(&prog, || unsafe {
            let mut failed = 0;
            let r = libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER);
            failed |= i32::from(!fails_with(r, libc::EPERM));
            let flags = (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_ulong;
            let r = libc::syscall(libc::SYS_clone, flags, 0usize, 0usize, 0usize, 0usize);
            if r == 0 {
                libc::_exit(0);
            }
            failed |= i32::from(!fails_with(r, libc::EPERM)) << 1;
            let r = libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize);
            failed |= i32::from(!fails_with(r, libc::ENOSYS)) << 2;
            // A plain clone (fork-like here) still works.
            let flags = libc::SIGCHLD as libc::c_ulong;
            let pid = libc::syscall(libc::SYS_clone, flags, 0usize, 0usize, 0usize, 0usize);
            if pid == 0 {
                libc::_exit(0);
            }
            let mut st = 0;
            let reaped = pid > 0 && libc::waitpid(pid as i32, &mut st, 0) == pid as i32;
            failed | (i32::from(!(reaped && libc::WEXITSTATUS(st) == 0)) << 3)
        });
        assert_eq!(
            code, 0,
            "bit 0 unshare, 1 clone(NEWUSER), 2 clone3, 3 clone"
        );
    }

    #[test]
    fn workspace_filter_denies_host_socket_families_in_a_child() {
        let prog = workspace_program();
        // SAFETY: raw syscalls only; every fd is closed before _exit.
        let code = in_child_code(&prog, || unsafe {
            let mut failed = 0;
            for family in workspace_denied_families() {
                let r = libc::syscall(
                    libc::SYS_socket,
                    family,
                    libc::SOCK_STREAM as libc::c_ulong,
                    0usize,
                );
                failed |= i32::from(!fails_with(r, libc::EPERM));
            }
            // Internet families still work, as does socketpair for local IPC.
            let fd = libc::syscall(
                libc::SYS_socket,
                libc::AF_INET as libc::c_ulong,
                libc::SOCK_STREAM as libc::c_ulong,
                0usize,
            );
            failed |= i32::from(fd < 0) << 1;
            if fd >= 0 {
                libc::close(fd as i32);
            }
            let mut pair = [0i32; 2];
            let r = libc::syscall(
                libc::SYS_socketpair,
                libc::AF_UNIX as libc::c_ulong,
                libc::SOCK_STREAM as libc::c_ulong,
                0usize,
                pair.as_mut_ptr(),
            );
            if r == 0 {
                libc::close(pair[0]);
                libc::close(pair[1]);
            }
            failed |= i32::from(r != 0) << 2;
            failed
        });
        assert_eq!(code, 0, "bit 0 family, 1 AF_INET, 2 socketpair");
    }
}
