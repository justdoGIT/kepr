// daemon_memlock.rs — lock the daemon's pages into RAM so decrypted
// secret bytes never land on swap. Split out of daemon.rs (LOC ceiling).
//
// MCL_FUTURE needs a large RLIMIT_MEMLOCK: the kernel charges every new
// mapping (heap growth, each worker thread's reserved stack) against the
// limit when it is created. An unprivileged user-mode daemon typically
// has 8 MiB and could not even spawn its worker pool, so below
// FUTURE_LOCK_MIN we lock current pages only and say so; secret buffers
// get their own locked allocations (agent vault plan P3). Root keeps
// MCL_FUTURE: CAP_IPC_LOCK bypasses the limit. Soft-fails with a warning.

const MCL_CURRENT: i32 = 1;
const MCL_FUTURE: i32 = 2;
const FUTURE_LOCK_MIN: u64 = 256 * 1024 * 1024;
extern "C" {
    fn mlockall(flags: i32) -> i32;
}

fn memlock_limit() -> u64 {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the valid, stack-local `rl`.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) } != 0 {
        return 0;
    }
    rl.rlim_cur
}

pub fn lock_memory() {
    let limit = memlock_limit();
    // Root holds CAP_IPC_LOCK (kept in kepr.service's bounding set),
    // which bypasses RLIMIT_MEMLOCK entirely, so it always locks future
    // pages regardless of the configured limit.
    // SAFETY: geteuid has no failure modes.
    let privileged = unsafe { libc::geteuid() } == 0;
    let flags = if privileged || limit == libc::RLIM_INFINITY || limit >= FUTURE_LOCK_MIN {
        MCL_CURRENT | MCL_FUTURE
    } else {
        eprintln!(
            "[kepr-daemon] note: RLIMIT_MEMLOCK is {} KiB; locking current pages only",
            limit / 1024
        );
        MCL_CURRENT
    };
    // SAFETY: mlockall takes only a flags integer.
    let ret = unsafe { mlockall(flags) };
    if ret != 0 {
        eprintln!("[kepr-daemon] warning: mlockall failed — secrets may be swappable");
    }
}
