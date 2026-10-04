// cli_doctor_hardening.rs — the "hardening" section of `kepr doctor`
// (agent vault plan §8, ticket T3.04). Advisory only: these checks never
// change doctor's exit status. Each check is a pure function over the
// contents of a kernel file so it can be tested with fixtures; `report`
// is the one thin I/O wrapper.

#[derive(Debug, PartialEq, Eq)]
pub enum Level {
    Good,
    Warn,
}

pub struct Finding {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
}

fn f(name: &'static str, level: Level, detail: impl Into<String>) -> Finding {
    Finding {
        name,
        level,
        detail: detail.into(),
    }
}

pub fn check_memfd_secret(available: bool) -> Finding {
    if available {
        f(
            "secret memory",
            Level::Good,
            "memfd_secret available: key pages hidden from the kernel direct map",
        )
    } else {
        f(
            "secret memory",
            Level::Warn,
            "memfd_secret unavailable: use Linux 5.14+ (or boot with secretmem.enable=1)",
        )
    }
}

pub fn check_yama(content: Option<&str>) -> Finding {
    match content.map(str::trim) {
        Some("0") => f(
            "ptrace scope",
            Level::Warn,
            "kernel.yama.ptrace_scope=0: any same-user process can attach; set 1 or 2",
        ),
        Some(v @ ("1" | "2" | "3")) => f(
            "ptrace scope",
            Level::Good,
            format!("kernel.yama.ptrace_scope={v}"),
        ),
        _ => f(
            "ptrace scope",
            Level::Warn,
            "Yama LSM not active: ptrace is limited only by dumpability",
        ),
    }
}

/// `/sys/kernel/security/lockdown` looks like `none [integrity] confidentiality`.
pub fn check_lockdown(content: Option<&str>) -> Finding {
    let mode = content
        .and_then(|c| c.split_whitespace().find(|w| w.starts_with('[')))
        .map(|w| w.trim_matches(|c| c == '[' || c == ']'));
    match mode {
        Some("confidentiality") => f(
            "kernel lockdown",
            Level::Good,
            "confidentiality: root cannot read kernel memory",
        ),
        Some("integrity") => f(
            "kernel lockdown",
            Level::Good,
            "integrity (confidentiality is stronger)",
        ),
        _ => f(
            "kernel lockdown",
            Level::Warn,
            "off: consider lockdown=confidentiality on the kernel cmdline",
        ),
    }
}

pub fn check_swap(proc_swaps: Option<&str>) -> Finding {
    let active = proc_swaps
        .map(|s| s.lines().skip(1).filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0);
    if active == 0 {
        f("swap", Level::Good, "no active swap")
    } else {
        f(
            "swap",
            Level::Warn,
            format!("{active} swap device(s) active: make sure swap is encrypted"),
        )
    }
}

pub fn check_landlock(lsm: Option<&str>) -> Finding {
    if lsm.is_some_and(|l| l.split(',').any(|m| m.trim() == "landlock")) {
        f(
            "landlock",
            Level::Good,
            "Landlock LSM active (used by agent sandboxes)",
        )
    } else {
        f(
            "landlock",
            Level::Warn,
            "Landlock LSM not active: agent sandboxes will be weaker",
        )
    }
}

pub fn check_userns(
    clone_sysctl: Option<&str>,
    apparmor_restrict: Option<&str>,
    max_userns: Option<&str>,
) -> Finding {
    if clone_sysctl.map(str::trim) == Some("0") || max_userns.map(str::trim) == Some("0") {
        return f(
            "user namespaces",
            Level::Warn,
            "unprivileged user namespaces disabled: agent sandboxes unavailable",
        );
    }
    if apparmor_restrict.map(str::trim) == Some("1") {
        return f(
            "user namespaces",
            Level::Warn,
            "restricted by AppArmor: install the kepr AppArmor profile",
        );
    }
    f(
        "user namespaces",
        Level::Good,
        "unprivileged user namespaces available",
    )
}

pub fn check_mem_encryption(cpuinfo: Option<&str>) -> Finding {
    let flags: Vec<&str> = cpuinfo
        .and_then(|c| c.lines().find(|l| l.starts_with("flags")))
        .map(|l| l.split_whitespace().collect())
        .unwrap_or_default();
    match ["tme", "sme", "sev", "sev_snp", "tdx_guest"]
        .iter()
        .find(|x| flags.contains(x))
    {
        Some(x) => f(
            "memory encryption",
            Level::Good,
            format!("CPU reports {x}: protects RAM against cold-boot and bus snooping"),
        ),
        None => f(
            "memory encryption",
            Level::Warn,
            "no TME/SME/SEV/TDX flag: enable memory encryption in firmware if supported",
        ),
    }
}

pub fn check_iommu(group_count: usize) -> Finding {
    if group_count > 0 {
        f(
            "IOMMU",
            Level::Good,
            format!("{group_count} IOMMU group(s): DMA attacks are constrained"),
        )
    } else {
        f(
            "IOMMU",
            Level::Warn,
            "no IOMMU groups: enable VT-d/AMD-Vi to block DMA attacks",
        )
    }
}

fn read(p: &str) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

pub fn report() -> Vec<Finding> {
    let iommu = std::fs::read_dir("/sys/kernel/iommu_groups")
        .map(|d| d.count())
        .unwrap_or(0);
    vec![
        check_memfd_secret(kepr_core::secmem::memfd_secret_available()),
        check_yama(read("/proc/sys/kernel/yama/ptrace_scope").as_deref()),
        check_lockdown(read("/sys/kernel/security/lockdown").as_deref()),
        check_swap(read("/proc/swaps").as_deref()),
        check_landlock(read("/sys/kernel/security/lsm").as_deref()),
        check_userns(
            read("/proc/sys/kernel/unprivileged_userns_clone").as_deref(),
            read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref(),
            read("/proc/sys/user/max_user_namespaces").as_deref(),
        ),
        check_mem_encryption(read("/proc/cpuinfo").as_deref()),
        check_iommu(iommu),
    ]
}

pub fn render(findings: &[Finding]) -> String {
    let mut s = String::from("\nHardening (advisory, does not affect the exit status):\n");
    for x in findings {
        let mark = match x.level {
            Level::Good => crate::cli_ui::color("32", "✓"),
            Level::Warn => crate::cli_ui::color("33", "!"),
        };
        s.push_str(&format!("  {mark}  {:<18} {}\n", x.name, x.detail));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yama_and_lockdown() {
        assert_eq!(check_yama(Some("0\n")).level, Level::Warn);
        assert_eq!(check_yama(Some("2\n")).level, Level::Good);
        assert_eq!(check_yama(None).level, Level::Warn);
        assert_eq!(
            check_lockdown(Some("none integrity [confidentiality]\n")).level,
            Level::Good
        );
        assert_eq!(
            check_lockdown(Some("[none] integrity confidentiality\n")).level,
            Level::Warn
        );
        assert_eq!(check_lockdown(None).level, Level::Warn);
    }

    #[test]
    fn swap_landlock_userns() {
        let header = "Filename Type Size Used Priority\n";
        assert_eq!(check_swap(Some(header)).level, Level::Good);
        assert_eq!(
            check_swap(Some(&format!("{header}/dev/sda2 partition 1 0 -2\n"))).level,
            Level::Warn
        );
        assert_eq!(
            check_landlock(Some("lockdown,capability,landlock,yama")).level,
            Level::Good
        );
        assert_eq!(check_landlock(Some("capability,yama")).level, Level::Warn);
        assert_eq!(check_userns(None, Some("1"), None).level, Level::Warn);
        assert_eq!(check_userns(Some("0"), None, None).level, Level::Warn);
        assert_eq!(
            check_userns(None, Some("0"), Some("63000")).level,
            Level::Good
        );
    }

    #[test]
    fn cpu_and_iommu() {
        assert_eq!(
            check_mem_encryption(Some("flags\t: fpu sme sev\n")).level,
            Level::Good
        );
        assert_eq!(
            check_mem_encryption(Some("flags\t: fpu sse\n")).level,
            Level::Warn
        );
        assert_eq!(check_iommu(0).level, Level::Warn);
        assert_eq!(check_iommu(3).level, Level::Good);
        assert_eq!(check_memfd_secret(true).level, Level::Good);
    }
}
