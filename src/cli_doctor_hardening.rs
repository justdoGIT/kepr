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

pub(crate) fn f(name: &'static str, level: Level, detail: impl Into<String>) -> Finding {
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
            "memfd_secret available: kepr's keys are hidden from the kernel direct map; while they exist the kernel refuses hibernation (KEPR_SECRET_MEMORY=locked keeps it)",
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

/// T12.34: where the kepr AppArmor profile stands. `Loaded` means the
/// sandbox probe got its user namespace; `Installed` that the file is in
/// /etc/apparmor.d but the probe still failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Loaded,
    Installed,
    Missing,
}

const PROFILE_PATH: &str = "/etc/apparmor.d/kepr";

pub fn check_userns(
    clone_sysctl: Option<&str>,
    apparmor_restrict: Option<&str>,
    max_userns: Option<&str>,
    profile: Profile,
) -> Finding {
    if clone_sysctl.map(str::trim) == Some("0") || max_userns.map(str::trim) == Some("0") {
        return f(
            "user namespaces",
            Level::Warn,
            "unprivileged user namespaces disabled: agent sandboxes unavailable",
        );
    }
    if apparmor_restrict.map(str::trim) == Some("1") {
        let (level, detail) = match profile {
            Profile::Loaded => (
                Level::Good,
                "restricted by AppArmor; the kepr profile allows the sandbox",
            ),
            Profile::Installed => (
                Level::Warn,
                "kepr AppArmor profile installed but not loaded: sudo apparmor_parser -r /etc/apparmor.d/kepr",
            ),
            Profile::Missing => (
                Level::Warn,
                "restricted by AppArmor: install the kepr AppArmor profile",
            ),
        };
        return f("user namespaces", level, detail);
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

/// `mode` and `key_sealer` come from the daemon's status (T12.36); both are
/// None when it can't be reached, and the line then says what it always did.
pub fn check_sleep_lock(
    gdbus: bool,
    system_bus: bool,
    opted_out: bool,
    mode: Option<&str>,
    key_sealer: Option<&str>,
) -> Finding {
    if mode == Some("system") {
        f(
            "lock on sleep",
            Level::Warn,
            "the system daemon doesn't watch for suspend; root's `kepr panic` locks on demand",
        )
    } else if opted_out {
        f(
            "lock on sleep",
            Level::Warn,
            "disabled by KEPR_LOCK_ON_SLEEP=0",
        )
    } else if gdbus && system_bus && mode == Some("user") && key_sealer != Some("passphrase") {
        f(
            "lock on sleep",
            Level::Warn,
            "suspend and screen lock stop gates, but the master key stays in memory: set a passphrase (`kepr lock`)",
        )
    } else if gdbus && system_bus {
        f(
            "lock on sleep",
            Level::Good,
            "gates stop and the store locks on suspend / screen lock",
        )
    } else {
        f(
            "lock on sleep",
            Level::Warn,
            "needs gdbus and a system bus (logind) to react to suspend / screen lock",
        )
    }
}

/// T12.25: locking when a FIDO2 security key is unplugged needs udevadm;
/// a line only when it is missing (and not turned off).
pub fn check_key_removal_lock(udevadm: bool, setting: Option<&str>) -> Option<Finding> {
    (!udevadm && setting != Some("0")).then(|| {
        f(
            "lock on key removal",
            Level::Warn,
            "needs udevadm to lock when a FIDO2 security key is unplugged",
        )
    })
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

fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()))
}

/// `/sys/kernel/security/apparmor/profiles` lines read `NAME (MODE)`.
fn profile_listed(profiles: Option<&str>) -> bool {
    profiles.is_some_and(|p| {
        p.lines()
            .any(|l| l.split_whitespace().next() == Some("kepr"))
    })
}

/// Root makes user namespaces whatever AppArmor says, so its probe proves
/// nothing about the profile; only the loaded list counts then.
fn profile_from(listed: bool, root: bool, probe_ok: bool, installed: bool) -> Profile {
    if listed || (!root && probe_ok) {
        Profile::Loaded
    } else if installed {
        Profile::Installed
    } else {
        Profile::Missing
    }
}

/// Only asked when AppArmor restricts user namespaces: the probe forks a
/// sandbox, which is wasted work when nothing restricts it.
fn profile_state(restrict: Option<&str>) -> Profile {
    if restrict.map(str::trim) != Some("1") {
        return Profile::Missing;
    }
    let listed = profile_listed(read("/sys/kernel/security/apparmor/profiles").as_deref());
    // SAFETY: geteuid has no failure modes.
    let root = unsafe { libc::geteuid() } == 0;
    let probe_ok = !listed && !root && crate::cli_agent_sandbox::probe(false).is_ok();
    let installed = std::path::Path::new(PROFILE_PATH).exists();
    profile_from(listed, root, probe_ok, installed)
}

pub fn report(mode: Option<&str>, key_sealer: Option<&str>) -> Vec<Finding> {
    let restrict = read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
    let iommu = std::fs::read_dir("/sys/kernel/iommu_groups")
        .map(|d| d.count())
        .unwrap_or(0);
    let key_removal = check_key_removal_lock(
        on_path("udevadm"),
        std::env::var("KEPR_LOCK_ON_KEY_REMOVAL").ok().as_deref(),
    );
    let mut v = vec![
        check_memfd_secret(kepr_core::secmem::memfd_secret_available()),
        check_yama(read("/proc/sys/kernel/yama/ptrace_scope").as_deref()),
        check_lockdown(read("/sys/kernel/security/lockdown").as_deref()),
        check_landlock(read("/sys/kernel/security/lsm").as_deref()),
        check_userns(
            read("/proc/sys/kernel/unprivileged_userns_clone").as_deref(),
            restrict.as_deref(),
            read("/proc/sys/user/max_user_namespaces").as_deref(),
            profile_state(restrict.as_deref()),
        ),
        check_mem_encryption(read("/proc/cpuinfo").as_deref()),
        check_iommu(iommu),
        check_sleep_lock(
            on_path("gdbus"),
            std::path::Path::new("/run/dbus/system_bus_socket").exists(),
            std::env::var("KEPR_LOCK_ON_SLEEP").as_deref() == Ok("0"),
            mode,
            key_sealer,
        ),
    ];
    v.extend(key_removal);
    v.extend(crate::cli_doctor_host::report()); // T12.35
    v
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
    fn landlock_userns() {
        // T12.35: the swap check moved to cli_doctor_host.
        assert_eq!(
            check_landlock(Some("lockdown,capability,landlock,yama")).level,
            Level::Good
        );
        assert_eq!(check_landlock(Some("capability,yama")).level, Level::Warn);
        let m = || Profile::Missing;
        assert_eq!(check_userns(None, Some("1"), None, m()).level, Level::Warn);
        assert_eq!(check_userns(Some("0"), None, None, m()).level, Level::Warn);
        assert_eq!(
            check_userns(None, Some("0"), Some("63000"), m()).level,
            Level::Good
        );
    }

    /// T12.36: the line says the store locks only when it can.
    #[test]
    fn sleep_lock_cases() {
        let sys = check_sleep_lock(true, true, false, Some("system"), Some("passphrase"));
        assert_eq!(sys.level, Level::Warn);
        assert!(sys
            .detail
            .contains("system daemon doesn't watch for suspend"));
        let file = check_sleep_lock(true, true, false, Some("user"), Some("file"));
        assert_eq!(file.level, Level::Warn);
        assert!(file.detail.contains("master key stays in memory"));
        assert!(file.detail.contains("kepr lock"));
        let pass = check_sleep_lock(true, true, false, Some("user"), Some("passphrase"));
        assert_eq!(pass.level, Level::Good);
        assert_eq!(
            pass.detail,
            check_sleep_lock(true, true, false, None, None).detail
        );
        // A watcher that can't run, or is turned off, says so first.
        let no_bus = check_sleep_lock(true, false, false, Some("user"), Some("file"));
        assert!(no_bus.detail.contains("needs gdbus"), "{}", no_bus.detail);
        let off = check_sleep_lock(true, true, true, Some("user"), Some("file"));
        assert!(
            off.detail.contains("KEPR_LOCK_ON_SLEEP=0"),
            "{}",
            off.detail
        );
    }

    /// Root makes user namespaces whatever AppArmor says, so only the
    /// loaded-profile list counts for root; a user's probe counts too.
    #[test]
    fn profile_facts() {
        let list = "snap.x (enforce)\nkepr (unconfined)\n";
        assert!(profile_listed(Some(list)));
        assert!(!profile_listed(Some("kepr-other (enforce)\n")));
        assert!(!profile_listed(None));
        // (listed, root, probe ok, file installed)
        assert_eq!(profile_from(true, true, false, true), Profile::Loaded);
        assert_eq!(profile_from(false, false, true, false), Profile::Loaded);
        assert_eq!(profile_from(false, true, true, true), Profile::Installed);
        assert_eq!(profile_from(false, true, true, false), Profile::Missing);
        assert_eq!(profile_from(false, false, false, true), Profile::Installed);
    }

    #[test]
    fn userns_profile_states() {
        let r = Some("1\n");
        let loaded = check_userns(None, r, None, Profile::Loaded);
        assert_eq!(loaded.level, Level::Good);
        assert!(loaded.detail.contains("kepr profile allows the sandbox"));
        let installed = check_userns(None, r, None, Profile::Installed);
        assert_eq!(installed.level, Level::Warn);
        assert!(installed
            .detail
            .contains("sudo apparmor_parser -r /etc/apparmor.d/kepr"));
        let missing = check_userns(None, r, None, Profile::Missing);
        assert_eq!(missing.level, Level::Warn);
        assert!(missing.detail.contains("install the kepr AppArmor profile"));
        // Without the restriction the profile state doesn't matter.
        for p in [Profile::Loaded, Profile::Installed, Profile::Missing] {
            let x = check_userns(None, Some("0"), None, p);
            assert_eq!(x.level, Level::Good);
            assert_eq!(x.detail, "unprivileged user namespaces available");
        }
        // Disabled outright beats any profile.
        let off = check_userns(Some("0"), r, None, Profile::Loaded);
        assert_eq!(off.level, Level::Warn);
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
        assert!(check_memfd_secret(true)
            .detail
            .contains("KEPR_SECRET_MEMORY=locked"));
        assert_eq!(
            check_sleep_lock(true, true, false, None, None).level,
            Level::Good
        );
        assert_eq!(
            check_sleep_lock(true, true, true, None, None).level,
            Level::Warn
        );
        assert_eq!(
            check_sleep_lock(false, true, false, None, None).level,
            Level::Warn
        );
        // T12.25: only a missing udevadm is worth a line.
        assert!(check_key_removal_lock(true, None).is_none());
        assert!(check_key_removal_lock(false, Some("0")).is_none());
        let w = check_key_removal_lock(false, None).unwrap();
        assert_eq!(w.level, Level::Warn);
        assert!(w.detail.contains("udevadm"));
    }
}
