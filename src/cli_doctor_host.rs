// cli_doctor_host.rs — host items of `kepr doctor`'s hardening section
// (plan §6.2, ticket T12.35): where RAM can reach a disk (hibernation, swap)
// and whether Thunderbolt devices can read it over DMA; then (plan §8,
// T12.36) the TPM2 and Secure Boot the master key and boot chain can lean on. Advisory only, like
// the rest of the section. Pure checks over file contents; `report_at`
// reads them under a root directory so tests can use a fake /sys and /proc.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::cli_doctor_hardening::{f, Finding, Level};

/// `state` is `/sys/power/state`, `resume` is `/sys/power/resume`
/// (`MAJ:MIN`, `0:0` when unset).
pub fn check_hibernation(
    state: Option<&str>,
    resume: Option<&str>,
    resume_is_crypt: bool,
) -> Finding {
    let can_hibernate = state.is_some_and(|s| s.split_whitespace().any(|w| w == "disk"));
    if !can_hibernate {
        f("hibernation", Level::Good, "this kernel can't hibernate")
    } else if resume.map(str::trim) == Some("0:0") {
        f(
            "hibernation",
            Level::Good,
            "no resume device set (hibernating to swap: see the swap line)",
        )
    } else if resume_is_crypt {
        f("hibernation", Level::Good, "resume device is dm-crypt")
    } else {
        f(
            "hibernation",
            Level::Warn,
            "hibernation writes RAM, keys included, to an unencrypted device: encrypt it or disable hibernation",
        )
    }
}

/// `/proc/swaps`: a header line, then one device or file per line.
/// zram never leaves RAM; `is_encrypted` answers for everything else.
pub fn check_swap(proc_swaps: Option<&str>, is_encrypted: impl Fn(&str) -> bool) -> Finding {
    let plain: Vec<&str> = proc_swaps
        .map(|s| {
            s.lines()
                .skip(1)
                .filter_map(|l| l.split_whitespace().next())
                .filter(|d| !d.starts_with("/dev/zram") && !is_encrypted(d))
                .collect()
        })
        .unwrap_or_default();
    let active = proc_swaps.is_some_and(|s| s.lines().skip(1).any(|l| !l.trim().is_empty()));
    if proc_swaps.is_none() {
        // /proc/swaps exists on every Linux: unreadable is not "no swap".
        f(
            "swap",
            Level::Warn,
            "can't read /proc/swaps: swap not checked",
        )
    } else if !active {
        f("swap", Level::Good, "no active swap")
    } else if plain.is_empty() {
        f("swap", Level::Good, "all active swap is dm-crypt or zram")
    } else {
        f(
            "swap",
            Level::Warn,
            format!(
                "unencrypted swap on {}: encrypt it (dm-crypt) or use zram",
                plain.join(", ")
            ),
        )
    }
}

/// One `iommu_dma_protection` value per Thunderbolt domain; a domain whose
/// value can't be read (older kernels have none) is `unknown`, never "1".
pub fn check_thunderbolt_dma(values: &[String]) -> Finding {
    if values.is_empty() {
        f("Thunderbolt DMA", Level::Good, "no Thunderbolt controller")
    } else if values.iter().all(|v| v.trim() == "1") {
        f("Thunderbolt DMA", Level::Good, "IOMMU DMA protection on")
    } else {
        f(
            "Thunderbolt DMA",
            Level::Warn,
            "Thunderbolt DMA protection off: enable it in firmware",
        )
    }
}

fn under(root: &Path, abs: &str) -> PathBuf {
    root.join(abs.trim_start_matches('/'))
}

/// A sysfs block-device directory is encrypted when it is a dm-crypt
/// device, or when every device under it (`slaves/`) is: an LVM volume on
/// LUKS counts, a volume spanning one plain disk doesn't.
fn dir_is_crypt(dir: &Path, depth: u8) -> bool {
    let uuid = fs::read_to_string(dir.join("dm/uuid")).unwrap_or_default();
    if uuid.starts_with("CRYPT-") {
        return true;
    }
    if depth >= 8 {
        return false;
    }
    let slaves: Vec<PathBuf> = fs::read_dir(dir.join("slaves"))
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    !slaves.is_empty() && slaves.iter().all(|s| dir_is_crypt(s, depth + 1))
}

/// `/sys/dev/block/MAJ:MIN` of a resume device or a swap file's filesystem.
fn dev_is_crypt(root: &Path, maj_min: &str) -> bool {
    dir_is_crypt(&under(root, "/sys/dev/block").join(maj_min.trim()), 0)
}

/// A swap entry: `/dev/mapper/*` and `/dev/dm-N` resolve to their dm-N
/// name; a swap file is as encrypted as the filesystem holding it.
fn swap_is_crypt(root: &Path, entry: &str) -> bool {
    // /proc/swaps writes a space in a name as `\040`.
    let path = under(root, &entry.replace("\\040", " "));
    if entry.starts_with("/dev/") {
        let real = fs::canonicalize(&path).unwrap_or(path);
        let Some(name) = real.file_name() else {
            return false;
        };
        return dir_is_crypt(&under(root, "/sys/class/block").join(name), 0);
    }
    match fs::metadata(&path) {
        Ok(m) => dev_is_crypt(
            root,
            &format!("{}:{}", libc::major(m.dev()), libc::minor(m.dev())),
        ),
        Err(_) => false,
    }
}

fn thunderbolt_values(root: &Path) -> Vec<String> {
    let Ok(dir) = fs::read_dir(under(root, "/sys/bus/thunderbolt/devices")) else {
        return Vec::new();
    };
    dir.flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("domain"))
        .map(|e| {
            fs::read_to_string(e.path().join("iommu_dma_protection"))
                .unwrap_or_else(|_| "unknown".into())
        })
        .collect()
}

/// T12.36: `/sys/class/tpm/tpm0/tpm_version_major`, and whether
/// `/sys/class/tpm/tpm0/pcr-sha256` exists.
pub fn check_tpm2(version_major: Option<&str>, sha256_bank: bool) -> Finding {
    if version_major.map(str::trim) != Some("2") {
        return f(
            "TPM2",
            Level::Warn,
            "no TPM2: the master key can't be bound to this machine",
        );
    }
    let bank = if sha256_bank { ", sha256 PCR bank" } else { "" };
    f(
        "TPM2",
        Level::Good,
        format!("TPM 2.0{bank}: KEPR_MASTER_KEY_SEAL=tpm2 binds new master keys to it"),
    )
}

/// The `SecureBoot` EFI variable: 4 attribute bytes, then the value.
pub fn check_secure_boot(var: Option<&[u8]>) -> Finding {
    match var.and_then(|v| v.get(4)) {
        Some(1) => f("Secure Boot", Level::Good, "enabled"),
        Some(0) => f(
            "Secure Boot",
            Level::Warn,
            "disabled: the firmware boots unsigned kernels",
        ),
        _ => f("Secure Boot", Level::Warn, "not a UEFI boot, or unknown"),
    }
}

const SECURE_BOOT_VAR: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

pub fn report_at(root: &Path) -> Vec<Finding> {
    let read = |p: &str| fs::read_to_string(under(root, p)).ok();
    let resume = read("/sys/power/resume");
    let resume_crypt = resume.as_deref().is_some_and(|r| dev_is_crypt(root, r));
    vec![
        check_hibernation(
            read("/sys/power/state").as_deref(),
            resume.as_deref(),
            resume_crypt,
        ),
        check_swap(read("/proc/swaps").as_deref(), |d| swap_is_crypt(root, d)),
        check_thunderbolt_dma(&thunderbolt_values(root)),
        check_tpm2(
            read("/sys/class/tpm/tpm0/tpm_version_major").as_deref(),
            under(root, "/sys/class/tpm/tpm0/pcr-sha256").exists(),
        ),
        check_secure_boot(fs::read(under(root, SECURE_BOOT_VAR)).ok().as_deref()),
    ]
}

pub fn report() -> Vec<Finding> {
    report_at(Path::new("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hibernation_cases() {
        let plain = "freeze mem disk\n";
        assert_eq!(
            check_hibernation(Some("freeze mem\n"), Some("8:2\n"), false).level,
            Level::Good
        );
        assert_eq!(
            check_hibernation(Some(plain), Some("0:0\n"), false).level,
            Level::Good
        );
        assert_eq!(
            check_hibernation(Some(plain), Some("253:1\n"), true).level,
            Level::Good
        );
        let w = check_hibernation(Some(plain), Some("8:2\n"), false);
        assert_eq!(w.level, Level::Warn);
        assert!(w.detail.contains("encrypt it or disable hibernation"));
        // No /sys/power/state: this kernel can't hibernate at all.
        assert_eq!(check_hibernation(None, None, false).level, Level::Good);
    }

    #[test]
    fn swap_cases() {
        let header = "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n";
        let crypt = |d: &str| d == "/dev/dm-1";
        assert_eq!(check_swap(Some(header), crypt).level, Level::Good);
        // Unreadable is not "no swap".
        let unread = check_swap(None, crypt);
        assert_eq!(unread.level, Level::Warn);
        assert!(unread.detail.contains("swap not checked"));
        let ok = format!(
            "{header}/dev/dm-1  partition\t8388604\t0\t-2\n/dev/zram0  partition\t4194300\t0\t100\n"
        );
        assert_eq!(check_swap(Some(&ok), crypt).level, Level::Good);
        let bad = format!("{ok}/dev/sda2  partition\t1048572\t0\t-3\n");
        let w = check_swap(Some(&bad), crypt);
        assert_eq!(w.level, Level::Warn);
        assert!(w.detail.contains("/dev/sda2"), "{}", w.detail);
        assert!(!w.detail.contains("/dev/dm-1"), "{}", w.detail);
        assert!(!w.detail.contains("/dev/zram0"), "{}", w.detail);
    }

    #[test]
    fn thunderbolt_cases() {
        let v = |s: &[&str]| s.iter().map(|x| format!("{x}\n")).collect::<Vec<_>>();
        let none = check_thunderbolt_dma(&[]);
        assert_eq!(none.level, Level::Good);
        assert!(none.detail.contains("no Thunderbolt controller"));
        assert_eq!(check_thunderbolt_dma(&v(&["1"])).level, Level::Good);
        // A domain that can't be read counts against the answer.
        assert_eq!(
            check_thunderbolt_dma(&v(&["1", "unknown"])).level,
            Level::Warn
        );
        let w = check_thunderbolt_dma(&v(&["1", "0"]));
        assert_eq!(w.level, Level::Warn);
        assert!(w.detail.contains("enable it in firmware"));
    }

    #[test]
    fn tpm2_cases() {
        let both = check_tpm2(Some("2\n"), true);
        assert_eq!(both.level, Level::Good);
        assert!(both.detail.contains("sha256 PCR bank"), "{}", both.detail);
        let no_bank = check_tpm2(Some("2\n"), false);
        assert_eq!(no_bank.level, Level::Good);
        assert!(!no_bank.detail.contains("sha256"), "{}", no_bank.detail);
        for v in [Some("1\n"), None] {
            let w = check_tpm2(v, true);
            assert_eq!(w.level, Level::Warn);
            assert!(w.detail.contains("no TPM2"), "{}", w.detail);
        }
    }

    #[test]
    fn secure_boot_cases() {
        assert_eq!(check_secure_boot(Some(&[6, 0, 0, 0, 1])).level, Level::Good);
        assert_eq!(check_secure_boot(Some(&[6, 0, 0, 0, 0])).level, Level::Warn);
        let none = check_secure_boot(None);
        assert_eq!(none.level, Level::Warn);
        assert!(none.detail.contains("not a UEFI boot, or unknown"));
        // Attributes only, no value byte: unknown.
        assert_eq!(check_secure_boot(Some(&[6, 0, 0, 0])).detail, none.detail);
    }

    #[test]
    fn report_reads_tpm_and_secure_boot() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        let v = report_at(root);
        assert_eq!(level(&v, "TPM2").0, WARN);
        assert_eq!(level(&v, "Secure Boot").0, WARN);
        put(root, "sys/class/tpm/tpm0/tpm_version_major", "2\n");
        fs::create_dir_all(root.join("sys/class/tpm/tpm0/pcr-sha256")).unwrap();
        let var = "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
        fs::create_dir_all(root.join(var).parent().unwrap()).unwrap();
        fs::write(root.join(var), [6u8, 0, 0, 0, 1]).unwrap();
        let v = report_at(root);
        let (good, detail) = level(&v, "TPM2");
        assert!(good && detail.contains("sha256 PCR bank"), "{detail}");
        assert_eq!(level(&v, "Secure Boot").0, GOOD);
    }

    fn put(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn level(v: &[Finding], name: &str) -> (bool, String) {
        let x = v.iter().find(|x| x.name == name).expect(name);
        (x.level == Level::Good, x.detail.clone())
    }
    const GOOD: bool = true;
    const WARN: bool = false;

    /// An LVM volume on LUKS (Ubuntu's encrypted layout): the swap LV's
    /// uuid is `LVM-…`, its slave is the `CRYPT-…` device.
    fn lvm_on_luks(root: &Path) {
        put(
            root,
            "sys/class/block/dm-0/dm/uuid",
            "CRYPT-LUKS2-abc-dm_crypt-0\n",
        );
        put(root, "sys/class/block/dm-1/dm/uuid", "LVM-xyz\n");
        let slaves = root.join("sys/class/block/dm-1/slaves");
        fs::create_dir_all(&slaves).unwrap();
        std::os::unix::fs::symlink("../../dm-0", slaves.join("dm-0")).unwrap();
        fs::create_dir_all(root.join("dev/mapper")).unwrap();
        put(root, "dev/dm-1", "");
        std::os::unix::fs::symlink("../dm-1", root.join("dev/mapper/vg-swap")).unwrap();
        fs::create_dir_all(root.join("sys/dev/block")).unwrap();
        std::os::unix::fs::symlink("../../class/block/dm-1", root.join("sys/dev/block/253:1"))
            .unwrap();
    }

    #[test]
    fn report_reads_a_fake_root() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        lvm_on_luks(root);
        put(root, "sys/class/block/sda2/partition", "2\n");
        put(root, "dev/sda2", "");
        put(root, "sys/power/state", "freeze mem disk\n");
        put(root, "sys/power/resume", "253:1\n");
        let swaps = "Filename Type Size Used Priority\n/dev/mapper/vg-swap partition 1 0 -2\n";
        put(root, "proc/swaps", swaps);
        put(
            root,
            "sys/bus/thunderbolt/devices/domain0/iommu_dma_protection",
            "1\n",
        );
        let v = report_at(root);
        assert_eq!(level(&v, "hibernation").0, GOOD);
        assert_eq!(level(&v, "swap").0, GOOD);
        assert_eq!(level(&v, "Thunderbolt DMA").0, GOOD);

        // A plain partition next to it, a resume device that isn't crypt,
        // and a second Thunderbolt domain without protection.
        put(
            root,
            "proc/swaps",
            &format!("{swaps}/dev/sda2 partition 1 0 -3\n"),
        );
        put(root, "sys/power/resume", "8:2\n");
        put(
            root,
            "sys/bus/thunderbolt/devices/domain1/iommu_dma_protection",
            "0\n",
        );
        let v = report_at(root);
        assert_eq!(level(&v, "hibernation").0, WARN);
        let (l, detail) = level(&v, "swap");
        assert_eq!(l, WARN);
        assert!(
            detail.contains("/dev/sda2") && !detail.contains("vg-swap"),
            "{detail}"
        );
        assert_eq!(level(&v, "Thunderbolt DMA").0, WARN);
    }

    /// A swap file is as encrypted as the filesystem it lives on.
    #[test]
    fn swap_file_follows_its_filesystem() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        put(root, "swap file", "");
        let dev = fs::metadata(root.join("swap file")).unwrap().dev();
        let mm = format!("{}:{}", libc::major(dev), libc::minor(dev));
        put(
            root,
            "proc/swaps",
            "Filename Type Size Used Priority\n/swap\\040file file 1 0 -2\n",
        );
        assert_eq!(level(&report_at(root), "swap").0, WARN);
        put(
            root,
            &format!("sys/dev/block/{mm}/dm/uuid"),
            "CRYPT-PLAIN-swap\n",
        );
        assert_eq!(level(&report_at(root), "swap").0, GOOD);
    }
}
