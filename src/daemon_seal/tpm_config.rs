// daemon_seal/tpm_config.rs — environment for the TPM2 PIN / counter
// sealer (T4.08, tpm.rs).
//
// Opt in with either of
//   KEPR_TPM2_PIN=1          the sealed key also needs a PIN, read by the
//                            tools from KEPR_TPM2_PIN_FILE (an absolute
//                            path: a systemd credential, a tmpfs file
//                            written at boot, removable media), never argv;
//   KEPR_TPM2_NV_INDEX=0x…   the anti-rollback NV counter (default
//                            0x01800A11, used whenever either is set).
// KEPR_TPM2_PCRS (e.g. `7+11`) also binds the key to those PCRs, as with
// the default seal. KEPR_MASTER_KEY_SEAL must be unset or `tpm2`.
//
// KEPR_TPM2_IMAGE_NV_INDEX=0x… (T12.30, any master-key sealer) gives the
// vault image an NV counter of its own (daemon_vault/rollback.rs); it
// must not be the master key's.

use std::path::{Path, PathBuf};

pub const DEFAULT_NV_INDEX: u32 = 0x0180_0A11;
const IMAGE_VAR: &str = "KEPR_TPM2_IMAGE_NV_INDEX";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmConfig {
    /// File holding the PIN (KEPR_TPM2_PIN=1).
    pub pin_file: Option<PathBuf>,
    pub nv_index: u32,
    /// `7,11` (tpm2-tools list syntax) from KEPR_TPM2_PCRS=7+11.
    pub pcrs: Option<String>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

impl TpmConfig {
    /// The configuration, when the TPM2 PIN or counter is asked for.
    pub fn from_env(seal: Option<&str>) -> Result<Option<Self>, String> {
        let cfg = Self::parse(
            seal,
            env("KEPR_TPM2_PIN").as_deref(),
            env("KEPR_TPM2_PIN_FILE").as_deref(),
            env("KEPR_TPM2_NV_INDEX").as_deref(),
            env("KEPR_TPM2_PCRS").as_deref(),
        )?;
        if let Some(f) = cfg.as_ref().and_then(|c| c.pin_file.as_deref()) {
            check_pin_file_mode("KEPR_TPM2_PIN_FILE", f)?;
        }
        Ok(cfg)
    }

    pub fn parse(
        seal: Option<&str>,
        pin: Option<&str>,
        pin_file: Option<&str>,
        index: Option<&str>,
        pcrs: Option<&str>,
    ) -> Result<Option<Self>, String> {
        let pin = match pin {
            None | Some("0" | "no" | "false") => false,
            Some("1" | "yes" | "true") => true,
            Some(v) => return Err(format!("KEPR_TPM2_PIN={v}: use 1 or 0")),
        };
        if !pin && index.is_none() {
            return Ok(None);
        }
        if !matches!(seal, None | Some("tpm2")) {
            return Err(
                "KEPR_TPM2_PIN / KEPR_TPM2_NV_INDEX need KEPR_MASTER_KEY_SEAL=tpm2 (or unset)"
                    .into(),
            );
        }
        let pin_file = match (pin, pin_file) {
            (false, _) => None,
            (true, Some(f)) if Path::new(f).is_absolute() => Some(PathBuf::from(f)),
            (true, _) => {
                return Err(
                    "KEPR_TPM2_PIN=1 needs KEPR_TPM2_PIN_FILE, the absolute path of \
                            a file holding the PIN"
                        .into(),
                )
            }
        };
        Ok(Some(Self {
            pin_file,
            nv_index: index.map_or(Ok(DEFAULT_NV_INDEX), |v| {
                parse_index("KEPR_TPM2_NV_INDEX", v)
            })?,
            pcrs: pcrs.map(pcr_list).transpose()?,
        }))
    }
}

/// The PIN guards the key against someone holding the disk and the TPM; a
/// file other users can read gives it to them. A file that isn't there yet
/// (written at boot) is checked when it appears, by the tools' own read.
pub(super) fn check_pin_file_mode(var: &str, f: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(f) {
        Ok(m) if m.permissions().mode() & 0o077 != 0 => Err(format!(
            "{var} {} is readable by group or others; chmod 600 it",
            f.display()
        )),
        _ => Ok(()),
    }
}

/// The vault image's NV counter index, if KEPR_TPM2_IMAGE_NV_INDEX is set.
pub fn image_index_from_env() -> Result<Option<u32>, String> {
    image_index(
        env(IMAGE_VAR).as_deref(),
        env("KEPR_TPM2_PIN").as_deref(),
        env("KEPR_TPM2_NV_INDEX").as_deref(),
    )
}

/// KEPR_TPM2_IMAGE_NV_INDEX given KEPR_TPM2_PIN and KEPR_TPM2_NV_INDEX:
/// never the index the master key's counter uses.
pub fn image_index(
    image: Option<&str>,
    pin: Option<&str>,
    master: Option<&str>,
) -> Result<Option<u32>, String> {
    let Some(image) = image else {
        return Ok(None);
    };
    let index = parse_index(IMAGE_VAR, image)?;
    // As in `TpmConfig::parse`; a bad master index is reported there.
    let master = match master {
        Some(m) => parse_index("KEPR_TPM2_NV_INDEX", m).ok(),
        None => matches!(pin, Some("1" | "yes" | "true")).then_some(DEFAULT_NV_INDEX),
    };
    if master == Some(index) {
        return Err(format!(
            "{IMAGE_VAR} must differ from the master key's counter index"
        ));
    }
    Ok(Some(index))
}

fn parse_index(var: &str, v: &str) -> Result<u32, String> {
    let n = match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    };
    n.filter(|n| (0x0100_0000..=0x01FF_FFFF).contains(n))
        .ok_or_else(|| format!("{var}={v}: an NV index 0x01000000-0x01FFFFFF"))
}

/// `7+11` → `7,11`, PCRs 0-23 only.
fn pcr_list(p: &str) -> Result<String, String> {
    let nums: Option<Vec<u8>> = p
        .split('+')
        .map(|n| n.parse::<u8>().ok().filter(|n| *n <= 23))
        .collect();
    let nums = nums.ok_or_else(|| format!("KEPR_TPM2_PCRS={p}: PCR numbers 0-23 joined by '+'"))?;
    Ok(nums.iter().map(u8::to_string).collect::<Vec<_>>().join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_unless_pin_or_index_is_set() {
        assert_eq!(
            TpmConfig::parse(None, None, None, None, Some("7")),
            Ok(None)
        );
        assert_eq!(
            TpmConfig::parse(None, Some("0"), None, None, None),
            Ok(None)
        );
    }

    #[test]
    fn parses_pin_index_and_pcrs() {
        let c = TpmConfig::parse(
            Some("tpm2"),
            Some("1"),
            Some("/run/pin"),
            None,
            Some("7+11"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(c.pin_file.as_deref(), Some(Path::new("/run/pin")));
        assert_eq!(c.nv_index, DEFAULT_NV_INDEX);
        assert_eq!(c.pcrs.as_deref(), Some("7,11"));
        let c = TpmConfig::parse(None, None, None, Some("0x01800B00"), None)
            .unwrap()
            .unwrap();
        assert_eq!((c.pin_file, c.nv_index, c.pcrs), (None, 0x0180_0B00, None));
    }

    #[test]
    fn rejects_bad_settings() {
        let p = |seal, pin, file, index, pcrs| TpmConfig::parse(seal, pin, file, index, pcrs);
        assert!(p(None, Some("maybe"), None, None, None).is_err());
        assert!(p(None, Some("1"), None, None, None)
            .unwrap_err()
            .contains("KEPR_TPM2_PIN_FILE"));
        assert!(p(None, Some("1"), Some("pin.txt"), None, None).is_err());
        assert!(p(Some("host"), Some("1"), Some("/p"), None, None).is_err());
        assert!(p(Some("aws-kms:x"), None, None, Some("0x01800A11"), None).is_err());
        assert!(p(None, None, None, Some("0x81000001"), None).is_err());
        assert!(p(None, None, None, Some("zz"), None).is_err());
        assert!(p(None, None, None, Some("0x01800A11"), Some("7+24")).is_err());
    }

    #[test]
    fn the_image_counter_is_off_unless_set() {
        assert_eq!(image_index(None, None, None), Ok(None));
        assert_eq!(image_index(None, Some("1"), Some("0x01800A11")), Ok(None));
        assert_eq!(
            image_index(Some("0x01800A12"), None, None),
            Ok(Some(0x0180_0A12))
        );
        assert_eq!(
            image_index(Some("25168402"), Some("1"), None),
            Ok(Some(0x0180_0A12))
        );
    }

    #[test]
    fn the_image_counter_must_not_be_the_master_keys() {
        let refused = |image, pin, master| {
            let e = image_index(Some(image), pin, master).unwrap_err();
            assert!(
                e.contains("must differ from the master key's counter index"),
                "{e}"
            );
        };
        refused("0x01800B00", None, Some("0x01800b00"));
        refused("0x01800A11", None, Some("0x01800A11"));
        // The default index, while the PIN puts the master key on it.
        refused("0x01800A11", Some("1"), None);
        refused("0x01800a11", Some("yes"), None);
        // The default is free while the master key has no counter, or
        // has another one.
        assert_eq!(
            image_index(Some("0x01800A11"), None, None),
            Ok(Some(DEFAULT_NV_INDEX))
        );
        assert_eq!(
            image_index(Some("0x01800A11"), Some("0"), None),
            Ok(Some(DEFAULT_NV_INDEX))
        );
        assert_eq!(
            image_index(Some("0x01800A11"), Some("1"), Some("0x01800B00")),
            Ok(Some(DEFAULT_NV_INDEX))
        );
    }

    #[test]
    fn an_out_of_range_image_counter_is_refused() {
        for bad in ["0x81000001", "0x00FFFFFF", "0x02000000", "zz", "-1"] {
            let e = image_index(Some(bad), None, None).unwrap_err();
            assert!(e.starts_with("KEPR_TPM2_IMAGE_NV_INDEX="), "{bad}: {e}");
            assert!(e.contains("0x01000000-0x01FFFFFF"), "{bad}: {e}");
        }
    }

    #[test]
    fn a_pin_file_other_users_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("pin");
        std::fs::write(&f, b"123456").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = check_pin_file_mode("KEPR_TPM2_PIN_FILE", &f).unwrap_err();
        assert!(e.contains("chmod 600"), "{e}");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(check_pin_file_mode("KEPR_TPM2_PIN_FILE", &f).is_err());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_pin_file_mode("KEPR_TPM2_PIN_FILE", &f).is_ok());
        assert!(check_pin_file_mode("KEPR_TPM2_PIN_FILE", &d.path().join("not-yet")).is_ok());
    }
}
