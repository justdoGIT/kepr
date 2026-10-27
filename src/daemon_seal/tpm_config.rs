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

use std::path::{Path, PathBuf};

pub const DEFAULT_NV_INDEX: u32 = 0x0180_0A11;

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
        Self::parse(
            seal,
            env("KEPR_TPM2_PIN").as_deref(),
            env("KEPR_TPM2_PIN_FILE").as_deref(),
            env("KEPR_TPM2_NV_INDEX").as_deref(),
            env("KEPR_TPM2_PCRS").as_deref(),
        )
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
            nv_index: index.map_or(Ok(DEFAULT_NV_INDEX), parse_index)?,
            pcrs: pcrs.map(pcr_list).transpose()?,
        }))
    }
}

fn parse_index(v: &str) -> Result<u32, String> {
    let n = match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    };
    n.filter(|n| (0x0100_0000..=0x01FF_FFFF).contains(n))
        .ok_or_else(|| format!("KEPR_TPM2_NV_INDEX={v}: an NV index 0x01000000-0x01FFFFFF"))
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
}
