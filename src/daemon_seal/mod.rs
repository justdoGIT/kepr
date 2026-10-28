// daemon_seal/ — the `seal` ticket batch, daemon side: how the master key
// is protected at rest and recovered.
// batch: seal
//
//   recovery   T4.10 recovery words (create / restore), fenced like the
//              recovery kit in daemon_recovery.rs
//   recovery_key T12.31 a recovery key for a sealed master key, and
//              T12.32 unlocking with it
//   describe   T12.33 what seals the master key, for `kepr status`
//   startup    T12.32 the master key at start-up: start locked when the
//              sealed key won't unseal and a recovery key is enrolled
//   runner     the helper-tool runner the sealers share (fake in tests)
//   tpm        T4.08 TPM2 PIN + anti-rollback counter (tpm2-tools);
//   tpm_blob   its sealed-key file format
//   tpm_config its environment
//   tpm_counter its NV counters, also the vault image's (T12.30)
//   tpm_session T12.29 salted, encrypting sessions for it
//   fido2_kek  T4.09 the `kepr_pw2` envelope: passphrase + security key
//              (used by key_unlock.rs; the CLI drives the device)
//   kms        T4.11 bring your own key: `KekSealer`, the blob header
//   kms_aws    T4.11 AWS KMS (SigV4)
//   kms_cloud  T4.12 GCP Cloud KMS and Azure Key Vault (bearer tokens)
//   pkcs11     T4.13 PKCS#11 token / HSM through pkcs11-tool (RSA-OAEP)
//   presence   T12.53 a person must approve `lock` / recovery-key enrol on
//              a keychain-sealed store
//   keychain   T10.04 the macOS keychain (`security`), macOS only at run time
//   http      the key services' HTTPS transport (fake / loopback in tests)
//
// `sealer_for` picks a sealer from the environment for
// master_key::sealer_from_env; `None` keeps the default one.

pub mod describe;
pub mod fido2_kek;
mod http;
mod keychain;
mod kms;
mod kms_aws;
mod kms_cloud;
mod pkcs11;
pub mod presence;
mod recovery;
pub mod recovery_key;
mod runner;
pub mod startup;
mod tpm;
mod tpm_blob;
mod tpm_config;
mod tpm_counter;
mod tpm_session;

use std::path::Path;
use std::sync::Arc;

use kepr_core::protocol::Response;
use kepr_core::protocol_seal::SealRequest;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_vault::rollback::EpochCounter;
use crate::master_key::Sealer;

/// The sealer `KEPR_MASTER_KEY_SEAL` (`seal`) and the TPM2 options ask
/// for, or `None` for the default. `work` is the master key's directory.
pub fn sealer_for(seal: Option<&str>, work: &Path) -> Result<Option<Box<dyn Sealer>>, String> {
    if seal == Some("keychain") {
        return Ok(Some(Box::new(keychain::KeychainSealer::from_env()?)));
    }
    let (kind, key) = seal.and_then(|s| s.split_once(':')).unwrap_or_default();
    let byok: Option<Box<dyn Sealer>> = match kind {
        "aws-kms" => Some(Box::new(kms::KmsSealer(kms_aws::AwsKms::from_env(key)?))),
        "gcp-kms" => Some(Box::new(kms::KmsSealer(kms_cloud::GcpKms::from_env(key)?))),
        "azure-kv" => Some(Box::new(kms::KmsSealer(kms_cloud::AzureKv::from_env(key)?))),
        "pkcs11" => Some(Box::new(kms::KmsSealer(pkcs11::Pkcs11::from_env(key)?))),
        _ => None,
    };
    if byok.is_some() {
        return Ok(byok);
    }
    if let Some(cfg) = tpm_config::TpmConfig::from_env(seal)? {
        return Ok(Some(Box::new(tpm::TpmSealer {
            cfg,
            runner: runner::SystemRunner,
            work: work.to_path_buf(),
        })));
    }
    Ok(None)
}

/// T12.33: does the environment pick a sealer other than the default
/// one (what `sealer_for` would build)? Builds nothing.
pub fn configured(seal: Option<&str>, tpm: Result<bool, String>) -> bool {
    let byok = seal
        .and_then(|s| s.split_once(':'))
        .is_some_and(|(k, _)| matches!(k, "aws-kms" | "gcp-kms" | "azure-kv" | "pkcs11"));
    // `tpm`: the TPM2 PIN / counter options are set; an error means
    // sealer_for refuses, so the default sealer was never in use.
    seal == Some("keychain") || byok || tpm.unwrap_or(true)
}

pub fn configured_from_env() -> bool {
    let seal = std::env::var("KEPR_MASTER_KEY_SEAL").ok();
    let tpm = tpm_config::TpmConfig::from_env(seal.as_deref()).map(|c| c.is_some());
    configured(seal.as_deref(), tpm)
}

/// The vault image's anti-rollback counter (T12.30): a TPM2 NV counter
/// when KEPR_TPM2_IMAGE_NV_INDEX names one, whatever seals the master key.
pub fn image_counter_from_env() -> Result<Option<Arc<dyn EpochCounter>>, String> {
    Ok(tpm_config::image_index_from_env()?.map(|index| {
        Arc::new(tpm_counter::NvCounter {
            index,
            runner: runner::SystemRunner,
        }) as Arc<dyn EpochCounter>
    }))
}

pub fn dispatch(uid: u32, _peer_pid: i32, username: &str, request: SealRequest) -> Response {
    match request {
        SealRequest::RecoveryWordsCreate { password } => {
            recovery::handle_create(uid, username, password.as_bytes())
        }
        SealRequest::RecoveryWordsRestore {
            words,
            new_password,
        } => recovery::handle_restore(uid, username, &words, new_password.as_bytes()),
        SealRequest::Fido2UnlockParams => fido2_kek::handle_params(uid, username),
        SealRequest::RecoveryKeyEnrol { words, current } => {
            recovery_key::handle_enrol(uid, username, &words, current.as_ref())
        }
        SealRequest::RecoveryKeyUnlock { words } => {
            recovery_key::handle_unlock(uid, username, &words)
        }
    }
}

/// One audit line (op only; never a value or a key).
fn audit_result(op: &'static str, uid: u32, username: &str, r: &Result<(), String>) {
    audit::log(&AuditEvent {
        op,
        name: None,
        uid,
        username,
        result: match r {
            Ok(()) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealer_choice_follows_the_setting() {
        let dir = Path::new("/nonexistent");
        let tpm_unset = ["KEPR_TPM2_PIN", "KEPR_TPM2_NV_INDEX"]
            .iter()
            .all(|v| std::env::var_os(v).is_none());
        // Nothing asked for: the default sealer.
        if tpm_unset {
            assert!(sealer_for(None, dir).unwrap().is_none());
            assert!(sealer_for(Some("host+tpm2"), dir).unwrap().is_none());
        }
        let e = sealer_for(Some("aws-kms:not-an-arn"), dir).err().unwrap();
        assert!(e.contains("not a KMS key ARN"), "{e}");
        if !cfg!(target_os = "macos") {
            let e = sealer_for(Some("keychain"), dir).err().unwrap();
            assert!(e.contains("only available on macOS"), "{e}");
        }
    }

    #[test]
    fn configured_matches_the_sealers_sealer_for_builds() {
        for seal in [
            None,
            Some("host"),
            Some("tpm2"),
            Some("host+tpm2"),
            Some("auto"),
        ] {
            assert!(!configured(seal, Ok(false)), "{seal:?}");
            // The TPM2 PIN / counter options pick the TPM2 sealer.
            assert!(configured(seal, Ok(true)), "{seal:?}");
        }
        for seal in [
            "keychain",
            "aws-kms:arn:aws:kms:eu-west-1:1:key/k",
            "gcp-kms:projects/p/locations/l/keyRings/r/cryptoKeys/k",
            "azure-kv:https://v.vault.azure.net/keys/k/1",
            "pkcs11:/m.so:L",
        ] {
            assert!(configured(Some(seal), Ok(false)), "{seal}");
        }
        // A broken TPM2 setting stops sealer_for: never call it the default.
        assert!(configured(None, Err("bad".into())));
        assert!(
            !configured(Some("aws-kms"), Ok(false)),
            "no key: not a sealer"
        );
    }
}
