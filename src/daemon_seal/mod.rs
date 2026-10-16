// daemon_seal/ — the `seal` ticket batch, daemon side: how the master key
// is protected at rest and recovered.
// batch: seal
//
//   recovery   T4.10 recovery words (create / restore), fenced like the
//              recovery kit in daemon_recovery.rs
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
//   keychain   T10.04 the macOS keychain (`security`), macOS only at run time
//   http      the key services' HTTPS transport (fake / loopback in tests)
//
// `sealer_for` picks a sealer from the environment for
// master_key::sealer_from_env; `None` keeps the default one.

pub mod fido2_kek;
mod http;
mod keychain;
mod kms;
mod kms_aws;
mod kms_cloud;
mod pkcs11;
mod recovery;
mod runner;
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
}
