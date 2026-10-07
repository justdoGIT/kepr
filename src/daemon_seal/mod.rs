// daemon_seal/ — the `seal` ticket batch, daemon side: how the master key
// is protected at rest and recovered.
// batch: seal
//
//   recovery   T4.10 recovery words (create / restore), fenced like the
//              recovery kit in daemon_recovery.rs
//   runner     the helper-tool runner the sealers share (fake in tests)
//   tpm        T4.08 TPM2 PIN + anti-rollback counter (tpm2-tools);
//   tpm_config its environment
//   fido2_kek  T4.09 the `kepr_pw2` envelope: passphrase + security key
//              (used by key_unlock.rs; the CLI drives the device)
//   kms        T4.11 bring your own key: `KekSealer`, the blob header
//   kms_aws    T4.11 AWS KMS (SigV4)
//   http       the key services' HTTPS transport (fake / loopback in tests)
//
// `sealer_for` picks a sealer from the environment for
// master_key::sealer_from_env; `None` keeps the default one.

pub mod fido2_kek;
mod http;
mod kms;
mod kms_aws;
mod recovery;
mod runner;
mod tpm;
mod tpm_config;

use std::path::Path;

use kepr_core::protocol::Response;
use kepr_core::protocol_seal::SealRequest;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::master_key::Sealer;

/// The sealer `KEPR_MASTER_KEY_SEAL` (`seal`) and the TPM2 options ask
/// for, or `None` for the default. `work` is the master key's directory.
pub fn sealer_for(seal: Option<&str>, work: &Path) -> Result<Option<Box<dyn Sealer>>, String> {
    let (kind, key) = seal.and_then(|s| s.split_once(':')).unwrap_or_default();
    let byok: Option<Box<dyn Sealer>> = match kind {
        "aws-kms" => Some(Box::new(kms::KmsSealer(kms_aws::AwsKms::from_env(key)?))),
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
    }
}
