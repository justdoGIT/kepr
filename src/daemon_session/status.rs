// daemon_session/status.rs — `Request::Status` (T11.24): the lock state
// plus mode, profile, store backend, what seals the master key, the
// caller's running gates, escrow, FIPS and (T12.31) whether a recovery
// key is enrolled. Nothing here is secret; the gate count is the caller's
// own.

use kepr_core::protocol::Response;
use kepr_core::protocol_session::StatusInfo;

/// What protects the master key at rest (never the backend's name).
pub fn key_sealer(password_protected: bool, user_mode: bool) -> &'static str {
    if password_protected {
        "passphrase"
    } else if user_mode {
        "file"
    } else {
        "host"
    }
}

/// T12.31: whether a recovery key is enrolled, on a sealed store; on a
/// passphrase store (which has the recovery kit instead) only when one is
/// left from before `kepr lock`.
pub fn recovery_key(password_protected: bool, enrolled: bool) -> Option<bool> {
    (!password_protected || enrolled).then_some(enrolled)
}

pub fn handle(uid: u32) -> Response {
    let password_protected = crate::protected_master_key_path().exists();
    let user = crate::user_mode();
    let backend = if crate::daemon_vault::active().is_some() {
        "image"
    } else {
        "file"
    };
    Response::StatusOk {
        locked: crate::crypto::backend_is_locked(),
        password_protected,
        info: StatusInfo {
            mode: Some(if user { "user" } else { "system" }.into()),
            profile: Some(kepr_core::profile::display_name()),
            store_backend: Some(backend.into()),
            key_sealer: Some(key_sealer(password_protected, user).into()),
            gates: Some(crate::daemon_gate_registry::gates_for(uid) as u32),
            escrow: Some(crate::state_dir().join("escrow.bin").exists()),
            fips: Some(crate::daemon_eco::cipher::describe().1),
            recovery_key: recovery_key(
                password_protected,
                crate::daemon_seal::recovery_key::path().exists(),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealer_names_never_the_backend() {
        assert_eq!(key_sealer(true, false), "passphrase");
        assert_eq!(key_sealer(true, true), "passphrase");
        assert_eq!(key_sealer(false, true), "file");
        assert_eq!(key_sealer(false, false), "host");
    }

    #[test]
    fn recovery_key_shows_on_sealed_stores() {
        assert_eq!(recovery_key(false, false), Some(false));
        assert_eq!(recovery_key(false, true), Some(true));
        assert_eq!(recovery_key(true, false), None);
        assert_eq!(recovery_key(true, true), Some(true));
    }

    #[test]
    fn every_field_is_filled() {
        let Response::StatusOk { info, .. } = handle(4_242_424) else {
            panic!("not a status");
        };
        assert!(matches!(info.mode.as_deref(), Some("user" | "system")));
        assert!(info.profile.is_some() && info.key_sealer.is_some());
        assert!(matches!(
            info.store_backend.as_deref(),
            Some("file" | "image")
        ));
        assert_eq!(info.gates, Some(0));
        assert!(info.escrow.is_some() && info.fips.is_some());
    }
}
