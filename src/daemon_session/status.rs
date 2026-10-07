// daemon_session/status.rs — `Request::Status` (T11.24): the lock state
// plus mode, profile, store backend, what seals the master key, the
// caller's running gates, escrow and FIPS. Nothing here is secret; the
// gate count is the caller's own.

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

/// The daemon's profile (T11.16), `default` when none is set.
pub fn profile() -> String {
    std::env::var("KEPR_PROFILE")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "default".into())
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
            profile: Some(profile()),
            store_backend: Some(backend.into()),
            key_sealer: Some(key_sealer(password_protected, user).into()),
            gates: Some(crate::daemon_gate_registry::gates_for(uid) as u32),
            escrow: Some(crate::state_dir().join("escrow.bin").exists()),
            fips: Some(crate::daemon_eco::cipher::describe().1),
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
