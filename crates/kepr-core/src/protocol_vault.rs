// protocol_vault.rs — `kepr vault …` requests and replies (T4.07): the
// P4 vault image (create, move the per-file store into it, check it,
// report on it). Carried by `Request::Vault` / `Response::Vault`.

use serde::{Deserialize, Serialize};

/// Size of a vault image made by `kepr vault init` without `--size`, or
/// by the daemon on the first write (T12.26): 64 MiB = 16384 slots.
pub const DEFAULT_IMAGE_MIB: u32 = 64;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum VaultRequest {
    /// Create the image (owner only; never over an existing one).
    VaultInit {
        size_mib: u32,
    },
    /// Move every per-file credential, with its meta and history, into
    /// the image (owner only; the image store must be active).
    VaultMigrate,
    /// Re-read the image and check the index, every page and the root.
    VaultVerify,
    VaultStatus,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VaultResponse {
    VaultInitOk {
        size_mib: u32,
    },
    VaultMigrateOk {
        migrated: usize,
        /// Left in per-file storage: already in the image, or unreadable.
        skipped: usize,
    },
    VaultVerifyOk {
        /// Counts are for the owner only (they span every user).
        #[serde(skip_serializing_if = "Option::is_none", default)]
        records: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        slots: Option<usize>,
    },
    VaultStatusOk {
        /// `file` or `image`: the store the daemon is using.
        backend: String,
        /// A vault image exists.
        image: bool,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        size_mib: Option<u32>,
        /// Share of slots in use; rounded to 10 % except for the owner.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        used_percent: Option<u8>,
        /// Owner only.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        used_slots: Option<u64>,
        /// Owner only: commits since the image was created.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        epoch: Option<u64>,
        /// Credentials still in per-file storage (the caller's own, or
        /// everyone's for the owner).
        legacy_files: usize,
        /// What refuses an older copy of the image (T12.30): `tpm2` (an
        /// NV counter as well as the state file) or `state-file`.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        rollback_guard: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    fn round_trip_request(r: Request) {
        let json = serde_json::to_string(&r).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{r:?}"), format!("{back:?}"), "{json}");
        assert!(matches!(back, Request::Vault(_)), "{json}");
    }

    #[test]
    fn requests_survive_json() {
        round_trip_request(Request::Vault(VaultRequest::VaultInit { size_mib: 16 }));
        round_trip_request(Request::Vault(VaultRequest::VaultMigrate));
        round_trip_request(Request::Vault(VaultRequest::VaultVerify));
        round_trip_request(Request::Vault(VaultRequest::VaultStatus));
        let raw: Request = serde_json::from_str(r#"{"cmd":"vault_status"}"#).unwrap();
        assert!(matches!(raw, Request::Vault(VaultRequest::VaultStatus)));
        // Core requests still parse as themselves.
        let list: Request = serde_json::from_str(r#"{"cmd":"list"}"#).unwrap();
        assert!(matches!(list, Request::List));
    }

    #[test]
    fn responses_survive_json() {
        for r in [
            VaultResponse::VaultInitOk { size_mib: 16 },
            VaultResponse::VaultMigrateOk {
                migrated: 3,
                skipped: 1,
            },
            VaultResponse::VaultVerifyOk {
                records: Some(4),
                slots: None,
            },
            VaultResponse::VaultStatusOk {
                backend: "image".into(),
                image: true,
                size_mib: Some(16),
                used_percent: Some(10),
                used_slots: None,
                epoch: Some(7),
                legacy_files: 0,
                rollback_guard: Some("tpm2".into()),
            },
        ] {
            let r = Response::Vault(r);
            let json = serde_json::to_string(&r).unwrap();
            let back: Response = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{r:?}"), format!("{back:?}"), "{json}");
            assert!(back.is_success());
        }
        let err: Response = serde_json::from_str(r#"{"kind":"err","error":"x"}"#).unwrap();
        assert!(matches!(err, Response::Err { .. }));
    }

    #[test]
    fn an_older_status_reply_without_rollback_guard_still_parses() {
        let old = r#"{"kind":"vault_status_ok","backend":"image","image":true,
            "size_mib":16,"legacy_files":0}"#;
        let r: Response = serde_json::from_str(old).unwrap();
        let Response::Vault(VaultResponse::VaultStatusOk { rollback_guard, .. }) = r else {
            panic!("{r:?}");
        };
        assert_eq!(rollback_guard, None);
        // And None stays out of the JSON.
        let none = serde_json::to_string(&VaultResponse::VaultStatusOk {
            backend: "file".into(),
            image: false,
            size_mib: None,
            used_percent: None,
            used_slots: None,
            epoch: None,
            legacy_files: 0,
            rollback_guard: None,
        })
        .unwrap();
        assert!(!none.contains("rollback_guard"), "{none}");
    }
}
