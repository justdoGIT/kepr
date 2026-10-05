// daemon_sharing/ — the `share` ticket batch (P6 sharing + T11.15):
// hybrid post-quantum share envelopes, devices, one-time links,
// self-destruct, contacts, emergency access, break-glass and escrow.
// `daemon_share.rs` keeps the original P6.1/P6.2 handlers.
//
// State that isn't a credential (devices, contacts, the sent-share
// ledger, emergency contacts) is one small JSON file per uid in the
// daemon's state directory, written through atomic_file under `LOCK`.

pub mod devices;
pub mod kem;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{SharingRequest, SharingResponse};

use crate::audit::{self, AuditEvent, AuditResult};

/// Serialises read-modify-write of the per-uid state files below.
pub(crate) static LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn state_path(kind: &str, uid: u32) -> PathBuf {
    crate::state_dir().join(format!("{kind}-{uid}.json"))
}

/// A missing or unreadable file is the empty state.
pub(crate) fn load<T: serde::de::DeserializeOwned + Default>(path: &Path) -> T {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub(crate) fn save<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot save state: {e}"))?;
    }
    crate::atomic_file::write(path, &bytes, 0o600).map_err(|e| format!("cannot save state: {e}"))
}

pub(crate) fn audit_r<T>(
    op: &'static str,
    uid: u32,
    username: &str,
    name: Option<&str>,
    r: &Result<T, String>,
) {
    audit::log(&AuditEvent {
        op,
        name,
        uid,
        username,
        result: match r {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}

pub(crate) fn done(message: impl Into<String>) -> Response {
    SharingResponse::SharingDone {
        message: message.into(),
    }
    .into()
}

pub fn dispatch(uid: u32, _peer_pid: i32, username: &str, request: SharingRequest) -> Response {
    match request {
        SharingRequest::DeviceAdd { label, oidc_issuer } => {
            devices::handle_add(uid, username, &label, oidc_issuer)
        }
        SharingRequest::DeviceEnroll { request, oidc } => {
            devices::handle_enroll(uid, username, &request, oidc.as_ref())
        }
        SharingRequest::DeviceList => devices::handle_list(uid),
        SharingRequest::DeviceRemove { device } => devices::handle_remove(uid, username, &device),
    }
}
