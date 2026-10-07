// daemon_sharing/ — the `share` ticket batch (P6 sharing + T11.15):
// hybrid post-quantum share envelopes, devices, one-time links,
// self-destruct, contacts, emergency access, break-glass and escrow.
// `daemon_share.rs` keeps the original P6.1/P6.2 handlers.
//
// State that isn't a credential (devices, contacts, the sent-share
// ledger, emergency contacts) is one small JSON file per uid in the
// daemon's state directory, written through atomic_file under `LOCK`.

pub mod breakglass;
pub mod contacts;
pub mod devices;
pub mod emergency;
pub mod emergency_proof;
pub mod emergency_release;
pub mod kem;
pub mod link;
pub mod report;
pub mod sent;
pub mod view;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{SharingRequest, SharingResponse};

use crate::audit::{self, AuditEvent, AuditResult};

/// Serialises read-modify-write of the per-uid state files below.
pub(crate) static LOCK: Mutex<()> = Mutex::new(());

/// The daemon's state directory (a per-process temp dir under test).
pub(crate) fn state_root() -> PathBuf {
    #[cfg(test)]
    {
        std::env::temp_dir().join(format!("kepr-sharing-tests-{}", std::process::id()))
    }
    #[cfg(not(test))]
    {
        crate::state_dir()
    }
}

pub(crate) fn state_path(kind: &str, uid: u32) -> PathBuf {
    state_root().join(format!("{kind}-{uid}.json"))
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

/// The audit chain's entries at `path` (unreadable lines skipped).
#[cfg(test)]
pub(crate) fn chain_entries(path: &Path) -> Vec<crate::audit_chain::ChainEntry> {
    use std::io::BufRead;
    let Ok(f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    std::io::BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

/// Test-only: an audit chain for this test binary, installed once, so
/// tests can check which ops were audited.
#[cfg(test)]
pub(crate) fn test_chain() -> PathBuf {
    static ONCE: std::sync::Once = std::sync::Once::new();
    let path = state_root().join("audit-chain.log");
    ONCE.call_once(|| {
        let _ = std::fs::create_dir_all(state_root());
        let chain = crate::audit_chain::AuditChain::open(path.clone()).expect("test chain");
        let _ = crate::audit::install_chain(std::sync::Arc::new(chain));
    });
    path
}

/// Test-only: was `op` audited for (uid, name) with result `ok`?
#[cfg(test)]
pub(crate) fn audited(uid: u32, op: &str, name: &str) -> bool {
    chain_entries(&test_chain())
        .iter()
        .any(|e| e.uid == uid && e.op == op && e.name.as_deref() == Some(name) && e.result == "ok")
}

/// Called by the expiry sweeper (daemon_expiry.rs) once per tick.
pub fn sweep(now: u64) {
    sent::sweep(now);
    emergency_release::sweep(now);
}

pub(crate) fn reply(r: Result<String, String>) -> Response {
    match r {
        Ok(message) => done(message),
        Err(e) => Response::fail(e),
    }
}

pub(crate) fn done(message: impl Into<String>) -> Response {
    SharingResponse::SharingDone {
        message: message.into(),
    }
    .into()
}

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, request: SharingRequest) -> Response {
    match request {
        SharingRequest::DeviceAdd { label, oidc_issuer } => {
            devices::handle_add(uid, username, &label, oidc_issuer)
        }
        SharingRequest::DeviceEnroll { request, oidc } => {
            devices::handle_enroll(uid, username, &request, oidc.as_ref())
        }
        SharingRequest::DeviceList => devices::handle_list(uid),
        SharingRequest::DeviceRemove { device } => devices::handle_remove(uid, username, &device),
        SharingRequest::ShareLinkCreate {
            name,
            ttl_secs,
            self_destruct,
            relay,
            view_window_secs,
        } => link::handle_create(
            (uid, peer_pid),
            username,
            &name,
            link::Options {
                ttl: ttl_secs,
                self_destruct: self_destruct == Some(true),
                relay,
                view_window: view_window_secs,
            },
        ),
        SharingRequest::ShareLinkOpen { blob, key, name } => {
            link::handle_open(uid, username, &blob, key.as_str(), name.as_deref())
        }
        SharingRequest::ShareSentList => sent::handle_list(uid),
        SharingRequest::ShareLinkOpened { id } => sent::handle_opened(uid, username, &id),
        SharingRequest::ShareContactAdd { name, key } => {
            contacts::handle_add(uid, username, &name, &key)
        }
        SharingRequest::ShareContactList => contacts::handle_list(uid),
        SharingRequest::ShareContactRemove { name } => {
            contacts::handle_remove(uid, username, &name)
        }
        SharingRequest::ShareReport => {
            report::handle_report(uid, username, &crate::audit_chain_path())
        }
        SharingRequest::EmergencyAdd {
            contact,
            delay_secs,
            names,
        } => emergency::handle_add(uid, username, &contact, delay_secs, names),
        SharingRequest::EmergencyList => emergency::handle_list(uid),
        SharingRequest::EmergencyRemove { contact } => {
            emergency::handle_remove(uid, username, &contact)
        }
        SharingRequest::EmergencyDeny { contact } => {
            emergency::handle_deny(uid, username, &contact)
        }
        SharingRequest::EmergencyProve { owner } => {
            emergency_release::handle_prove(uid, username, &owner)
        }
        SharingRequest::EmergencyRequest { proof } => {
            emergency_release::handle_request(uid, username, &proof)
        }
        SharingRequest::EmergencyRelease => emergency_release::handle_release(uid, username),
        SharingRequest::BreakGlass { name, shares } => {
            breakglass::handle(uid, username, &name, &shares)
        }
    }
}
