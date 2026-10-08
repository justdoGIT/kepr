// daemon_syncx/ — the `sync` ticket batch, daemon side. Requests arrive
// as `Request::Syncx` via daemon_extra.rs.
//
//   bundle     T6.09 bundle format: Argon2id + AES-256-GCM over a JSON body
//   export     T6.09 ExportBundle: every credential `get` could read now
//   import     T6.09 ImportBundle: create / update / skip, per credential
//   transfer   T6.09 chunked transfer of bundles (64 KiB frames)
//   device_bundle  T6.10 sync bundles: to every enrolled device, MAC'd
//   sync_state     T6.10 last writer per credential, tombstones
//   sync_merge     T6.10 SyncDevice / SyncBuild / SyncMerge
//   folder_bundle  T6.02 shared-folder bundles: folder key, signed manifest
//   folder         T6.02 FolderExport
//   folder_import  T6.02 FolderImport: pinned sender, changed values only
//   quorum         T7.12 M-of-N approvals: requirement, requests, windows
//   quorum_cmd     T7.12 Quorum* requests
//   quorum_device  T7.12 approvals signed by enrolled devices

mod bundle;
mod device_bundle;
mod export;
mod folder;
mod folder_bundle;
mod folder_import;
mod import;
mod quorum;
mod quorum_cmd;
mod quorum_device;
mod sync_merge;
mod sync_state;
#[cfg(test)]
mod testutil;
mod transfer;

use kepr_core::protocol::Response;
use kepr_core::protocol_syncx::{SyncxRequest, SyncxResponse};

use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry::now_unix;

/// T7.12 hooks: `get` / gate resolves check `quorum_gate`; `set` keeps
/// the requirement; the expiry sweeper closes windows.
pub fn quorum_gate(uid: u32, name: &str, meta: &crate::expiry::CredMeta) -> Result<(), String> {
    quorum::gate(uid, name, meta, now_unix())
}
pub use quorum::{carry_over as quorum_carry_over, sweep as quorum_sweep};

pub(crate) fn audit_r<T>(
    op: &str,
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

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, r: SyncxRequest) -> Response {
    let who = (uid, peer_pid);
    match r {
        SyncxRequest::ExportBundle { passphrase } => {
            export::handle_export(who, username, &passphrase)
        }
        SyncxRequest::ExportChunk { id, index } => match transfer::export_chunk(uid, &id, index) {
            Ok(data) => SyncxResponse::BundleChunk { id, index, data }.into(),
            Err(e) => Response::fail(e),
        },
        SyncxRequest::ImportPut {
            upload,
            index,
            chunk,
            last,
        } => {
            match transfer::put_upload(uid, upload.as_deref(), (index, &chunk, last), now_unix()) {
                Ok((upload, done)) => SyncxResponse::ImportPutOk { upload, done }.into(),
                Err(e) => Response::fail(e),
            }
        }
        SyncxRequest::ImportBundle {
            upload,
            passphrase,
            prefix,
            overwrite,
            apply,
            start,
        } => import::handle_import(
            who,
            username,
            import::Args {
                upload: &upload,
                passphrase: &passphrase,
                prefix: prefix.as_deref(),
                overwrite,
                apply,
                start,
            },
        ),
        SyncxRequest::SyncDevice => sync_merge::handle_device(uid),
        SyncxRequest::SyncBuild => sync_merge::handle_build(who, username),
        SyncxRequest::SyncMerge { upload, start } => {
            sync_merge::handle_merge(who, username, &upload, start)
        }
        SyncxRequest::FolderExport {
            folder,
            recipients,
            sealed,
        } => folder::handle_export(who, username, &folder, &recipients, sealed),
        SyncxRequest::FolderImport {
            upload,
            overwrite,
            apply,
            start,
        } => folder_import::handle_import(
            who,
            username,
            folder_import::ImportArgs {
                upload: &upload,
                overwrite,
                apply,
                start,
            },
        ),
        SyncxRequest::QuorumSet { name, approvals } => {
            quorum_cmd::handle_set(uid, username, &name, approvals, now_unix())
        }
        SyncxRequest::QuorumRequest { name, secs } => {
            quorum_cmd::handle_request(uid, username, &name, secs, now_unix())
        }
        SyncxRequest::QuorumApprove { id, approval } => quorum_cmd::handle_approve(
            uid,
            username,
            (&id, approval.as_deref()),
            || crate::daemon_polkit::consent_granted(peer_pid),
            now_unix(),
        ),
        SyncxRequest::QuorumSign { request } => quorum_cmd::handle_sign(
            uid,
            username,
            &request,
            || crate::daemon_polkit::consent_granted(peer_pid),
            now_unix(),
        ),
        SyncxRequest::QuorumList => quorum_cmd::handle_list(uid, now_unix()),
    }
}
