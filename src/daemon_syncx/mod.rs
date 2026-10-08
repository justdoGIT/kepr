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

mod bundle;
mod device_bundle;
mod export;
mod folder;
mod folder_bundle;
mod folder_import;
mod import;
mod sync_merge;
mod sync_state;
mod transfer;

use kepr_core::protocol::Response;
use kepr_core::protocol_syncx::{SyncxRequest, SyncxResponse};

use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry::now_unix;

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
    }
}
