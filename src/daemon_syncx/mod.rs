// daemon_syncx/ — the `sync` ticket batch, daemon side. Requests arrive
// as `Request::Syncx` via daemon_extra.rs.
//
//   bundle     T6.09 bundle format: Argon2id + AES-256-GCM over a JSON body
//   export     T6.09 ExportBundle: every credential `get` could read now
//   import     T6.09 ImportBundle: create / update / skip, per credential
//   transfer   T6.09 chunked transfer of bundles (64 KiB frames)

mod bundle;
mod export;
mod import;
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
    }
}
