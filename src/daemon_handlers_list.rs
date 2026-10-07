// daemon_handlers_list.rs — handle_list: the caller's credentials with
// the flags from their sidecar metas (TTL, consent, FIDO2, sealed and
// bound hosts, record type). Split from daemon_handlers.rs (LOC limit),
// like daemon_handlers_get.rs; never reads a value.

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_cache;
use crate::expiry;
use crate::store::{self, file_mtime_str, file_size};
use kepr_core::protocol::{CredInfo, Response};

pub fn handle_list(uid: u32, username: &str) -> Response {
    let entries = daemon_cache::list_for_uid(uid);
    let creds: Vec<CredInfo> = entries
        .iter()
        .map(|(name, path)| {
            let meta_opt = expiry::read_meta(&expiry::meta_path_for(path)).and_then(|r| r.ok());
            let expires_at = meta_opt
                .as_ref()
                .and_then(|m| m.expires_at_unix.map(expiry::format_expires_at));
            let requires_consent = meta_opt
                .as_ref()
                .and_then(|m| m.requires_consent)
                .filter(|v| *v)
                .map(|_| true);
            let requires_fido2 = meta_opt
                .as_ref()
                .and_then(|m| m.requires_fido2)
                .filter(|v| *v)
                .map(|_| true);
            let sealed = meta_opt.as_ref().and_then(|m| m.sealed).filter(|v| *v);
            let bound_hosts = meta_opt
                .as_ref()
                .and_then(|m| m.bindings.as_ref())
                .map(|bs| {
                    bs.iter()
                        .map(|b| format!("{}:{}", b.host, b.port))
                        .collect()
                });
            CredInfo {
                name: name.clone(),
                cred_name: store::to_cred_name(uid, name),
                size: file_size(path),
                modified: file_mtime_str(path),
                expires_at,
                requires_consent,
                requires_fido2,
                sealed,
                bound_hosts,
                record_type: meta_opt.as_ref().and_then(|m| m.record_type.clone()),
                tags: meta_opt.as_ref().and_then(|m| m.tags.clone()),
                folder: meta_opt.as_ref().and_then(|m| m.folder.clone()),
                alias_of: None,
                db_kind: meta_opt
                    .as_ref()
                    .and_then(|m| m.bindings.as_ref()?.first()?.inject.db_kind())
                    .map(str::to_string),
                requires_reauth: meta_opt.as_ref().and_then(|m| m.requires_reauth), // T11.14
            }
        })
        .chain(crate::daemon_store::alias_infos(uid)) // T11.5
        .collect();

    audit::log(&AuditEvent {
        op: "list",
        name: None,
        uid,
        username,
        result: AuditResult::Ok,
    });

    let count = creds.len();
    Response::ListOk {
        credentials: creds,
        count,
    }
}
