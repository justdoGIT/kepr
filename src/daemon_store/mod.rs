// daemon_store/ — the `store` ticket batch, daemon side: tags and folders
// (T5.01), search (T11.1), trash (T11.2), aliases (T11.5). Requests arrive as
// `Request::Store` via daemon_extra.rs; `Request::Delete` comes to
// `handle_rm` from daemon_dispatch.rs.

mod alias;
mod files;
mod organize;
mod pattern;
mod search;
#[cfg(test)]
pub mod testkit;
mod trash;

use kepr_core::protocol::Response;
use kepr_core::protocol_store::StoreRequest;

/// `kepr ls` hook: aliases have no value file, so list them here.
pub use alias::infos as alias_infos;
/// `Get` hook: an alias reads its target, under the target's policy.
pub use alias::resolve as resolve_alias;
/// `handle_set` hook: keep tags / folder across a value replacement.
pub use organize::carry_over;
/// `Request::Delete`: into the trash (T11.2).
pub use trash::handle_rm;
/// The expiry sweeper's hook: purge old trash entries.
pub use trash::sweep as sweep_trash;

pub fn dispatch(uid: u32, _peer_pid: i32, username: &str, r: StoreRequest) -> Response {
    match r {
        StoreRequest::Organize {
            name,
            add_tags,
            remove_tags,
            folder,
        } => organize::handle_organize(
            uid,
            username,
            &name,
            (&add_tags, &remove_tags),
            folder.as_deref(),
        ),
        StoreRequest::Search { pattern } => search::handle_search(uid, username, &pattern),
        StoreRequest::TrashList => trash::handle_list(uid, username),
        StoreRequest::TrashRestore { name } => trash::handle_restore(uid, username, &name),
        StoreRequest::TrashPurge { name } => trash::handle_purge(uid, username, name.as_deref()),
        StoreRequest::DeleteNow { name } => alias::remove_if_alias(uid, username, &name)
            .unwrap_or_else(|| crate::daemon_handlers::handle_delete(uid, username, &name)),
        StoreRequest::Link { alias, target } => alias::handle_link(uid, username, &alias, &target),
    }
}
