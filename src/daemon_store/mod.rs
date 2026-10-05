// daemon_store/ — the `store` ticket batch, daemon side: tags and folders
// (T5.01). Requests arrive as `Request::Store` via daemon_extra.rs.

mod organize;
#[cfg(test)]
pub mod testkit;

use kepr_core::protocol::Response;
use kepr_core::protocol_store::StoreRequest;

/// `handle_set` hook: keep tags / folder across a value replacement.
pub use organize::carry_over;

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
    }
}
