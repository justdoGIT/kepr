// daemon_desktop/ — the `desktop` ticket batch, daemon side (T13.28): the
// encrypted item store behind kepr's Secret Service front end
// (`kepr secret-service`). Requests arrive as `Request::Desktop` via
// daemon_extra.rs, from the user's own front end process. Items are
// ordinary credentials in the store (`SSI_<id>`, folder `secret-service`),
// so locking, the idle and sleep locks, the vault image, backups and sync
// apply to them like to everything else; what is special is that their
// attributes are matched here, in the daemon, and that a secret leaves
// only through `SsItemSecret`, which is audited and policy-checked.

mod collections;
mod doc;
mod items;

use kepr_core::protocol::Response;
use kepr_core::protocol_desktop::DesktopRequest as Q;

/// Is credential `name` of `uid` a Secret Service item? `Get` refuses those
/// (they are read through `SsItemSecret`).
pub fn is_item(uid: u32, name: &str) -> bool {
    // By name too: an item restored from a backup has no sidecar flag until
    // it is next written.
    if name
        .strip_prefix(doc::PREFIX)
        .is_some_and(kepr_core::protocol_desktop::valid_item_id)
    {
        return true;
    }
    let path = crate::expiry::meta_path_for(&crate::store::cred_path(uid, name));
    matches!(crate::expiry::read_meta(&path), Some(Ok(m)) if m.desktop_item == Some(true))
}

pub fn dispatch(uid: u32, _peer_pid: i32, username: &str, r: Q) -> Response {
    let out = match r {
        Q::SsItemCreate {
            collection,
            label,
            attributes,
            content_type,
            secret,
            replace,
        } => items::create(
            uid,
            username,
            (&collection, &label, &attributes),
            (&content_type, &secret),
            replace,
        ),
        Q::SsItemSearch {
            collection,
            attributes,
        } => items::search(uid, collection.as_deref(), &attributes),
        Q::SsItemSecret { id } => items::secret(uid, username, &id),
        Q::SsItemUpdate {
            id,
            label,
            attributes,
            content_type,
            secret,
        } => items::update(
            uid,
            username,
            &id,
            (
                label.as_deref(),
                attributes.as_ref(),
                content_type.as_deref(),
                secret.as_ref(),
            ),
        ),
        Q::SsItemDelete { id } => items::delete(uid, username, &id),
        Q::SsCollections => collections::list(uid),
        Q::SsCollectionCreate { label, alias } => {
            collections::create(uid, username, &label, alias.as_deref())
        }
        Q::SsCollectionSet { id, label } => collections::rename(uid, username, &id, &label),
        Q::SsCollectionDelete { id } => collections::delete(uid, username, &id),
        Q::SsAliasSet { alias, collection } => {
            collections::set_alias(uid, username, &alias, collection.as_deref())
        }
    };
    items::to_response(out)
}

#[cfg(test)]
mod tests;
