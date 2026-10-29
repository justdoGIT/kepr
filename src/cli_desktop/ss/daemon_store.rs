// cli_desktop/ss/daemon_store.rs — the Secret Service store kept by the
// kepr daemon (daemon_desktop/). Each call is one request on the daemon's
// socket, started on demand like any `kepr` command. The daemon rate-limits
// its clients; a burst (a client reading fifty secrets in a row) is waited
// out here instead of surfacing as an error.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_desktop::{
    self as pd, DesktopRequest as Q, DesktopResponse as R, SsCollectionInfo, SsItemInfo,
};
use zeroize::Zeroizing;

use super::store::{Attrs, Change, Res, Secret, Store, StoreError};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const RETRIES: u32 = 40;

pub struct DaemonStore;

/// The daemon's words as store errors.
pub fn map_error(e: &str) -> StoreError {
    match e {
        pd::ERR_LOCKED => StoreError::Locked,
        pd::ERR_NO_ITEM | pd::ERR_NO_COLLECTION => StoreError::NotFound,
        other => StoreError::Other(other.to_string()),
    }
}

/// Send `req`, waiting out the daemon's rate limit.
pub fn send(req: &Request) -> Res<Response> {
    for attempt in 0..=RETRIES {
        match crate::client::send_request(req) {
            Ok(Response::Err { error }) if error == "rate limited" && attempt < RETRIES => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(r) => return Ok(r),
            Err(e) => return Err(StoreError::Other(e)),
        }
    }
    Err(StoreError::Other(
        "the kepr daemon is rate limiting this program".into(),
    ))
}

fn ask(q: Q) -> Res<R> {
    match send(&Request::Desktop(q))? {
        Response::Desktop(r) => Ok(r),
        Response::Err { error } => Err(map_error(&error)),
        _ => Err(StoreError::Other(
            "unexpected reply from the kepr daemon".into(),
        )),
    }
}

fn unexpected<T>() -> Res<T> {
    Err(StoreError::Other(
        "unexpected reply from the kepr daemon".into(),
    ))
}

fn enc(b: &[u8]) -> ZeroString {
    ZeroString::from_string(B64.encode(b))
}

impl Store for DaemonStore {
    fn locked(&self) -> Res<bool> {
        match send(&Request::Status)? {
            Response::StatusOk { locked, .. } => Ok(locked),
            Response::Err { error } => Err(map_error(&error)),
            _ => unexpected(),
        }
    }

    fn collections(&self) -> Res<(Vec<SsCollectionInfo>, BTreeMap<String, String>)> {
        match ask(Q::SsCollections)? {
            R::SsCollections {
                collections,
                aliases,
            } => Ok((collections, aliases)),
            _ => unexpected(),
        }
    }

    fn create_collection(&self, label: &str, alias: Option<&str>) -> Res<SsCollectionInfo> {
        match ask(Q::SsCollectionCreate {
            label: label.into(),
            alias: alias.map(String::from),
        })? {
            R::SsCollection { collection } => Ok(*collection),
            _ => unexpected(),
        }
    }

    fn rename_collection(&self, id: &str, label: &str) -> Res<SsCollectionInfo> {
        match ask(Q::SsCollectionSet {
            id: id.into(),
            label: label.into(),
        })? {
            R::SsCollection { collection } => Ok(*collection),
            _ => unexpected(),
        }
    }

    fn delete_collection(&self, id: &str) -> Res<u32> {
        match ask(Q::SsCollectionDelete { id: id.into() })? {
            R::SsDeleted { items, .. } => Ok(items),
            _ => unexpected(),
        }
    }

    fn set_alias(&self, alias: &str, collection: Option<&str>) -> Res<()> {
        match ask(Q::SsAliasSet {
            alias: alias.into(),
            collection: collection.map(String::from),
        })? {
            R::SsAliasOk => Ok(()),
            _ => unexpected(),
        }
    }

    fn items(&self, collection: Option<&str>, want: &Attrs) -> Res<Vec<SsItemInfo>> {
        match ask(Q::SsItemSearch {
            collection: collection.map(String::from),
            attributes: want.clone(),
        })? {
            R::SsItems { items } => Ok(items),
            _ => unexpected(),
        }
    }

    fn create_item(
        &self,
        (collection, label, attributes): (&str, &str, &Attrs),
        (content_type, secret): (&str, &[u8]),
        replace: bool,
    ) -> Res<SsItemInfo> {
        let q = Q::SsItemCreate {
            collection: collection.into(),
            label: label.into(),
            attributes: attributes.clone(),
            content_type: content_type.into(),
            secret: enc(secret),
            replace,
        };
        match ask(q)? {
            R::SsItem { item } => Ok(*item),
            _ => unexpected(),
        }
    }

    fn secret(&self, id: &str) -> Res<Secret> {
        match ask(Q::SsItemSecret { id: id.into() })? {
            R::SsSecret {
                secret,
                content_type,
                ..
            } => {
                let raw = B64
                    .decode(secret.as_bytes())
                    .map_err(|_| StoreError::Other("the daemon sent a damaged secret".into()))?;
                Ok((Zeroizing::new(raw), content_type))
            }
            _ => unexpected(),
        }
    }

    fn update_item(&self, id: &str, c: Change) -> Res<SsItemInfo> {
        let q = Q::SsItemUpdate {
            id: id.into(),
            label: c.label,
            attributes: c.attributes,
            content_type: c.content_type,
            secret: c.secret.as_ref().map(|s| enc(s)),
        };
        match ask(q)? {
            R::SsItem { item } => Ok(*item),
            _ => unexpected(),
        }
    }

    fn delete_item(&self, id: &str) -> Res<()> {
        match ask(Q::SsItemDelete { id: id.into() })? {
            R::SsDeleted { .. } => Ok(()),
            _ => unexpected(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_daemon_s_words_map_to_store_errors() {
        assert_eq!(map_error(pd::ERR_LOCKED), StoreError::Locked);
        assert_eq!(map_error(pd::ERR_NO_ITEM), StoreError::NotFound);
        assert_eq!(map_error(pd::ERR_NO_COLLECTION), StoreError::NotFound);
        assert_eq!(map_error("boom"), StoreError::Other("boom".into()));
    }
}
