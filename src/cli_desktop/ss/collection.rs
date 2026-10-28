// cli_desktop/ss/collection.rs — org.freedesktop.Secret.Collection: search
// one collection, create an item in it, delete it. Reached by its own path
// or through /aliases/<alias>.

use std::sync::Arc;

use super::caller::Caller;
use super::names::{self as n, DErr, DResult};
use super::policy::Op;
use super::server::{attrs_at, bool_at, val_at, Server};
use super::store::{Attrs, StoreError};
use super::view::SESSION;
use crate::cli_desktop::dbus::Value;

pub fn call(
    srv: &Arc<Server>,
    who: &Caller,
    id: &str,
    member: &str,
    b: &[Value],
) -> DResult<Vec<Value>> {
    if srv.view.collection(id).is_none() {
        srv.view.stale();
        if srv.view.collection(id).is_none() {
            return Err(DErr::new(n::E_NO_OBJECT, format!("no collection {id}")));
        }
    }
    match member {
        "SearchItems" => {
            let want = attrs_at(b, 0)?;
            srv.gate(who, Op::Search, "SearchItems", id, None)?;
            let items = srv.view.items(Some(id), &want);
            Ok(vec![Value::paths(
                items.iter().map(|i| n::item_path(id, &i.id)),
            )])
        }
        "CreateItem" => {
            let props = val_at(b, 0)?
                .pairs_sv()
                .ok_or_else(|| DErr::args("argument 0 must be a dictionary"))?;
            let replace = bool_at(b, 2)?;
            let label = props
                .iter()
                .find(|(k, _)| k == n::P_LABEL)
                .and_then(|(_, v)| v.as_str())
                .unwrap_or("")
                .to_string();
            let attrs: Attrs = match props.iter().find(|(k, _)| k == n::P_ATTRS) {
                Some((_, v)) => v
                    .pairs_ss()
                    .ok_or_else(|| DErr::args("Attributes must be a dictionary of strings"))?
                    .into_iter()
                    .collect(),
                None => Attrs::new(),
            };
            srv.gate(who, Op::Write, "CreateItem", id, Some(&label))?;
            if id != SESSION {
                srv.require_unlocked()?;
            }
            let (mut secret, ct) = srv.sessions.decode(&who.name, val_at(b, 1)?)?;
            let ct = if ct.is_empty() {
                "text/plain"
            } else {
                ct.as_str()
            };
            let r = srv
                .view
                .store()
                .create_item((id, &label, &attrs), (ct, &secret), replace)
                .map_err(DErr::from);
            zeroize::Zeroize::zeroize(&mut *secret);
            srv.view.stale();
            srv.done(who, "CreateItem", id, Some(&label), &r);
            let item = r?;
            let path = n::item_path(id, &item.id);
            srv.emit(
                &n::collection_path(id),
                n::I_COLLECTION,
                "ItemCreated",
                vec![Value::path(&path)],
            );
            Ok(vec![Value::path(path), Value::path(n::NONE)])
        }
        "Delete" => {
            srv.gate(who, Op::Write, "DeleteCollection", id, None)?;
            if id != SESSION {
                srv.require_unlocked()?;
            }
            let r = srv.view.store().delete_collection(id).map_err(|e| match e {
                StoreError::Invalid(t) => DErr::new(n::E_DENIED, t),
                other => other.into(),
            });
            srv.view.stale();
            srv.done(who, "DeleteCollection", id, None, &r);
            r?;
            srv.emit(
                n::ROOT,
                n::I_SERVICE,
                "CollectionDeleted",
                vec![Value::path(n::collection_path(id))],
            );
            Ok(vec![Value::path(n::NONE)])
        }
        _ => Err(DErr::new(
            n::E_UNKNOWN_METHOD,
            format!("no method {member} on a collection"),
        )),
    }
}
