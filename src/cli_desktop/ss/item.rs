// cli_desktop/ss/item.rs — org.freedesktop.Secret.Item: read, replace or
// delete one item's secret. The secret never passes through here in the
// clear except to be encrypted for (or decrypted from) the client's
// session.

use std::sync::Arc;

use super::caller::Caller;
use super::names::{self as n, DErr, DResult};
use super::policy::Op;
use super::server::{str_at, val_at, Server};
use super::service::item_open;
use super::store::Change;
use crate::cli_desktop::dbus::Value;

pub fn call(
    srv: &Arc<Server>,
    who: &Caller,
    (coll, id): (&str, &str),
    member: &str,
    b: &[Value],
) -> DResult<Vec<Value>> {
    let info = srv
        .view
        .item(id)
        .filter(|i| i.collection == coll)
        .ok_or_else(|| DErr::new(n::E_NO_OBJECT, format!("no item {id}")))?;
    let path = n::item_path(coll, id);
    let label = Some(info.label.as_str());
    match member {
        "GetSecret" => {
            let session = str_at(b, 0)?;
            srv.gate(who, Op::Read, "GetSecret", id, label)?;
            if !item_open(srv, coll) {
                return Err(super::store::StoreError::Locked.into());
            }
            let r = srv
                .view
                .store()
                .secret(id)
                .map_err(DErr::from)
                .and_then(|(s, ct)| srv.sessions.encode(session, &who.name, &s, &ct));
            srv.done(who, "GetSecret", id, label, &r);
            r.map(|v| vec![v])
        }
        "SetSecret" => {
            srv.gate(who, Op::Write, "SetSecret", id, label)?;
            if !item_open(srv, coll) {
                return Err(super::store::StoreError::Locked.into());
            }
            let (secret, ct) = srv.sessions.decode(&who.name, val_at(b, 0)?)?;
            let change = Change {
                secret: Some(secret),
                content_type: (!ct.is_empty()).then_some(ct),
                ..Default::default()
            };
            let r = srv.view.store().update_item(id, change).map_err(DErr::from);
            srv.view.stale();
            srv.done(who, "SetSecret", id, label, &r);
            r?;
            srv.emit(&path, n::I_ITEM, "ItemChanged", vec![]);
            srv.emit(
                &n::collection_path(coll),
                n::I_COLLECTION,
                "ItemChanged",
                vec![Value::path(&path)],
            );
            Ok(vec![])
        }
        "Delete" => {
            srv.gate(who, Op::Write, "DeleteItem", id, label)?;
            if !item_open(srv, coll) {
                return Err(super::store::StoreError::Locked.into());
            }
            let r = srv.view.store().delete_item(id).map_err(DErr::from);
            srv.view.stale();
            srv.done(who, "DeleteItem", id, label, &r);
            r?;
            srv.emit(
                &n::collection_path(coll),
                n::I_COLLECTION,
                "ItemDeleted",
                vec![Value::path(&path)],
            );
            Ok(vec![Value::path(n::NONE)])
        }
        _ => Err(DErr::new(
            n::E_UNKNOWN_METHOD,
            format!("no method {member} on an item"),
        )),
    }
}
