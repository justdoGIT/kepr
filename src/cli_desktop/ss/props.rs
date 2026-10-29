// cli_desktop/ss/props.rs — org.freedesktop.DBus.Properties for every
// object of the Secret Service. Properties are read from the server's view
// of the store, which keeps labels and attributes while kepr is locked
// (only secrets are withheld then).

use std::sync::Arc;

use super::caller::Caller;
use super::names::{self as n, DErr, DResult, Obj};
use super::policy::Op;
use super::server::{str_at, val_at, Server};
use super::service::item_open;
use super::store::Change;
use super::view::SESSION;
use crate::cli_desktop::dbus::sig::Type;
use crate::cli_desktop::dbus::Value;

fn missing(what: &str) -> DErr {
    DErr::new(n::E_NO_OBJECT, format!("no such {what}"))
}

fn collection_id(srv: &Server, obj: &Obj) -> DResult<String> {
    let id = match obj {
        Obj::Collection(c) => c.clone(),
        Obj::Alias(a) => srv.view.resolve(a).ok_or_else(|| missing("collection"))?,
        _ => unreachable!("only collections"),
    };
    srv.view
        .collection(&id)
        .map(|_| id)
        .ok_or_else(|| missing("collection"))
}

/// Every property of `obj`'s interface `iface`.
pub fn props_of(srv: &Server, obj: &Obj, iface: &str) -> DResult<Vec<(String, Value)>> {
    let p = |k: &str, v: Value| (k.to_string(), v);
    match (obj, iface) {
        (Obj::Service, n::I_SERVICE) => {
            let (cs, _) = srv.view.collections();
            Ok(vec![p(
                "Collections",
                Value::paths(cs.iter().map(|c| n::collection_path(&c.id))),
            )])
        }
        (Obj::Collection(_) | Obj::Alias(_), n::I_COLLECTION) => {
            let id = collection_id(srv, obj)?;
            let c = srv
                .view
                .collection(&id)
                .ok_or_else(|| missing("collection"))?;
            let items = srv.view.items(Some(&id), &Default::default());
            Ok(vec![
                p(
                    "Items",
                    Value::paths(items.iter().map(|i| n::item_path(&id, &i.id))),
                ),
                p("Label", Value::str(c.label)),
                p("Locked", Value::Bool(id != SESSION && srv.view.locked())),
                p("Created", Value::U64(c.created)),
                p("Modified", Value::U64(c.modified)),
            ])
        }
        (Obj::Item(coll, id), n::I_ITEM) => {
            let i = srv
                .view
                .item(id)
                .filter(|i| i.collection == *coll)
                .ok_or_else(|| missing("item"))?;
            let schema = i
                .attributes
                .get("xdg:schema")
                .cloned()
                .unwrap_or_else(|| "org.freedesktop.Secret.Generic".into());
            Ok(vec![
                p("Locked", Value::Bool(!item_open(srv, coll))),
                p("Attributes", Value::dict_ss(&i.attributes)),
                p("Label", Value::str(i.label)),
                p("Type", Value::str(schema)),
                p("Created", Value::U64(i.created)),
                p("Modified", Value::U64(i.modified)),
            ])
        }
        (Obj::Session(_), n::I_SESSION) | (Obj::Prompt(_), n::I_PROMPT) => Ok(vec![]),
        _ => Err(DErr::new(
            n::E_UNKNOWN_IFACE,
            format!("the object has no interface {iface}"),
        )),
    }
}

pub fn call(
    srv: &Arc<Server>,
    who: &Caller,
    obj: &Obj,
    member: &str,
    b: &[Value],
) -> DResult<Vec<Value>> {
    match member {
        "Get" | "GetAll" => {
            srv.gate(who, Op::Search, "GetProperties", "-", None)?;
            let all = props_of(srv, obj, str_at(b, 0)?)?;
            if member == "GetAll" {
                return Ok(vec![Value::dict_sv(all)]);
            }
            let name = str_at(b, 1)?;
            let v = all
                .into_iter()
                .find(|(k, _)| k == name)
                .ok_or_else(|| DErr::new(n::E_UNKNOWN_PROP, format!("no property {name}")))?;
            Ok(vec![Value::variant(v.1)])
        }
        "Set" => set(srv, who, obj, (str_at(b, 0)?, str_at(b, 1)?), val_at(b, 2)?),
        _ => Err(DErr::new(
            n::E_UNKNOWN_METHOD,
            format!("no method {member} on Properties"),
        )),
    }
}

fn set(
    srv: &Arc<Server>,
    who: &Caller,
    obj: &Obj,
    (iface, name): (&str, &str),
    v: &Value,
) -> DResult<Vec<Value>> {
    let v = v.unwrap_variant();
    props_of(srv, obj, iface)?; // the interface and object exist
    let (path, target) = match (obj, iface, name) {
        (Obj::Collection(_) | Obj::Alias(_), n::I_COLLECTION, "Label") => {
            let id = collection_id(srv, obj)?;
            let label = v
                .as_str()
                .ok_or_else(|| DErr::args("Label must be a string"))?;
            srv.gate(who, Op::Write, "SetLabel", &id, Some(label))?;
            if id != SESSION {
                srv.require_unlocked()?;
            }
            let r = srv
                .view
                .store()
                .rename_collection(&id, label)
                .map_err(DErr::from);
            srv.view.stale();
            srv.done(who, "SetLabel", &id, Some(label), &r);
            r?;
            (n::collection_path(&id), id)
        }
        (Obj::Item(coll, id), n::I_ITEM, "Label" | "Attributes") => {
            let mut change = Change::default();
            if name == "Label" {
                change.label = Some(
                    v.as_str()
                        .ok_or_else(|| DErr::args("Label must be a string"))?
                        .to_string(),
                );
            } else {
                let pairs = v
                    .pairs_ss()
                    .ok_or_else(|| DErr::args("Attributes must be a dictionary of strings"))?;
                change.attributes = Some(pairs.into_iter().collect());
            }
            srv.gate(who, Op::Write, "SetProperty", id, None)?;
            if !item_open(srv, coll) {
                return Err(super::store::StoreError::Locked.into());
            }
            let r = srv.view.store().update_item(id, change).map_err(DErr::from);
            srv.view.stale();
            srv.done(who, "SetProperty", id, None, &r);
            r?;
            (n::item_path(coll, id), id.clone())
        }
        (_, _, "Locked" | "Created" | "Modified" | "Items" | "Collections" | "Type") => {
            return Err(DErr::new(n::E_READ_ONLY, format!("{name} is read only")))
        }
        _ => return Err(DErr::new(n::E_UNKNOWN_PROP, format!("no property {name}"))),
    };
    let _ = target;
    srv.emit(
        &path,
        n::I_PROPS,
        "PropertiesChanged",
        vec![
            Value::str(iface),
            Value::dict_sv(vec![(name.to_string(), v.clone())]),
            Value::Array(Type::Str, vec![]),
        ],
    );
    Ok(vec![])
}
