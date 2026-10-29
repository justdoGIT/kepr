// cli_desktop/ss/service.rs — org.freedesktop.Secret.Service, the object at
// /org/freedesktop/secrets: sessions, searching across collections,
// unlocking, reading several secrets at once, and aliases.

use std::sync::Arc;

use super::caller::Caller;
use super::names::{self as n, DErr, DResult, Obj};
use super::policy::Op;
use super::server::{attrs_at, str_at, val_at, Server};
use super::sig_types::secrets_map_type;
use super::store::StoreError;
use super::view::SESSION;
use crate::cli_desktop::dbus::Value;

/// `ao` argument, as the item and collection objects it names.
fn objects_at(b: &[Value], i: usize) -> DResult<Vec<Obj>> {
    let paths = val_at(b, i)?
        .strings()
        .ok_or_else(|| DErr::args(format!("argument {i} must be an array of object paths")))?;
    Ok(paths.iter().filter_map(|p| n::parse(p)).collect())
}

/// Is the item readable now? Everything in `session` always is.
pub fn item_open(srv: &Server, collection: &str) -> bool {
    collection == SESSION || !srv.view.locked()
}

pub fn call(srv: &Arc<Server>, who: &Caller, member: &str, b: &[Value]) -> DResult<Vec<Value>> {
    match member {
        "OpenSession" => {
            srv.require_user(who, "OpenSession")?;
            let (id, out) = srv.sessions.open(&who.name, str_at(b, 0)?, val_at(b, 1)?)?;
            Ok(vec![out, Value::path(n::session_path(&id))])
        }
        "SearchItems" => {
            let want = attrs_at(b, 0)?;
            srv.gate(who, Op::Search, "SearchItems", "-", None)?;
            let (mut open, mut locked) = (Vec::new(), Vec::new());
            for i in srv.view.items(None, &want) {
                let p = n::item_path(&i.collection, &i.id);
                if item_open(srv, &i.collection) { open.push(p) } else { locked.push(p) }
            }
            srv.audit.record(who, "SearchItems", "-", None, &format!("ok {} found", open.len() + locked.len()));
            Ok(vec![Value::paths(open), Value::paths(locked)])
        }
        "Unlock" => {
            srv.require_user(who, "Unlock")?;
            let objects = objects_at(b, 0)?;
            let paths = |v: &[Obj]| v.iter().map(path_of).collect::<Vec<_>>();
            if !srv.view.locked() {
                return Ok(vec![Value::paths(paths(&objects)), Value::path(n::NONE)]);
            }
            // Only the session collection is open while kepr is locked.
            let (open, need): (Vec<Obj>, Vec<Obj>) = objects.into_iter().partition(|o| matches!(o, Obj::Collection(c) | Obj::Item(c, _) if c == SESSION));
            if need.is_empty() {
                return Ok(vec![Value::paths(paths(&open)), Value::path(n::NONE)]);
            }
            let prompt = srv.prompts.create(&who.name, paths(&need)).ok_or_else(|| DErr::new(n::E_FAILED, "too many open prompts"))?;
            Ok(vec![Value::paths(paths(&open)), Value::path(n::prompt_path(&prompt))])
        }
        "Lock" => Err(DErr::new(
            n::E_NOT_SUPPORTED,
            "kepr locks as a whole: use `kepr panic` or `kepr lock`, or let the idle timer or screen lock do it",
        )),
        "GetSecrets" => {
            let objects = objects_at(b, 0)?;
            let session = str_at(b, 1)?;
            srv.gate(who, Op::Read, "GetSecrets", "-", None)?;
            let mut entries = Vec::new();
            for o in objects {
                let Obj::Item(c, id) = o else { continue };
                // The path names a collection too; only the item's own counts,
                // so `session/<id>` cannot pose as an open collection.
                let Some(info) = srv.view.item(&id).filter(|i| i.collection == c) else { continue };
                if !item_open(srv, &info.collection) {
                    return Err(StoreError::Locked.into());
                }
                let r = srv.view.store().secret(&id).map_err(DErr::from).and_then(|(s, ct)| srv.sessions.encode(session, &who.name, &s, &ct));
                srv.done(who, "GetSecret", &id, Some(&info.label), &r);
                entries.push(Value::Dict(Box::new(Value::path(n::item_path(&c, &id))), Box::new(r?)));
            }
            Ok(vec![Value::Array(secrets_map_type(), entries)])
        }
        "ReadAlias" => {
            let name = str_at(b, 0)?;
            Ok(vec![Value::path(srv.view.resolve(name).map_or(n::NONE.to_string(), |c| n::collection_path(&c)))])
        }
        "SetAlias" => {
            let name = str_at(b, 0)?.to_string();
            let target = b.get(1).and_then(Value::as_str).ok_or_else(|| DErr::args("argument 1 must be an object path"))?;
            srv.gate(who, Op::Write, "SetAlias", &name, None)?;
            let coll = match n::parse(target) {
                Some(Obj::Collection(c)) => Some(c),
                _ if target == n::NONE => None,
                _ => return Err(DErr::args("not a collection")),
            };
            let r = srv.view.store().set_alias(&name, coll.as_deref()).map_err(DErr::from);
            srv.view.stale();
            srv.done(who, "SetAlias", &name, None, &r);
            r.map(|()| vec![])
        }
        "CreateCollection" => {
            let props = val_at(b, 0)?.pairs_sv().ok_or_else(|| DErr::args("argument 0 must be a dictionary"))?;
            let alias = str_at(b, 1)?;
            let label = props.iter().find(|(k, _)| k == n::P_COLL_LABEL).and_then(|(_, v)| v.as_str()).unwrap_or("Unnamed");
            // A well-known alias that already exists is returned, not remade.
            if !alias.is_empty() {
                if let Some(c) = srv.view.resolve(alias) {
                    return Ok(vec![Value::path(n::collection_path(&c)), Value::path(n::NONE)]);
                }
            }
            srv.gate(who, Op::Write, "CreateCollection", alias, Some(label))?;
            srv.require_unlocked()?;
            let r = srv.view.store().create_collection(label, (!alias.is_empty()).then_some(alias)).map_err(DErr::from);
            srv.view.stale();
            srv.done(who, "CreateCollection", alias, Some(label), &r);
            let c = r?;
            let path = n::collection_path(&c.id);
            srv.emit(n::ROOT, n::I_SERVICE, "CollectionCreated", vec![Value::path(&path)]);
            Ok(vec![Value::path(path), Value::path(n::NONE)])
        }
        _ => Err(DErr::new(n::E_UNKNOWN_METHOD, format!("no method {member} on the service"))),
    }
}

pub fn path_of(o: &Obj) -> String {
    match o {
        Obj::Service => n::ROOT.into(),
        Obj::Collection(c) => n::collection_path(c),
        Obj::Alias(a) => n::alias_path(a),
        Obj::Item(c, i) => n::item_path(c, i),
        Obj::Session(s) => n::session_path(s),
        Obj::Prompt(p) => n::prompt_path(p),
    }
}
