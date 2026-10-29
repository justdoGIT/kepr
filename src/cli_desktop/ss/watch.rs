// cli_desktop/ss/watch.rs — tells clients when kepr locks or unlocks.
//
// kepr locks for reasons this process never sees (`kepr lock`, a panic,
// suspend, the idle timer). A client that cached "Locked = false" would try
// a secret and fail, so once a second the lock state is read and, when it
// changed, every collection and item announces its new `Locked`. The same
// pass keeps the item cache fresh while unlocked.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::names as n;
use super::server::Server;
use super::store::Attrs;
use super::view::SESSION;
use crate::cli_desktop::dbus::sig::Type;
use crate::cli_desktop::dbus::Value;

pub const INTERVAL: Duration = Duration::from_secs(1);

fn announce(srv: &Server, path: &str, iface: &str, locked: bool) {
    srv.emit(
        path,
        n::I_PROPS,
        "PropertiesChanged",
        vec![
            Value::str(iface),
            Value::dict_sv(vec![("Locked".into(), Value::Bool(locked))]),
            Value::Array(Type::Str, vec![]),
        ],
    );
}

/// Announce `locked` for everything that depends on it (the memory-only
/// `session` collection never does).
pub fn announce_all(srv: &Server, locked: bool) {
    srv.view.stale();
    for c in srv.view.collections().0.iter().filter(|c| c.id != SESSION) {
        announce(srv, &n::collection_path(&c.id), n::I_COLLECTION, locked);
    }
    for i in srv
        .view
        .items(None, &Attrs::new())
        .iter()
        .filter(|i| i.collection != SESSION)
    {
        announce(srv, &n::item_path(&i.collection, &i.id), n::I_ITEM, locked);
    }
}

/// One pass: true when the state changed since the previous pass. The very
/// first pass only records the state.
pub fn tick(srv: &Server, first: &mut bool) -> bool {
    let changed = srv.view.lock_change();
    if std::mem::take(first) {
        return false;
    }
    match changed {
        Some(locked) => {
            announce_all(srv, locked);
            true
        }
        None => {
            srv.view.sync();
            false
        }
    }
}

pub fn spawn(srv: Arc<Server>, stop: Arc<AtomicBool>) {
    let _ = std::thread::Builder::new()
        .name("lock-watch".into())
        .spawn(move || {
            let mut first = true;
            while !stop.load(Ordering::SeqCst) {
                tick(&srv, &mut first);
                std::thread::sleep(INTERVAL);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::super::audit::Audit;
    use super::super::policy::Policy;
    use super::super::server::Sink;
    use super::super::store::{MemStore, Store};
    use super::super::unlock::Unlocker;
    use super::super::view::Routed;
    use super::*;
    use crate::cli_desktop::dbus::Message;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Rec(Mutex<Vec<Message>>);
    impl Sink for Rec {
        fn emit(&self, m: Message) {
            self.0.lock().unwrap().push(m);
        }
    }
    struct No;
    impl Unlocker for No {
        fn unlock(&self, _: &AtomicBool) -> Result<bool, String> {
            Ok(false)
        }
    }

    #[test]
    fn a_change_of_lock_state_is_announced_once_for_each_object() {
        let store = Arc::new(MemStore::new(&["login"]));
        let attrs = Attrs::new();
        store
            .create_item(("login", "a", &attrs), ("text/plain", b"x"), false)
            .unwrap();
        let sink = Arc::new(Rec::default());
        let srv = Server::new(
            Arc::new(Routed::new(store.clone())),
            Policy::default(),
            Audit::memory(),
            Arc::new(No),
            sink.clone(),
        );
        let mut first = true;
        assert!(!tick(&srv, &mut first), "the first pass only looks");
        assert!(!tick(&srv, &mut first));
        assert!(sink.0.lock().unwrap().is_empty());
        store.set_locked(true);
        assert!(tick(&srv, &mut first));
        let sent = sink.0.lock().unwrap().clone();
        // login + one item.
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert!(sent
            .iter()
            .all(|m| m.member.as_deref() == Some("PropertiesChanged")));
        assert!(sent
            .iter()
            .all(|m| m.body[1].pairs_sv().unwrap()[0].1.as_bool() == Some(true)));
        assert!(!tick(&srv, &mut first), "no change, no signal");
        assert_eq!(sink.0.lock().unwrap().len(), 2);
        store.set_locked(false);
        assert!(tick(&srv, &mut first));
        assert_eq!(sink.0.lock().unwrap().len(), 4);
    }
}
