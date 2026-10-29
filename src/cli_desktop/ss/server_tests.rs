// Behaviour of the Secret Service API, driven through `Server::handle`.
// The whole file is test code: the attribute below is where
// tests/file_size_limit.rs stops counting production lines.

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kepr_core::protocol_desktop as pd;
use zeroize::Zeroizing;

use super::audit::Audit;
use super::caller::Caller;
use super::dh;
use super::names::{self as n};
use super::policy::Policy;
use super::server::{Server, Sink};
use super::store::{MemStore, Store};
use super::unlock::Unlocker;
use super::view::Routed;
use crate::cli_desktop::dbus::{Message, Value};

#[derive(Default)]
struct Recorder(Mutex<Vec<Message>>);
impl Sink for Recorder {
    fn emit(&self, m: Message) {
        self.0.lock().unwrap().push(m);
    }
}
impl Recorder {
    fn named(&self, member: &str) -> Vec<Message> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.member.as_deref() == Some(member))
            .cloned()
            .collect()
    }
}

/// Unlocks the store when asked, as a person typing the passphrase would.
struct Types {
    store: Arc<MemStore>,
    ok: bool,
    asked: Mutex<u32>,
}
impl Unlocker for Types {
    fn unlock(&self, _: &AtomicBool) -> Result<bool, String> {
        *self.asked.lock().unwrap() += 1;
        if self.ok {
            self.store.set_locked(false);
        }
        Ok(self.ok)
    }
}

struct Rig {
    srv: Arc<Server>,
    store: Arc<MemStore>,
    sink: Arc<Recorder>,
    unlocker: Arc<Types>,
    serial: Mutex<u32>,
}

fn rig_with(policy: Policy, unlock_ok: bool) -> Rig {
    let store = Arc::new(MemStore::new(&[pd::LOGIN]));
    let sink = Arc::new(Recorder::default());
    let unlocker = Arc::new(Types {
        store: Arc::clone(&store),
        ok: unlock_ok,
        asked: Mutex::new(0),
    });
    let srv = Server::new(
        Arc::new(Routed::new(store.clone())),
        policy,
        Audit::memory(),
        unlocker.clone(),
        sink.clone(),
    );
    Rig {
        srv,
        store,
        sink,
        unlocker,
        serial: Mutex::new(0),
    }
}

fn rig() -> Rig {
    rig_with(Policy::default(), true)
}

/// kepr is locked from the start and the bridge has never seen the store;
/// a call that needs it waits at most `wait` for the dialog.
fn cold_rig(unlock_ok: bool, wait: Duration) -> Rig {
    let mut r = rig_with(Policy::default(), unlock_ok);
    r.store.set_locked(true);
    r.srv = Arc::clone(&r.srv).with_wait(wait);
    r
}

fn who(name: &str) -> Caller {
    Caller {
        name: name.into(),
        pid: Some(100),
        uid: Some(1000),
        exe: Some("/usr/bin/test-app".into()),
        sandboxed: false,
    }
}

impl Rig {
    fn call(&self, c: &Caller, path: &str, iface: &str, member: &str, body: Vec<Value>) -> Message {
        let mut m = Message::call(n::BUS_NAME, path, iface, member, body);
        m.sender = Some(c.name.clone());
        let mut s = self.serial.lock().unwrap();
        *s += 1;
        m.serial = *s;
        self.srv.handle(c, &m)
    }

    fn ok(
        &self,
        c: &Caller,
        path: &str,
        iface: &str,
        member: &str,
        body: Vec<Value>,
    ) -> Vec<Value> {
        let r = self.call(c, path, iface, member, body);
        assert_eq!(
            r.kind,
            crate::cli_desktop::dbus::msg::METHOD_RETURN,
            "{member}: {:?}",
            r.body
        );
        r.body
    }

    fn err(&self, c: &Caller, path: &str, iface: &str, member: &str, body: Vec<Value>) -> String {
        let r = self.call(c, path, iface, member, body);
        assert_eq!(
            r.kind,
            crate::cli_desktop::dbus::msg::ERROR,
            "{member} should fail: {:?}",
            r.body
        );
        r.error_name.unwrap()
    }

    fn plain_session(&self, c: &Caller) -> String {
        let b = self.ok(
            c,
            n::ROOT,
            n::I_SERVICE,
            "OpenSession",
            vec![Value::str("plain"), Value::variant(Value::str(""))],
        );
        b[1].as_str().unwrap().to_string()
    }

    fn create(
        &self,
        c: &Caller,
        session: &str,
        label: &str,
        attrs: &[(&str, &str)],
        secret: &[u8],
    ) -> String {
        let a: std::collections::BTreeMap<String, String> = attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let props = Value::dict_sv(vec![
            (n::P_LABEL.into(), Value::str(label)),
            (n::P_ATTRS.into(), Value::dict_ss(&a)),
        ]);
        let sec = Value::Struct(vec![
            Value::path(session),
            Value::Bytes(vec![]),
            Value::Bytes(secret.to_vec()),
            Value::str("text/plain"),
        ]);
        let b = self.ok(
            c,
            &n::alias_path("default"),
            n::I_COLLECTION,
            "CreateItem",
            vec![props, sec, Value::Bool(true)],
        );
        assert_eq!(b[1].as_str(), Some("/"), "no prompt needed");
        b[0].as_str().unwrap().to_string()
    }
}

fn search(r: &Rig, c: &Caller, attrs: &[(&str, &str)]) -> (Vec<String>, Vec<String>) {
    let a: std::collections::BTreeMap<String, String> = attrs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let b = r.ok(
        c,
        n::ROOT,
        n::I_SERVICE,
        "SearchItems",
        vec![Value::dict_ss(&a)],
    );
    (b[0].strings().unwrap(), b[1].strings().unwrap())
}

#[test]
fn store_search_and_read_back_with_a_plain_session() {
    let r = rig();
    let c = who(":1.10");
    let s = r.plain_session(&c);
    let item = r.create(
        &c,
        &s,
        "Mail",
        &[("xdg:schema", "x.Net"), ("user", "alice")],
        b"s3cret",
    );
    assert!(item.starts_with("/org/freedesktop/secrets/collection/login/"));
    assert_eq!(r.sink.named("ItemCreated").len(), 1);
    let (unlocked, locked) = search(&r, &c, &[("user", "alice")]);
    assert_eq!((unlocked, locked), (vec![item.clone()], vec![]));
    assert!(search(&r, &c, &[("user", "bob")]).0.is_empty());
    let got = r.ok(&c, &item, n::I_ITEM, "GetSecret", vec![Value::path(&s)]);
    let f = got[0].as_struct().unwrap();
    assert_eq!(
        (f[0].as_str(), f[2].as_bytes(), f[3].as_str()),
        (Some(s.as_str()), Some(&b"s3cret"[..]), Some("text/plain"))
    );
    // GetSecrets for several at once.
    let m = r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "GetSecrets",
        vec![
            Value::paths(vec![
                item.clone(),
                "/org/freedesktop/secrets/collection/login/NOSUCH".into(),
            ]),
            Value::path(&s),
        ],
    );
    assert_eq!(m[0].sig(), "a{o(oayays)}");
    assert_eq!(
        m[0].as_array().unwrap().len(),
        1,
        "unknown items are skipped"
    );
    // Replacing an item with the same attributes keeps one.
    let again = r.create(
        &c,
        &s,
        "Mail",
        &[("xdg:schema", "x.Net"), ("user", "alice")],
        b"changed",
    );
    assert_eq!(again, item);
    assert_eq!(search(&r, &c, &[]).0.len(), 1);
    // And the audit log says who read what.
    let log = r.srv.audit.lines().join("\n");
    assert!(
        log.contains("\"op\":\"GetSecret\"")
            && log.contains("\"label\":\"Mail\"")
            && log.contains("/usr/bin/test-app"),
        "{log}"
    );
    assert!(
        !log.contains("s3cret") && !log.contains("alice"),
        "no secrets or attribute values in the log: {log}"
    );
}

#[test]
fn a_dh_session_encrypts_the_secret_on_the_wire() {
    let r = rig();
    let c = who(":1.11");
    let (private, public) = dh::keypair().unwrap();
    let b = r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "OpenSession",
        vec![
            Value::str(dh::ALGORITHM),
            Value::variant(Value::Bytes(public.to_vec())),
        ],
    );
    let Value::Variant(server_pub) = &b[0] else {
        panic!()
    };
    let key = dh::session_key(&private, server_pub.as_bytes().unwrap()).unwrap();
    let s = b[1].as_str().unwrap().to_string();
    // The client sends an encrypted secret…
    let (iv, ct) = dh::encrypt(&key, b"from the client").unwrap();
    let sec = Value::Struct(vec![
        Value::path(&s),
        Value::Bytes(iv.to_vec()),
        Value::Bytes(ct),
        Value::str("text/plain"),
    ]);
    let props = Value::dict_sv(vec![(n::P_LABEL.into(), Value::str("L"))]);
    let item = r.ok(
        &c,
        &n::collection_path("login"),
        n::I_COLLECTION,
        "CreateItem",
        vec![props, sec, Value::Bool(false)],
    )[0]
    .as_str()
    .unwrap()
    .to_string();
    // …and reads it back encrypted under a new IV.
    let got = r.ok(&c, &item, n::I_ITEM, "GetSecret", vec![Value::path(&s)]);
    let f = got[0].as_struct().unwrap();
    assert_ne!(f[2].as_bytes().unwrap(), b"from the client");
    let plain: Zeroizing<Vec<u8>> =
        dh::decrypt(&key, f[1].as_bytes().unwrap(), f[2].as_bytes().unwrap()).unwrap();
    assert_eq!(&plain[..], b"from the client");
}

#[test]
fn another_connection_cannot_use_a_session_and_a_closed_one_is_gone() {
    let r = rig();
    let (a, b) = (who(":1.1"), who(":1.2"));
    let s = r.plain_session(&a);
    let item = r.create(&a, &s, "L", &[("k", "v")], b"x");
    assert_eq!(
        r.err(&b, &item, n::I_ITEM, "GetSecret", vec![Value::path(&s)]),
        n::E_NO_SESSION
    );
    assert_eq!(
        r.err(&b, &s, n::I_SESSION, "Close", vec![]),
        n::E_NO_SESSION
    );
    r.ok(&a, &s, n::I_SESSION, "Close", vec![]);
    assert_eq!(
        r.err(&a, &item, n::I_ITEM, "GetSecret", vec![Value::path(&s)]),
        n::E_NO_SESSION
    );
    // A connection that leaves takes its sessions with it.
    let s2 = r.plain_session(&a);
    r.srv.forget(":1.1");
    assert_eq!(
        r.err(&a, &item, n::I_ITEM, "GetSecret", vec![Value::path(&s2)]),
        n::E_NO_SESSION
    );
}

#[test]
fn properties_read_set_and_refuse() {
    let r = rig();
    let c = who(":1.3");
    let s = r.plain_session(&c);
    let item = r.create(
        &c,
        &s,
        "Mail",
        &[("xdg:schema", "x.Net"), ("user", "alice")],
        b"x",
    );
    let all = r.ok(&c, &item, n::I_PROPS, "GetAll", vec![Value::str(n::I_ITEM)]);
    let p: std::collections::BTreeMap<_, _> = all[0].pairs_sv().unwrap().into_iter().collect();
    assert_eq!(p["Label"].as_str(), Some("Mail"));
    assert_eq!(p["Locked"].as_bool(), Some(false));
    assert_eq!(p["Type"].as_str(), Some("x.Net"));
    assert_eq!(p["Attributes"].pairs_ss().unwrap().len(), 2);
    assert!(matches!(p["Created"], Value::U64(t) if *t > 0));
    // One property, in a variant.
    let one = r.ok(
        &c,
        &item,
        n::I_PROPS,
        "Get",
        vec![Value::str(n::I_ITEM), Value::str("Label")],
    );
    assert_eq!(one[0], Value::variant(Value::str("Mail")));
    // Set the label and the attributes.
    r.ok(
        &c,
        &item,
        n::I_PROPS,
        "Set",
        vec![
            Value::str(n::I_ITEM),
            Value::str("Label"),
            Value::variant(Value::str("Renamed")),
        ],
    );
    let a2: std::collections::BTreeMap<String, String> =
        [("user".to_string(), "carol".to_string())].into();
    r.ok(
        &c,
        &item,
        n::I_PROPS,
        "Set",
        vec![
            Value::str(n::I_ITEM),
            Value::str("Attributes"),
            Value::variant(Value::dict_ss(&a2)),
        ],
    );
    assert_eq!(search(&r, &c, &[("user", "carol")]).0, vec![item.clone()]);
    assert!(search(&r, &c, &[("user", "alice")]).0.is_empty());
    assert_eq!(r.sink.named("PropertiesChanged").len(), 2);
    // Collection and service properties.
    let coll = r.ok(
        &c,
        &n::alias_path("default"),
        n::I_PROPS,
        "GetAll",
        vec![Value::str(n::I_COLLECTION)],
    );
    let cp: std::collections::BTreeMap<_, _> = coll[0].pairs_sv().unwrap().into_iter().collect();
    assert_eq!(cp["Items"].strings().unwrap(), vec![item.clone()]);
    assert_eq!(cp["Locked"].as_bool(), Some(false));
    let svc = r.ok(
        &c,
        n::ROOT,
        n::I_PROPS,
        "Get",
        vec![Value::str(n::I_SERVICE), Value::str("Collections")],
    );
    assert!(svc[0]
        .unwrap_variant()
        .strings()
        .unwrap()
        .contains(&n::collection_path("login")));
    r.ok(
        &c,
        &n::collection_path("login"),
        n::I_PROPS,
        "Set",
        vec![
            Value::str(n::I_COLLECTION),
            Value::str("Label"),
            Value::variant(Value::str("My keys")),
        ],
    );
    assert_eq!(
        r.store
            .collections()
            .unwrap()
            .0
            .iter()
            .find(|c| c.id == "login")
            .unwrap()
            .label,
        "My keys"
    );
    // Refusals.
    assert_eq!(
        r.err(
            &c,
            &item,
            n::I_PROPS,
            "Set",
            vec![
                Value::str(n::I_ITEM),
                Value::str("Locked"),
                Value::variant(Value::Bool(true))
            ]
        ),
        n::E_READ_ONLY
    );
    assert_eq!(
        r.err(
            &c,
            &item,
            n::I_PROPS,
            "Get",
            vec![Value::str(n::I_ITEM), Value::str("Nope")]
        ),
        n::E_UNKNOWN_PROP
    );
    assert_eq!(
        r.err(
            &c,
            &item,
            n::I_PROPS,
            "GetAll",
            vec![Value::str(n::I_COLLECTION)]
        ),
        n::E_UNKNOWN_IFACE
    );
    assert_eq!(
        r.err(
            &c,
            &item,
            n::I_PROPS,
            "Set",
            vec![
                Value::str(n::I_ITEM),
                Value::str("Label"),
                Value::variant(Value::U32(1))
            ]
        ),
        n::E_INVALID_ARGS
    );
}

#[test]
fn a_locked_store_shows_what_exists_refuses_secrets_and_offers_an_unlock() {
    let r = rig();
    let c = who(":1.4");
    let s = r.plain_session(&c);
    let item = r.create(&c, &s, "Mail", &[("user", "alice")], b"x");
    assert_eq!(
        search(&r, &c, &[("user", "alice")]).0,
        vec![item.clone()],
        "seen while unlocked"
    );
    r.store.set_locked(true);
    r.srv.view.stale();
    // Found, but reported locked, and the secret is refused.
    let (unlocked, locked) = search(&r, &c, &[("user", "alice")]);
    assert_eq!((unlocked.len(), locked), (0, vec![item.clone()]));
    let p = r.ok(
        &c,
        &item,
        n::I_PROPS,
        "Get",
        vec![Value::str(n::I_ITEM), Value::str("Locked")],
    );
    assert_eq!(p[0], Value::variant(Value::Bool(true)));
    assert_eq!(
        r.err(&c, &item, n::I_ITEM, "GetSecret", vec![Value::path(&s)]),
        n::E_LOCKED
    );
    assert_eq!(r.err(&c, &item, n::I_ITEM, "Delete", vec![]), n::E_LOCKED);
    // Unlock gives a prompt; running it asks the unlocker and signals.
    let b = r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "Unlock",
        vec![Value::paths(vec![item.clone()])],
    );
    assert!(b[0].strings().unwrap().is_empty());
    let prompt = b[1].as_str().unwrap().to_string();
    assert!(prompt.starts_with("/org/freedesktop/secrets/prompt/"));
    assert_eq!(
        r.err(
            &who(":1.99"),
            &prompt,
            n::I_PROMPT,
            "Prompt",
            vec![Value::str("")]
        ),
        n::E_NO_OBJECT,
        "someone else's prompt"
    );
    r.ok(&c, &prompt, n::I_PROMPT, "Prompt", vec![Value::str("")]);
    let t = Instant::now();
    while r.sink.named("Completed").is_empty() {
        assert!(t.elapsed() < Duration::from_secs(5), "no Completed signal");
        std::thread::sleep(Duration::from_millis(10));
    }
    let done = &r.sink.named("Completed")[0];
    assert_eq!(done.path.as_deref(), Some(prompt.as_str()));
    assert_eq!(done.body[0], Value::Bool(false), "not dismissed");
    assert_eq!(
        done.body[1].unwrap_variant().strings().unwrap(),
        vec![item.clone()]
    );
    assert_eq!(*r.unlocker.asked.lock().unwrap(), 1);
    // Now it reads.
    r.srv.view.stale();
    assert_eq!(
        r.ok(&c, &item, n::I_ITEM, "GetSecret", vec![Value::path(&s)])[0]
            .as_struct()
            .unwrap()[2]
            .as_bytes(),
        Some(&b"x"[..])
    );
    // Unlocking an unlocked store needs no prompt.
    let b = r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "Unlock",
        vec![Value::paths(vec![item.clone()])],
    );
    assert_eq!(
        (b[0].strings().unwrap(), b[1].as_str()),
        (vec![item], Some("/"))
    );
}

#[test]
fn a_dismissed_or_failed_unlock_completes_as_dismissed() {
    let r = rig_with(Policy::default(), false);
    let c = who(":1.5");
    let s = r.plain_session(&c);
    let item = r.create(&c, &s, "L", &[("k", "v")], b"x");
    r.store.set_locked(true);
    r.srv.view.stale();
    let prompt = r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "Unlock",
        vec![Value::paths(vec![item])],
    )[1]
    .as_str()
    .unwrap()
    .to_string();
    r.ok(&c, &prompt, n::I_PROMPT, "Prompt", vec![Value::str("")]);
    let t = Instant::now();
    while r.sink.named("Completed").is_empty() {
        assert!(t.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
    let done = &r.sink.named("Completed")[0];
    assert_eq!(done.body[0], Value::Bool(true));
    assert!(done.body[1].unwrap_variant().strings().unwrap().is_empty());
    // A prompt that was never run can be dismissed.
    let p2 = r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "Unlock",
        vec![Value::paths(vec![n::collection_path("login")])],
    )[1]
    .as_str()
    .unwrap()
    .to_string();
    r.ok(&c, &p2, n::I_PROMPT, "Dismiss", vec![]);
    assert!(r.srv.prompts.exists(p2.rsplit('/').next().unwrap(), ":1.5"));
}

#[test]
fn a_dialog_just_dismissed_is_not_shown_again_by_an_explicit_unlock() {
    let r = rig_with(Policy::default(), false);
    let c = who(":1.5");
    let s = r.plain_session(&c);
    let item = r.create(&c, &s, "L", &[("k", "v")], b"x");
    r.store.set_locked(true);
    r.srv.view.stale();
    for round in 1..=3 {
        let prompt = r.ok(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "Unlock",
            vec![Value::paths(vec![item.clone()])],
        )[1]
        .as_str()
        .unwrap()
        .to_string();
        r.ok(&c, &prompt, n::I_PROMPT, "Prompt", vec![Value::str("")]);
        let t = Instant::now();
        while r.sink.named("Completed").len() < round {
            assert!(t.elapsed() < Duration::from_secs(5), "round {round}");
            std::thread::sleep(Duration::from_millis(10));
        }
        let done = &r.sink.named("Completed")[round - 1];
        assert_eq!(done.body[0], Value::Bool(true), "dismissed");
    }
    assert_eq!(
        *r.unlocker.asked.lock().unwrap(),
        1,
        "one dialog; the retries in a loop were not shown"
    );
    let last = r.srv.audit.lines().pop().unwrap();
    assert!(last.contains("a dialog was dismissed"), "{last}");
}

#[test]
fn an_item_is_read_only_under_the_collection_it_is_in() {
    let r = rig();
    let c = who(":1.5");
    let s = r.plain_session(&c);
    let item = r.create(&c, &s, "L", &[("k", "v")], b"x");
    let id = item.rsplit('/').next().unwrap();
    let fake = n::item_path("session", id);
    let m = r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "GetSecrets",
        vec![Value::paths(vec![fake]), Value::path(&s)],
    );
    assert!(
        m[0].as_array().unwrap().is_empty(),
        "wrong collection: skipped"
    );
    let m = r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "GetSecrets",
        vec![Value::paths(vec![item]), Value::path(&s)],
    );
    assert_eq!(m[0].as_array().unwrap().len(), 1);
}

#[test]
fn a_caller_the_server_cannot_name_gets_nothing_under_a_policy() {
    let policy =
        Policy::parse("[[rule]]\nexe = \"/usr/bin/chromium*\"\nop = \"read\"\naction = \"deny\"\n")
            .unwrap();
    let r = rig_with(policy, true);
    let c = who(":1.5");
    let s = r.plain_session(&c);
    let item = r.create(&c, &s, "Mail", &[("k", "v")], b"x");
    // The same connection, its program no longer readable in /proc.
    let hidden = Caller {
        exe: None,
        ..c.clone()
    };
    assert_eq!(
        r.err(
            &hidden,
            &item,
            n::I_ITEM,
            "GetSecret",
            vec![Value::path(&s)]
        ),
        n::E_DENIED
    );
    assert_eq!(
        r.err(
            &hidden,
            n::ROOT,
            n::I_SERVICE,
            "OpenSession",
            vec![Value::str("plain"), Value::variant(Value::str(""))]
        ),
        n::E_DENIED
    );
}

#[test]
fn the_session_collection_works_while_kepr_is_locked() {
    let r = rig();
    let c = who(":1.6");
    let s = r.plain_session(&c);
    r.store.set_locked(true);
    r.srv.view.stale();
    let sess = n::alias_path("session");
    let sec = Value::Struct(vec![
        Value::path(&s),
        Value::Bytes(vec![]),
        Value::Bytes(b"temp".to_vec()),
        Value::str("text/plain"),
    ]);
    let props = Value::dict_sv(vec![(n::P_LABEL.into(), Value::str("T"))]);
    let item = r.ok(
        &c,
        &sess,
        n::I_COLLECTION,
        "CreateItem",
        vec![props, sec, Value::Bool(false)],
    )[0]
    .as_str()
    .unwrap()
    .to_string();
    let got = r.ok(&c, &item, n::I_ITEM, "GetSecret", vec![Value::path(&s)]);
    assert_eq!(
        got[0].as_struct().unwrap()[2].as_bytes(),
        Some(&b"temp"[..])
    );
    let l = r.ok(
        &c,
        &sess,
        n::I_PROPS,
        "Get",
        vec![Value::str(n::I_COLLECTION), Value::str("Locked")],
    );
    assert_eq!(l[0], Value::variant(Value::Bool(false)));
}

#[test]
fn the_policy_can_refuse_a_program_and_the_refusal_is_audited() {
    let policy =
        Policy::parse("[[rule]]\nexe = \"/usr/bin/test-app\"\nop = \"read\"\naction = \"deny\"\n")
            .unwrap();
    let r = rig_with(policy, true);
    let c = who(":1.7");
    let s = r.plain_session(&c);
    let item = r.create(&c, &s, "Mail", &[("k", "v")], b"x");
    assert_eq!(
        search(&r, &c, &[("k", "v")]).0.len(),
        1,
        "searching is allowed"
    );
    assert_eq!(
        r.err(&c, &item, n::I_ITEM, "GetSecret", vec![Value::path(&s)]),
        n::E_DENIED
    );
    assert_eq!(
        r.err(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "GetSecrets",
            vec![Value::paths(vec![item]), Value::path(&s)]
        ),
        n::E_DENIED
    );
    assert!(r
        .srv
        .audit
        .lines()
        .iter()
        .any(|l| l.contains("\"result\":\"denied\"") && l.contains("GetSecret")));
    // A different program is not affected.
    let mut other = who(":1.8");
    other.exe = Some("/usr/bin/other".into());
    let s2 = r.plain_session(&other);
    let item2 = search(&r, &other, &[("k", "v")]).0[0].clone();
    r.ok(
        &other,
        &item2,
        n::I_ITEM,
        "GetSecret",
        vec![Value::path(&s2)],
    );
    r.srv.set_policy(Policy::deny_all());
    assert_eq!(
        r.err(
            &other,
            &item2,
            n::I_ITEM,
            "GetSecret",
            vec![Value::path(&s2)]
        ),
        n::E_DENIED
    );
}

#[test]
fn deleting_collections_aliases_and_items() {
    let r = rig();
    let c = who(":1.9");
    let s = r.plain_session(&c);
    let item = r.create(&c, &s, "L", &[("k", "v")], b"x");
    assert_eq!(
        r.ok(&c, &item, n::I_ITEM, "Delete", vec![])[0].as_str(),
        Some("/")
    );
    assert_eq!(r.sink.named("ItemDeleted").len(), 1);
    assert!(search(&r, &c, &[]).0.is_empty());
    assert_eq!(
        r.err(&c, &item, n::I_ITEM, "GetSecret", vec![Value::path(&s)]),
        n::E_NO_OBJECT
    );
    // A new collection with an alias; asking again for the alias returns it.
    let props = Value::dict_sv(vec![(n::P_COLL_LABEL.into(), Value::str("Work"))]);
    let b = r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "CreateCollection",
        vec![props.clone(), Value::str("work")],
    );
    let work = b[0].as_str().unwrap().to_string();
    assert_eq!(b[1].as_str(), Some("/"));
    assert_eq!(r.sink.named("CollectionCreated").len(), 1);
    let again = r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "CreateCollection",
        vec![props, Value::str("work")],
    );
    assert_eq!(again[0].as_str(), Some(work.as_str()));
    assert_eq!(
        r.ok(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "ReadAlias",
            vec![Value::str("work")]
        )[0]
        .as_str(),
        Some(work.as_str())
    );
    assert_eq!(
        r.ok(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "ReadAlias",
            vec![Value::str("nope")]
        )[0]
        .as_str(),
        Some("/")
    );
    r.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "SetAlias",
        vec![Value::str("work"), Value::path("/")],
    );
    assert_eq!(
        r.ok(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "ReadAlias",
            vec![Value::str("work")]
        )[0]
        .as_str(),
        Some("/")
    );
    assert_eq!(
        r.ok(&c, &work, n::I_COLLECTION, "Delete", vec![])[0].as_str(),
        Some("/")
    );
    assert_eq!(r.sink.named("CollectionDeleted").len(), 1);
    assert_eq!(
        r.err(
            &c,
            &work,
            n::I_COLLECTION,
            "SearchItems",
            vec![Value::dict_ss(&std::collections::BTreeMap::new())]
        ),
        n::E_NO_OBJECT
    );
    // The login collection stays; locking is not offered.
    assert_eq!(
        r.err(
            &c,
            &n::collection_path("login"),
            n::I_COLLECTION,
            "Delete",
            vec![]
        ),
        n::E_DENIED
    );
    assert_eq!(
        r.err(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "Lock",
            vec![Value::paths(vec![])]
        ),
        n::E_NOT_SUPPORTED
    );
}

#[test]
fn unknown_things_get_the_standard_errors_and_introspection_works() {
    let r = rig();
    let c = who(":1.12");
    assert_eq!(
        r.err(
            &c,
            "/org/freedesktop/secrets/nothing",
            n::I_SERVICE,
            "SearchItems",
            vec![]
        ),
        n::E_UNKNOWN_OBJECT
    );
    assert_eq!(
        r.err(&c, n::ROOT, n::I_SERVICE, "Frobnicate", vec![]),
        n::E_UNKNOWN_METHOD
    );
    assert_eq!(
        r.err(&c, n::ROOT, "com.example.Other", "Foo", vec![]),
        n::E_UNKNOWN_IFACE
    );
    assert_eq!(
        r.err(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "SearchItems",
            vec![Value::U32(1)]
        ),
        n::E_INVALID_ARGS
    );
    assert_eq!(
        r.err(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "OpenSession",
            vec![Value::str("rot13"), Value::variant(Value::str(""))]
        ),
        n::E_NOT_SUPPORTED
    );
    assert_eq!(
        r.err(
            &c,
            &n::item_path("login", "NOSUCHITEM"),
            n::I_ITEM,
            "Delete",
            vec![]
        ),
        n::E_NO_OBJECT
    );
    // Peer and introspection.
    r.ok(&c, n::ROOT, n::I_PEER, "Ping", vec![]);
    assert_eq!(
        r.ok(&c, n::ROOT, n::I_PEER, "GetMachineId", vec![])[0]
            .as_str()
            .unwrap()
            .len(),
        32
    );
    let xml = r.ok(&c, n::ROOT, n::I_INTRO, "Introspect", vec![])[0]
        .as_str()
        .unwrap()
        .to_string();
    for want in [
        "org.freedesktop.Secret.Service",
        "OpenSession",
        "GetSecrets",
        "org.freedesktop.DBus.Properties",
        "<node name=\"collection\"/>",
    ] {
        assert!(xml.contains(want), "{want}");
    }
    let item_xml = r.ok(
        &c,
        &n::item_path("login", "X"),
        n::I_INTRO,
        "Introspect",
        vec![],
    )[0]
    .as_str()
    .unwrap()
    .to_string();
    assert!(item_xml.contains("org.freedesktop.Secret.Item") && item_xml.contains("GetSecret"));
    for p in [
        "/",
        "/org",
        "/org/freedesktop",
        "/org/freedesktop/secrets/collection",
    ] {
        assert!(
            r.ok(&c, p, n::I_INTRO, "Introspect", vec![])[0]
                .as_str()
                .unwrap()
                .contains("<node"),
            "{p}"
        );
    }
    // Without an interface header the member is looked up (some clients).
    let mut m = Message::call(
        n::BUS_NAME,
        n::ROOT,
        "",
        "ReadAlias",
        vec![Value::str("default")],
    );
    m.interface = None;
    m.sender = Some(":1.12".into());
    m.serial = 5;
    assert_eq!(
        r.srv.handle(&c, &m).kind,
        crate::cli_desktop::dbus::msg::METHOD_RETURN
    );
}

#[test]
fn many_sessions_from_one_client_are_bounded_and_the_oldest_makes_room() {
    let r = rig();
    let c = who(":1.13");
    let first = r.plain_session(&c);
    for _ in 1..super::session::MAX_PER_OWNER {
        r.plain_session(&c);
    }
    assert!(r
        .srv
        .sessions
        .exists(first.rsplit('/').next().unwrap(), ":1.13"));
    // One more is still served: it costs the client its oldest.
    let newest = r.plain_session(&c);
    assert!(!r
        .srv
        .sessions
        .exists(first.rsplit('/').next().unwrap(), ":1.13"));
    assert!(r
        .srv
        .sessions
        .exists(newest.rsplit('/').next().unwrap(), ":1.13"));
    let _ = Ordering::SeqCst;
}

#[test]
fn a_cold_start_with_kepr_locked_asks_to_unlock_and_carries_on() {
    let r = cold_rig(true, Duration::from_secs(5));
    let c = who(":1.20");
    // The very first question needs the store: the dialog is shown, the
    // call waits for it and then answers as usual.
    let (unlocked, locked) = search(&r, &c, &[]);
    assert!((unlocked.len(), locked.len()) == (0, 0));
    assert_eq!(*r.unlocker.asked.lock().unwrap(), 1);
    let s = r.plain_session(&c);
    let item = r.create(&c, &s, "L", &[("k", "v")], b"x");
    assert_eq!(*r.unlocker.asked.lock().unwrap(), 1, "once is enough");
    assert_eq!(search(&r, &c, &[("k", "v")]).0, vec![item]);
    assert!(r
        .srv
        .audit
        .lines()
        .iter()
        .any(|l| l.contains("AutoUnlock") && l.contains("\"ok\"")));
}

#[test]
fn a_refused_cold_unlock_fails_with_is_locked_and_is_not_asked_again_at_once() {
    let r = cold_rig(false, Duration::from_secs(5));
    let c = who(":1.21");
    assert_eq!(
        r.err(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "SearchItems",
            vec![Value::dict_ss(&std::collections::BTreeMap::new())]
        ),
        n::E_LOCKED
    );
    assert_eq!(*r.unlocker.asked.lock().unwrap(), 1);
    // Applications retry in a loop: no second dialog within the cooldown.
    assert_eq!(
        r.err(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "ReadAlias",
            vec![Value::str("default")]
        ),
        n::E_LOCKED
    );
    assert_eq!(*r.unlocker.asked.lock().unwrap(), 1);
    // The session collection and plain sessions never need kepr.
    let s = r.plain_session(&c);
    let sess = n::alias_path("session");
    let sec = Value::Struct(vec![
        Value::path(&s),
        Value::Bytes(vec![]),
        Value::Bytes(b"t".to_vec()),
        Value::str("text/plain"),
    ]);
    let props = Value::dict_sv(vec![(n::P_LABEL.into(), Value::str("T"))]);
    r.ok(
        &c,
        &sess,
        n::I_COLLECTION,
        "CreateItem",
        vec![props, sec, Value::Bool(false)],
    );
    assert_eq!(*r.unlocker.asked.lock().unwrap(), 1);
    assert!(r
        .srv
        .audit
        .lines()
        .iter()
        .any(|l| l.contains("AutoUnlock") && l.contains("refused")));
}

#[test]
fn a_dialog_nobody_answers_gives_up_instead_of_hanging_the_client() {
    struct Never;
    impl Unlocker for Never {
        fn unlock(&self, cancel: &AtomicBool) -> Result<bool, String> {
            while !cancel.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(false)
        }
    }
    let store = Arc::new(MemStore::new(&[pd::LOGIN]));
    store.set_locked(true);
    let sink = Arc::new(Recorder::default());
    let srv = Server::new(
        Arc::new(Routed::new(store)),
        Policy::default(),
        Audit::memory(),
        Arc::new(Never),
        sink,
    )
    .with_wait(Duration::from_millis(100));
    let c = who(":1.22");
    let mut m = Message::call(
        n::BUS_NAME,
        n::ROOT,
        n::I_SERVICE,
        "ReadAlias",
        vec![Value::str("default")],
    );
    m.sender = Some(c.name.clone());
    m.serial = 1;
    let t = Instant::now();
    let reply = srv.handle(&c, &m);
    assert_eq!(reply.error_name.as_deref(), Some(n::E_LOCKED));
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[test]
fn a_program_the_policy_refuses_everywhere_gets_no_session_and_no_unlock_dialog() {
    let r = rig_with(Policy::deny_all(), true);
    let c = who(":1.30");
    assert_eq!(
        r.err(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "OpenSession",
            vec![Value::str("plain"), Value::variant(Value::str(""))]
        ),
        n::E_DENIED
    );
    r.store.set_locked(true);
    r.srv.view.stale();
    assert_eq!(
        r.err(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "Unlock",
            vec![Value::paths(vec![n::collection_path("login")])]
        ),
        n::E_DENIED
    );
    assert_eq!(*r.unlocker.asked.lock().unwrap(), 0, "no dialog was shown");
    assert!(r
        .srv
        .audit
        .lines()
        .iter()
        .any(|l| l.contains("OpenSession") && l.contains("denied")));
    assert!(r
        .srv
        .audit
        .lines()
        .iter()
        .any(|l| l.contains("Unlock") && l.contains("denied")));
}

#[test]
fn a_refused_program_cannot_start_the_dialog_at_a_cold_start_either() {
    let mut r = rig_with(Policy::deny_all(), true);
    r.store.set_locked(true);
    r.srv = Arc::clone(&r.srv).with_wait(Duration::from_secs(2));
    let c = who(":1.31");
    assert_eq!(
        r.err(
            &c,
            n::ROOT,
            n::I_SERVICE,
            "ReadAlias",
            vec![Value::str("default")]
        ),
        n::E_DENIED
    );
    assert_eq!(*r.unlocker.asked.lock().unwrap(), 0);
    // A program that may do one thing may start the dialog.
    let only_search =
        Policy::parse("default = \"deny\"\n[[rule]]\nop = \"search\"\naction = \"allow\"\n")
            .unwrap();
    let r2 = cold_rig(true, Duration::from_secs(2));
    r2.srv.set_policy(only_search);
    r2.ok(
        &c,
        n::ROOT,
        n::I_SERVICE,
        "ReadAlias",
        vec![Value::str("default")],
    );
    assert_eq!(*r2.unlocker.asked.lock().unwrap(), 1);
}
