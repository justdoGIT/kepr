// cli_desktop/ss/server.rs — the Secret Service server: one `handle` that
// takes a decoded method call and the caller's identity and returns the
// reply. Signals leave through a `Sink`. Nothing here touches the bus, so
// the whole API is tested by calling `handle`.
//
// Order of business for a call: find the object the path names; answer the
// standard interfaces (Peer, Introspectable, Properties); otherwise check
// the policy for what the call does (search, read, write) and run it, and
// record reads and writes in the audit log.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::audit::Audit;
use super::caller::Caller;
use super::names::{self as n, DErr, DResult, Obj};
use super::policy::{Action, Op, Policy};
use super::prompt::Prompts;
use super::session::Sessions;
use super::store::Store;
use super::unlock::Unlocker;
use super::view::View;
use crate::cli_desktop::dbus::{Message, Value};

/// Where signals go (the bus connection; a recorder in tests).
pub trait Sink: Send + Sync {
    fn emit(&self, m: Message);
}

/// After a dialog was dismissed or failed, no new one is shown for this long.
const COOLDOWN: Duration = Duration::from_secs(10);
/// How long a call waits for the person to unlock (clients give up at 25 s).
pub const UNLOCK_WAIT: Duration = Duration::from_secs(20);

pub struct Server {
    pub view: View,
    pub sessions: Sessions,
    pub prompts: Prompts,
    pub audit: Audit,
    policy: Mutex<Arc<Policy>>,
    pub unlocker: Arc<dyn Unlocker>,
    pub sink: Arc<dyn Sink>,
    last_refusal: Mutex<Option<Instant>>,
    wait: Duration,
}

pub fn str_at(b: &[Value], i: usize) -> DResult<&str> {
    b.get(i)
        .and_then(Value::as_str)
        .ok_or_else(|| DErr::args(format!("argument {i} must be a string")))
}

pub fn bool_at(b: &[Value], i: usize) -> DResult<bool> {
    b.get(i)
        .and_then(Value::as_bool)
        .ok_or_else(|| DErr::args(format!("argument {i} must be a boolean")))
}

pub fn val_at(b: &[Value], i: usize) -> DResult<&Value> {
    b.get(i)
        .ok_or_else(|| DErr::args(format!("argument {i} is missing")))
}

/// `a{ss}` argument.
pub fn attrs_at(b: &[Value], i: usize) -> DResult<super::store::Attrs> {
    val_at(b, i)?
        .pairs_ss()
        .map(|p| p.into_iter().collect())
        .ok_or_else(|| DErr::args(format!("argument {i} must be a dictionary of strings")))
}

/// Does this call need the real store's contents (as opposed to the
/// in-memory `session` collection, sessions and prompts)?
fn needs_contents(obj: &Obj, member: &str, props: bool) -> bool {
    let not_session = |c: &str| c != super::view::SESSION;
    match obj {
        Obj::Service => {
            props
                || matches!(
                    member,
                    "SearchItems" | "ReadAlias" | "SetAlias" | "GetSecrets" | "CreateCollection"
                )
        }
        Obj::Collection(c) | Obj::Alias(c) | Obj::Item(c, _) => not_session(c),
        Obj::Session(_) | Obj::Prompt(_) => false,
    }
}

fn machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "0".repeat(32))
}

impl Server {
    pub fn new(
        store: Arc<dyn Store>,
        policy: Policy,
        audit: Audit,
        unlocker: Arc<dyn Unlocker>,
        sink: Arc<dyn Sink>,
    ) -> Arc<Server> {
        Arc::new(Server {
            view: View::new(store),
            sessions: Sessions::default(),
            prompts: Prompts::default(),
            audit,
            policy: Mutex::new(Arc::new(policy)),
            unlocker,
            sink,
            last_refusal: Mutex::new(None),
            wait: UNLOCK_WAIT,
        })
    }

    /// The kepr store is locked and nothing of it is known yet: show the
    /// unlock dialog and wait for it, as a keyring does for the first
    /// program to ask. A dialog that was just dismissed is not shown again
    /// at once.
    pub fn await_unlock(self: &Arc<Self>, who: &Caller) -> DResult<()> {
        if self.cooling() {
            return Err(super::store::StoreError::Locked.into());
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel();
        let (srv, flag) = (Arc::clone(self), Arc::clone(&cancel));
        std::thread::spawn(move || {
            let _ = tx.send(srv.unlocker.unlock(&flag));
        });
        let unlocked = matches!(rx.recv_timeout(self.wait), Ok(Ok(true)));
        if unlocked {
            self.view.stale();
            self.audit.record(who, "AutoUnlock", "-", None, "ok");
            return Ok(());
        }
        cancel.store(true, Ordering::SeqCst);
        self.note_refusal();
        self.audit.record(who, "AutoUnlock", "-", None, "refused");
        Err(super::store::StoreError::Locked.into())
    }

    /// Was a dialog just dismissed or timed out? Neither the first-ask
    /// dialog nor an explicit `Unlock` prompt is shown again until it passes,
    /// so a program in a loop cannot flood the screen.
    fn cooling(&self) -> bool {
        self.last_refusal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|t| t.elapsed() < COOLDOWN)
    }

    fn note_refusal(&self) {
        *self.last_refusal.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    }

    /// Test control: how long `await_unlock` waits.
    #[cfg(test)]
    pub fn with_wait(self: Arc<Self>, d: Duration) -> Arc<Self> {
        match Arc::try_unwrap(self) {
            Ok(mut s) => {
                s.wait = d;
                Arc::new(s)
            }
            Err(a) => a,
        }
    }

    pub fn set_policy(&self, p: Policy) {
        *self.policy.lock().unwrap_or_else(|e| e.into_inner()) = Arc::new(p);
    }

    /// A connection left the bus: its sessions and prompts end.
    pub fn forget(&self, name: &str) {
        self.sessions.drop_owner(name);
        self.prompts.drop_owner(name);
    }

    /// The policy's verdict; a denial is audited and becomes AccessDenied.
    pub fn gate(
        &self,
        who: &Caller,
        op: Op,
        call: &str,
        target: &str,
        label: Option<&str>,
    ) -> DResult<()> {
        let verdict = self
            .policy
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .check(who, op);
        if verdict == Action::Deny {
            self.audit.record(who, call, target, label, "denied");
            return Err(DErr::new(n::E_DENIED, "this program may not use the Secret Service (see ~/.config/kepr/secret-service.toml)"));
        }
        Ok(())
    }

    /// Audit a finished read or write.
    pub fn done<T>(
        &self,
        who: &Caller,
        call: &str,
        target: &str,
        label: Option<&str>,
        r: &DResult<T>,
    ) {
        let result = match r {
            Ok(_) => "ok".to_string(),
            Err(DErr(name, _)) => name.rsplit('.').next().unwrap_or("error").to_string(),
        };
        self.audit.record(who, call, target, label, &result);
    }

    /// May this program use the Secret Service at all, i.e. does the policy
    /// allow it at least one operation? Opening a session and asking kepr to
    /// unlock are for programs that can do something afterwards: a program
    /// the policy refuses everywhere gets neither a session nor a passphrase
    /// dialog on the person's screen.
    pub fn require_user(&self, who: &Caller, call: &str) -> DResult<()> {
        let p = Arc::clone(&self.policy.lock().unwrap_or_else(|e| e.into_inner()));
        let any = [Op::Search, Op::Read, Op::Write]
            .into_iter()
            .any(|op| p.check(who, op) == Action::Allow);
        if any {
            return Ok(());
        }
        self.audit.record(who, call, "-", None, "denied");
        Err(DErr::new(
            n::E_DENIED,
            "this program may not use the Secret Service (see ~/.config/kepr/secret-service.toml)",
        ))
    }

    pub fn require_unlocked(&self) -> DResult<()> {
        if self.view.locked() {
            Err(super::store::StoreError::Locked.into())
        } else {
            Ok(())
        }
    }

    pub fn emit(&self, path: &str, iface: &str, member: &str, body: Vec<Value>) {
        self.sink.emit(Message::signal(path, iface, member, body));
    }

    pub fn handle(self: &Arc<Self>, who: &Caller, m: &Message) -> Message {
        match self.route(who, m) {
            Ok(body) => m.reply_to(body),
            Err(DErr(name, text)) => m.error_to(name, &text),
        }
    }

    fn route(self: &Arc<Self>, who: &Caller, m: &Message) -> DResult<Vec<Value>> {
        let path = m.path.as_deref().unwrap_or("");
        let member = m.member.as_deref().unwrap_or("");
        let iface = m.interface.as_deref();
        let is = |i: &str| iface.is_none_or(|x| x == i);
        if is(n::I_PEER) && member == "Ping" {
            return Ok(vec![]);
        }
        if is(n::I_PEER) && member == "GetMachineId" {
            return Ok(vec![Value::str(machine_id())]);
        }
        if is(n::I_INTRO) && member == "Introspect" {
            return super::intro::introspect(self, path).map(|x| vec![Value::str(x)]);
        }
        let obj = n::parse(path)
            .ok_or_else(|| DErr::new(n::E_UNKNOWN_OBJECT, format!("no object at {path}")))?;
        if needs_contents(&obj, member, iface == Some(n::I_PROPS)) && self.view.cold() {
            self.require_user(who, "AutoUnlock")?;
            self.await_unlock(who)?;
        }
        if iface == Some(n::I_PROPS) {
            return super::props::call(self, who, &obj, member, &m.body);
        }
        let b = &m.body[..];
        let nothing = || DErr::new(n::E_UNKNOWN_METHOD, format!("no method {member} on {path}"));
        match (&obj, iface) {
            (Obj::Service, None | Some(n::I_SERVICE)) => super::service::call(self, who, member, b),
            (Obj::Collection(id), None | Some(n::I_COLLECTION)) => {
                super::collection::call(self, who, id, member, b)
            }
            (Obj::Alias(a), None | Some(n::I_COLLECTION)) => {
                let id = self.view.resolve(a).ok_or_else(|| {
                    DErr::new(n::E_NO_OBJECT, format!("no collection for alias {a}"))
                })?;
                super::collection::call(self, who, &id, member, b)
            }
            (Obj::Item(c, i), None | Some(n::I_ITEM)) => {
                super::item::call(self, who, (c, i), member, b)
            }
            (Obj::Session(id), None | Some(n::I_SESSION)) if member == "Close" => {
                if self.sessions.close(id, &who.name) {
                    Ok(vec![])
                } else {
                    Err(DErr::new(n::E_NO_SESSION, "no such session"))
                }
            }
            (Obj::Prompt(id), None | Some(n::I_PROMPT)) => self.prompt_call(who, id, member, b),
            (_, Some(i))
                if ![
                    n::I_SERVICE,
                    n::I_COLLECTION,
                    n::I_ITEM,
                    n::I_SESSION,
                    n::I_PROMPT,
                ]
                .contains(&i) =>
            {
                Err(DErr::new(n::E_UNKNOWN_IFACE, format!("no interface {i}")))
            }
            _ => Err(nothing()),
        }
    }

    fn prompt_call(
        self: &Arc<Self>,
        who: &Caller,
        id: &str,
        member: &str,
        b: &[Value],
    ) -> DResult<Vec<Value>> {
        if !self.prompts.exists(id, &who.name) {
            return Err(DErr::new(n::E_NO_OBJECT, "no such prompt"));
        }
        match member {
            "Prompt" => {
                str_at(b, 0)?; // the window id, unused: our dialogs are not parented
                let Some((objects, cancel)) = self.prompts.start(id, &who.name) else {
                    return Err(DErr::new(n::E_FAILED, "the prompt is already shown"));
                };
                let (srv, id, who) = (Arc::clone(self), id.to_string(), who.clone());
                std::thread::spawn(move || srv.run_prompt(&who, &id, objects, &cancel));
                Ok(vec![])
            }
            "Dismiss" => {
                self.prompts.dismiss(id, &who.name);
                Ok(vec![])
            }
            _ => Err(DErr::new(
                n::E_UNKNOWN_METHOD,
                format!("no method {member} on a prompt"),
            )),
        }
    }

    /// The body of a prompt thread: the unlock dialog, then `Completed`.
    pub fn run_prompt(&self, who: &Caller, id: &str, objects: Vec<String>, cancel: &AtomicBool) {
        let cooling = self.cooling();
        let unlocked = !cooling
            && match self.unlocker.unlock(cancel) {
                Ok(u) => u && !cancel.load(Ordering::SeqCst),
                Err(e) => {
                    eprintln!("kepr secret-service: {e}");
                    false
                }
            };
        if !unlocked && !cooling {
            self.note_refusal();
        }
        self.view.stale();
        let result = match (unlocked, cooling) {
            (true, _) => "ok",
            (false, true) => "refused (a dialog was dismissed a moment ago)",
            (false, false) => "refused",
        };
        self.audit.record(who, "Unlock", "-", None, result);
        let result = if unlocked { objects } else { Vec::new() };
        self.emit(
            &n::prompt_path(id),
            n::I_PROMPT,
            "Completed",
            vec![Value::Bool(!unlocked), Value::variant(Value::paths(result))],
        );
        self.prompts.finish(id);
    }
}
