// cli_desktop/ss/run.rs — `kepr secret-service run`: own org.freedesktop.secrets
// on the session bus and answer libsecret clients from kepr's store.
//
// The reader thread only decodes. Each method call goes to a worker thread
// (at most MAX_BUSY at once), which learns who called, asks the `Server` and
// sends the reply. A watcher thread announces lock changes; signals from the
// bus end sessions and prompts of connections that left. SIGTERM / SIGINT
// stop it, SIGHUP re-reads the policy file.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::audit::{self, Audit};
use super::bus_caller::Callers;
use super::caller::Caller;
use super::daemon_store::DaemonStore;
use super::names as n;
use super::policy::Policy;
use super::server::{Server, Sink};
use super::unlock::{detect_here, Daemon, Dialogs};
use super::view::Routed;
use super::watch;
use crate::cli_desktop::dbus::conn::{Handler, BUS, BUS_PATH};
use crate::cli_desktop::dbus::msg::{METHOD_CALL, SIGNAL};
use crate::cli_desktop::dbus::{addr, Conn, Message, Value};

const MAX_BUSY: usize = 64;
const ALLOW_REPLACEMENT: u32 = 1;
const REPLACE_EXISTING: u32 = 2;
const DO_NOT_QUEUE: u32 = 4;

static STOPS: AtomicUsize = AtomicUsize::new(0);
static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(sig: libc::c_int) {
    if sig == libc::SIGHUP {
        RELOAD.store(true, Ordering::SeqCst);
    } else {
        STOPS.fetch_add(1, Ordering::SeqCst);
    }
}

fn catch_signals() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: a plain handler that only touches atomics; the sigaction
        // struct is zeroed and then given a handler and an empty mask.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

pub fn my_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// `~/.config/kepr/secret-service.toml`
pub fn policy_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        });
    base.join("kepr/secret-service.toml")
}

/// The policy at `path`; a broken file denies everything, loudly.
pub fn load_policy(path: &std::path::Path) -> Policy {
    Policy::load(path).unwrap_or_else(|e| {
        eprintln!("kepr secret-service: {e}; refusing every program until it is fixed");
        Policy::deny_all()
    })
}

struct BusSink(OnceLock<Arc<Conn>>);

impl Sink for BusSink {
    fn emit(&self, m: Message) {
        if let Some(c) = self.0.get() {
            let _ = c.send(&m);
        }
    }
}

pub struct Options {
    pub replace: bool,
    pub policy: PathBuf,
    pub audit: PathBuf,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            replace: false,
            policy: policy_path(),
            audit: audit::default_path(),
        }
    }
}

struct Ctx {
    server: Arc<Server>,
    callers: Callers,
    busy: AtomicUsize,
    stop: Arc<AtomicBool>,
    uid: u32,
}

fn on_message(ctx: &Arc<Ctx>, conn: &Arc<Conn>, m: Message) {
    match m.kind {
        METHOD_CALL => spawn_call(ctx, conn, m),
        SIGNAL if m.sender.as_deref() == Some(BUS) => on_bus_signal(ctx, &m),
        _ => {}
    }
}

fn on_bus_signal(ctx: &Ctx, m: &Message) {
    match m.member.as_deref() {
        Some("NameOwnerChanged") => {
            let gone = m
                .body
                .get(2)
                .and_then(Value::as_str)
                .is_some_and(str::is_empty);
            if let (true, Some(name)) = (gone, m.body.first().and_then(Value::as_str)) {
                ctx.server.forget(name);
                ctx.callers.forget(name);
            }
        }
        Some("NameLost") if m.body.first().and_then(Value::as_str) == Some(n::BUS_NAME) => {
            eprintln!(
                "kepr secret-service: another program took {}; stopping",
                n::BUS_NAME
            );
            ctx.stop.store(true, Ordering::SeqCst);
        }
        _ => {}
    }
}

fn spawn_call(ctx: &Arc<Ctx>, conn: &Arc<Conn>, m: Message) {
    if m.sender.is_none() {
        return;
    }
    if ctx.busy.fetch_add(1, Ordering::SeqCst) >= MAX_BUSY {
        ctx.busy.fetch_sub(1, Ordering::SeqCst);
        if m.wants_reply() {
            let _ = conn.send(&m.error_to(
                "org.freedesktop.DBus.Error.LimitsExceeded",
                "too many calls at once",
            ));
        }
        return;
    }
    let (ctx, conn) = (Arc::clone(ctx), Arc::clone(conn));
    let spawned = std::thread::Builder::new().name("ss-call".into()).spawn({
        let ctx = Arc::clone(&ctx);
        move || {
            let who = identify(&ctx, &conn, m.sender.as_deref().unwrap_or(""));
            let reply = match who.uid {
                Some(u) if u != ctx.uid => {
                    m.error_to(n::E_DENIED, "this service is for the user who started it")
                }
                _ => ctx.server.handle(&who, &m),
            };
            if m.wants_reply() {
                let _ = conn.send(&reply);
            }
            ctx.busy.fetch_sub(1, Ordering::SeqCst);
        }
    });
    if spawned.is_err() {
        ctx.busy.fetch_sub(1, Ordering::SeqCst);
    }
}

fn identify(ctx: &Ctx, conn: &Conn, name: &str) -> Caller {
    ctx.callers.who(conn, name)
}

/// Ask the bus for the name; explain who has it if someone does.
fn request_name(conn: &Conn, replace: bool) -> Result<(), String> {
    let flags = ALLOW_REPLACEMENT | DO_NOT_QUEUE | if replace { REPLACE_EXISTING } else { 0 };
    let call = Message::call(
        BUS,
        BUS_PATH,
        BUS,
        "RequestName",
        vec![Value::str(n::BUS_NAME), Value::U32(flags)],
    );
    let r = conn
        .call(call, Duration::from_secs(5))
        .map_err(|e| format!("RequestName: {e}"))?;
    match r.body.first().and_then(Value::as_u32) {
        Some(1 | 4) => Ok(()),
        _ => Err(format!(
            "{} is already owned by {}. Run `kepr secret-service takeover` to move the session over, or stop that program first",
            n::BUS_NAME,
            owner_description(conn)
        )),
    }
}

fn owner_description(conn: &Conn) -> String {
    super::bus_caller::owner_of(conn, n::BUS_NAME)
        .map_or_else(|| "another program".into(), |o| o.describe())
}

pub fn run(opts: &Options) -> Result<(), String> {
    catch_signals();
    let audit = Audit::file(opts.audit.clone());
    let unlocker = Arc::new(Dialogs {
        kepr: Daemon,
        prompter: detect_here(),
    });
    let sink = Arc::new(BusSink(OnceLock::new()));
    let server = Server::new(
        Arc::new(Routed::new(Arc::new(DaemonStore))),
        load_policy(&opts.policy),
        audit,
        unlocker,
        sink.clone(),
    );
    let stop = Arc::new(AtomicBool::new(false));
    let ctx = Arc::new(Ctx {
        server: Arc::clone(&server),
        callers: Callers::default(),
        busy: AtomicUsize::new(0),
        stop: Arc::clone(&stop),
        uid: my_uid(),
    });
    let handler: Arc<Handler> = {
        let ctx = Arc::clone(&ctx);
        Arc::new(move |conn, m| on_message(&ctx, conn, m))
    };
    let conn = Conn::connect(&addr::session_bus()?, ctx.uid, handler)?;
    let _ = sink.0.set(Arc::clone(&conn));
    let rule = "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'";
    let m = Message::call(BUS, BUS_PATH, BUS, "AddMatch", vec![Value::str(rule)]);
    conn.call(m, Duration::from_secs(5))
        .map_err(|e| format!("AddMatch: {e}"))?;
    request_name(&conn, opts.replace)?;
    watch::spawn(Arc::clone(&server), Arc::clone(&stop));
    eprintln!(
        "kepr secret-service: serving {} as {}",
        n::BUS_NAME,
        conn.unique_name()
    );
    server.audit.record(
        &Caller::unknown(conn.unique_name()),
        "Start",
        "-",
        None,
        "ok",
    );
    while STOPS.load(Ordering::SeqCst) == 0 && !stop.load(Ordering::SeqCst) && !conn.is_closed() {
        if RELOAD.swap(false, Ordering::SeqCst) {
            server.set_policy(load_policy(&opts.policy));
            eprintln!("kepr secret-service: policy reloaded");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    stop.store(true, Ordering::SeqCst);
    server.audit.record(
        &Caller::unknown(conn.unique_name()),
        "Stop",
        "-",
        None,
        "ok",
    );
    conn.close();
    Ok(())
}
