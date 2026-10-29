// daemon_policy/enforce.rs — T6.11: load `policy.toml` and enforce it
// before a governed request reaches its handler.
//
// The file is read at start and again on SIGHUP (or `kepr policy
// reload`). Absent = no policy (today's behaviour). Present but invalid
// = every governed operation is denied until it is fixed (fail closed),
// and the parse error is on stderr and in `kepr policy status`.
//
// Denied reads answer the usual "credential unavailable"; denied writes
// and shares say "denied by policy". The precise reason goes to the
// audit log as `policy-deny`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kepr_core::policy::{Ctx, Decision, PolicyFile};
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_records::RecordsRequest;
use kepr_core::protocol_session::SessionRequest;
use kepr_core::protocol_sharing::SharingRequest;

use crate::audit::{self, AuditEvent, AuditResult};

pub enum Loaded {
    Absent,
    Active(PolicyFile),
    Broken(String),
}

static CURRENT: Mutex<Option<Arc<Loaded>>> = Mutex::new(None);
static HUP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_hup(_: libc::c_int) {
    HUP.store(true, Ordering::SeqCst); // async-signal-safe
}

/// `~/.config/kepr/policy.toml` (user mode) or `/etc/kepr/policy.toml`;
/// `KEPR_POLICY_FILE` overrides both (the daemon's own environment).
pub fn policy_path() -> PathBuf {
    if let Some(p) = std::env::var_os("KEPR_POLICY_FILE") {
        return PathBuf::from(p);
    }
    if !crate::user_mode() {
        return PathBuf::from("/etc/kepr/policy.toml");
    }
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        })
        .join("kepr/policy.toml")
}

pub fn parse(text: &str) -> Result<PolicyFile, String> {
    let file: PolicyFile = toml::from_str(text).map_err(|e| e.to_string())?;
    file.validate()?;
    Ok(file)
}

fn load() -> Loaded {
    match std::fs::read_to_string(policy_path()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded::Absent,
        Err(e) => Loaded::Broken(format!("cannot read the policy file: {e}")),
        Ok(text) => parse(&text).map_or_else(Loaded::Broken, Loaded::Active),
    }
}

/// Re-read the file now.
pub fn reload() -> Arc<Loaded> {
    let loaded = Arc::new(load());
    if let Loaded::Broken(e) = &*loaded {
        eprintln!("[kepr-daemon] policy file has errors; governed operations are denied: {e}");
    }
    if let Ok(mut cur) = CURRENT.lock() {
        *cur = Some(Arc::clone(&loaded));
    }
    loaded
}

/// Load the policy and reload it on SIGHUP. Called once at start.
pub fn init() {
    let handler: extern "C" fn(libc::c_int) = on_hup;
    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGHUP, handler as libc::sighandler_t);
    }
    reload();
}

pub fn current() -> Arc<Loaded> {
    if HUP.swap(false, Ordering::SeqCst) {
        return reload();
    }
    let cached = CURRENT.lock().ok().and_then(|c| c.clone());
    cached.unwrap_or_else(reload)
}

/// Hosts a record seal will bind (`host` field of the record's fields).
fn record_host(fields: &str) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Host {
        host: Option<String>,
    }
    serde_json::from_str::<Host>(fields)
        .ok()
        .and_then(|h| h.host)
        .into_iter()
        .collect()
}

/// The governed op, credential names to check, bound hosts and TTL of a
/// request.
type Governed = (&'static str, Vec<String>, Vec<String>, Option<u64>);

/// What a request asks for; `None` for requests the policy doesn't govern.
fn governed(
    uid: u32,
    request: &Request,
    get_op: impl FnOnce() -> &'static str,
) -> Option<Governed> {
    Some(match request {
        // `kepr serve` (T11.19) reads through `GetQuiet`, `--pull` (T3.06)
        // through `FetchFd`: the same read.
        Request::Get { name, .. }
        | Request::Session(SessionRequest::GetQuiet { name })
        | Request::Session(SessionRequest::FetchFd { name }) => {
            let upper = name.to_uppercase();
            let target = crate::daemon_store::resolve_alias(uid, &upper);
            let mut names = vec![upper];
            if !names.contains(&target) {
                names.push(target); // an alias may not widen its target's policy
            }
            (get_op(), names, vec![], None)
        }
        // T13.28: a Secret Service secret read is a read of that item's
        // credential, so a policy that denies `get` of `SSI_*` covers it.
        Request::Desktop(kepr_core::protocol_desktop::DesktopRequest::SsItemSecret { id }) => {
            let name = format!("SSI_{}", id.to_uppercase());
            (get_op(), vec![name], vec![], None)
        }
        Request::Set {
            name,
            ttl_secs,
            sealed,
            bindings,
            ..
        } => {
            let hosts = bindings.iter().flatten().map(|b| b.host.clone()).collect();
            let op = if *sealed == Some(true) { "seal" } else { "set" };
            (op, vec![name.to_uppercase()], hosts, *ttl_secs)
        }
        Request::RecordSet {
            name, fields, seal, ..
        } => {
            let (op, hosts) = match seal {
                true => ("seal", record_host(fields.as_str())),
                false => ("set", vec![]),
            };
            (op, vec![name.to_uppercase()], hosts, None)
        }
        Request::Records(RecordsRequest::AttachGet { name, .. }) => {
            ("get", vec![name.to_uppercase()], vec![], None)
        }
        // T11.7: a convert rewrites the value.
        Request::Records(RecordsRequest::RecordConvert { name, .. }) => {
            ("set", vec![name.to_uppercase()], vec![], None)
        }
        Request::ShareSend { name, .. } => ("share", vec![name.to_uppercase()], vec![], None),
        // A one-time link (T6.04) is a share too.
        Request::Sharing(SharingRequest::ShareLinkCreate { name, .. }) => {
            ("share", vec![name.to_uppercase()], vec![], None)
        }
        _ => return None,
    })
}

/// `Some(refusal)` when the policy denies `request`; `None` to proceed.
pub fn enforce(uid: u32, peer_pid: i32, username: &str, request: &Request) -> Option<Response> {
    decide(&current(), (uid, peer_pid), username, request)
}

fn decide(
    loaded: &Loaded,
    (uid, peer_pid): (u32, i32),
    username: &str,
    request: &Request,
) -> Option<Response> {
    if let Loaded::Absent = loaded {
        return None;
    }
    let caller = std::cell::OnceCell::new();
    let inspect = || caller.get_or_init(|| super::caller::inspect(peer_pid));
    let (op, names, hosts, ttl) = governed(uid, request, || inspect().get_op)?;
    let decision = match loaded {
        Loaded::Absent => return None,
        Loaded::Broken(_) => Decision::Deny(None, "the policy file has errors".into()),
        Loaded::Active(policy) => {
            let c = inspect();
            let roles = super::roles::held(policy, uid, username, peer_pid);
            names
                .iter()
                .map(|name| {
                    policy.check(&Ctx {
                        op,
                        name,
                        exe: c.exe.as_deref(),
                        parent: c.parent.as_deref(),
                        harness: c.harness.as_deref(),
                        roles: &roles,
                        hosts: &hosts,
                        ttl,
                    })
                })
                .find(|d| !d.allowed())
                .unwrap_or(Decision::Allow(0))
        }
    };
    let Decision::Deny(_, why) = decision else {
        return None;
    };
    audit::log(&AuditEvent {
        op: "policy-deny",
        name: names.first().map(String::as_str),
        uid,
        username,
        result: AuditResult::Fail(format!("{op}: {why}")),
    });
    Some(match op {
        "get" | "exec" | "export" => Response::fail("credential unavailable"),
        _ => Response::fail(format!("denied by policy: {why}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::generate::ZeroString;

    fn get(name: &str) -> Request {
        Request::Get {
            name: name.into(),
            fido2_assertion: None,
        }
    }

    #[test]
    fn parse_rejects_typos_and_unknown_ops() {
        assert!(parse("[[rule]]\neffect = \"allow\"\nops = [\"get\"]\nname = [\"A\"]\n").is_err());
        assert!(parse("[[rule]]\neffect = \"allow\"\nops = [\"read\"]\n").is_err());
        assert!(parse("[[rule]]\neffect = \"permit\"\nops = [\"get\"]\n").is_err());
        let p = parse("[[rule]]\neffect = \"allow\"\nops = [\"*\"]\n").unwrap();
        assert_eq!(p.rules.len(), 1);
        assert!(parse("").unwrap().rules.is_empty());
    }

    #[test]
    fn roles_parse_from_toml_and_run_in_policy_tests() {
        let p = parse(
            "[roles.ops]\nmembers = [\"group:ops\"]\n\
             [[rule]]\neffect = \"allow\"\nops = [\"get\"]\nrole = [\"ops\"]\n\
             [[test]]\nop = \"get\"\nname = \"A\"\nroles = [\"ops\"]\nexpect = \"allow\"\n\
             [[test]]\nop = \"get\"\nname = \"A\"\nexpect = \"deny\"\n",
        )
        .unwrap();
        assert!(p.run_tests().0);
        assert!(parse("[[rule]]\neffect = \"allow\"\nops = [\"get\"]\nrole = [\"x\"]\n").is_err());
        assert!(parse("[roles.a]\nmembers = [\"alice\"]\n").is_err());
    }

    #[test]
    fn governed_requests() {
        let (op, names, _, _) = governed(4242, &get("a"), || "exec").unwrap();
        assert_eq!((op, names), ("exec", vec!["A".to_string()]));
        let quiet = Request::Session(SessionRequest::GetQuiet { name: "a".into() });
        let (op, names, _, _) = governed(4242, &quiet, || "get").unwrap();
        assert_eq!((op, names), ("get", vec!["A".to_string()]));
        let pull = Request::Session(SessionRequest::FetchFd { name: "b".into() });
        let (op, names, _, _) = governed(4242, &pull, || "get").unwrap();
        assert_eq!((op, names), ("get", vec!["B".to_string()]));
        let set = Request::Set {
            name: "k".into(),
            value: Some(ZeroString::from_string("v".into())),
            generate: None,
            ttl_secs: Some(60),
            requires_consent: None,
            requires_fido2: None,
            sealed: Some(true),
            bindings: Some(vec![kepr_core::binding::Binding {
                host: "api.x.ai".into(),
                port: 443,
                inject: kepr_core::binding::Inject::Bearer,
            }]),
        };
        let (op, names, hosts, ttl) = governed(1, &set, || "get").unwrap();
        assert_eq!(op, "seal");
        assert_eq!(names, vec!["K".to_string()]);
        assert_eq!((hosts, ttl), (vec!["api.x.ai".to_string()], Some(60)));
        let rec = Request::RecordSet {
            name: "db".into(),
            record_type: "database".into(),
            fields: ZeroString::from_string(r#"{"host":"db.internal","password":"p"}"#.into()),
            requires_consent: None,
            seal: true,
        };
        let (op, _, hosts, _) = governed(1, &rec, || "get").unwrap();
        assert_eq!((op, hosts), ("seal", vec!["db.internal".to_string()]));
        assert!(governed(1, &Request::List, || "get").is_none());
    }

    fn is_err(r: &Option<Response>, text: &str) -> bool {
        matches!(r, Some(Response::Err { error }) if error.contains(text))
    }

    #[test]
    fn absent_policy_allows_and_broken_denies() {
        let me = (4242, std::process::id() as i32);
        assert!(decide(&Loaded::Absent, me, "u", &get("A")).is_none());
        let broken = Loaded::Broken("bad".into());
        assert!(is_err(
            &decide(&broken, me, "u", &get("A")),
            "credential unavailable"
        ));
        assert!(decide(&broken, me, "u", &Request::List).is_none());
        let share = Request::ShareSend {
            name: "a".into(),
            to: "x".into(),
            ttl_secs: None,
            view_window_secs: None,
        };
        assert!(is_err(
            &decide(&broken, me, "u", &share),
            "denied by policy"
        ));
    }

    #[test]
    fn active_policy_matches_this_caller() {
        let me = (4242, std::process::id() as i32);
        let exe = std::env::current_exe().unwrap();
        let text = format!(
            "[[rule]]\neffect = \"deny\"\nops = [\"get\"]\nnames = [\"SECRET*\"]\n\n\
             [[rule]]\neffect = \"allow\"\nops = [\"get\"]\nexe = [\"{}\"]\n",
            exe.display()
        );
        let p = Loaded::Active(parse(&text).unwrap());
        assert!(decide(&p, me, "u", &get("token")).is_none());
        assert!(is_err(
            &decide(&p, me, "u", &get("secret_x")),
            "credential unavailable"
        ));
        let share = Request::ShareSend {
            name: "token".into(),
            to: "x".into(),
            ttl_secs: None,
            view_window_secs: None,
        };
        assert!(is_err(
            &decide(&p, me, "u", &share),
            "no rule allows share of TOKEN"
        ));
        let link = Request::Sharing(SharingRequest::ShareLinkCreate {
            name: "token".into(),
            ttl_secs: Some(60),
            self_destruct: None,
            relay: None,
            view_window_secs: None,
        });
        assert!(is_err(
            &decide(&p, me, "u", &link),
            "no rule allows share of TOKEN"
        ));
    }
}
