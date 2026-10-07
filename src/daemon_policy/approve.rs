// daemon_policy/approve.rs — T9.04 request handlers, and `consent`, the
// one consent check `get`, gate resolves and the rest call: the
// registered approver when the credential opts in and one is live,
// otherwise the polkit prompt (as before). See approvals.rs.

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::PolicyResponse;

use super::approvals;
use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};

const VIAS: &[&str] = &["desktop", "ntfy", "any"];

/// Is the consent-gated read of `name` by `peer_pid` approved?
pub fn consent(uid: u32, peer_pid: i32, name: &str, meta: &CredMeta) -> bool {
    if let Some(via) = meta.approve_via.as_deref() {
        let c = super::caller::inspect(peer_pid);
        let requester = format!(
            "{} (pid {peer_pid})",
            c.exe.as_deref().unwrap_or("an unknown program")
        );
        if let Some(answer) = approvals::ask(uid, (name, via, requester), approvals::TIMEOUT) {
            return answer;
        }
    }
    crate::daemon_polkit::consent_granted(peer_pid)
}

fn log(op: &str, name: Option<&str>, uid: u32, username: &str, r: &Result<(), String>) {
    audit::log(&AuditEvent {
        op,
        name,
        uid,
        username,
        result: match r {
            Ok(()) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}

fn done(message: String) -> Response {
    Response::Policy(PolicyResponse::PolicyDone { message })
}

/// `ApproveVia`: opting in changes how consent is asked, so it needs a
/// polkit approval itself; opting out doesn't.
pub fn handle_via(
    uid: u32,
    peer_pid: i32,
    username: &str,
    name: &str,
    via: Option<&str>,
) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(e);
    }
    let upper = name.to_uppercase();
    let r = (|| {
        if let Some(v) = via.filter(|v| !VIAS.contains(v)) {
            return Err(format!(
                "unknown approval channel `{v}` (desktop, ntfy or any)"
            ));
        }
        let _lock = crate::daemon_credlock::lock(uid, &upper);
        let mp = expiry::meta_path_for(&cred_path(uid, &upper));
        if !crate::store::cred_exists(uid, &upper) {
            return Err("credential unavailable".to_string());
        }
        let mut meta = match expiry::read_meta(&mp) {
            Some(Ok(m)) => m,
            Some(Err(_)) => return Err("credential unavailable".to_string()),
            None => CredMeta::default(),
        };
        if meta.requires_consent != Some(true) {
            return Err(
                "only for consent-gated credentials (kepr set NAME --requires-consent)".into(),
            );
        }
        if via.is_some() && !crate::daemon_polkit::consent_granted(peer_pid) {
            return Err("approval denied (polkit)".into());
        }
        meta.approve_via = via.map(String::from);
        expiry::write_meta(&mp, &meta)
    })();
    log("approve-via", Some(&upper), uid, username, &r);
    match r {
        Ok(()) => done(match via {
            Some(v) => format!(
                "{upper}: consent prompts go to the approver ({v}); run kepr approvals serve"
            ),
            None => format!("{upper}: consent prompts use polkit again"),
        }),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_register(uid: u32, peer_pid: i32, username: &str) -> Response {
    let r = approvals::register(uid, peer_pid, || {
        crate::daemon_polkit::consent_granted(peer_pid)
    });
    log(
        "approver-register",
        None,
        uid,
        username,
        &r.as_ref().map(|_| ()).map_err(Clone::clone),
    );
    match r {
        Ok(key) => Response::Policy(PolicyResponse::ApproverKey {
            key,
            timeout_secs: approvals::TIMEOUT.as_secs(),
        }),
        Err(e) => Response::fail(e),
    }
}

/// Polled every second by the approver: not audited.
pub fn handle_poll(uid: u32, peer_pid: i32, key: &str) -> Response {
    match approvals::poll(uid, peer_pid, key) {
        Ok(pending) => Response::Policy(PolicyResponse::ApprovalsPending { pending }),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_answer(
    uid: u32,
    peer_pid: i32,
    username: &str,
    (key, id, token): (&str, &str, &str),
    allow: bool,
) -> Response {
    match approvals::answer(uid, peer_pid, key, (id, token), allow) {
        Ok(name) => {
            let op = if allow {
                "approval-allow"
            } else {
                "approval-deny"
            };
            log(op, Some(&name), uid, username, &Ok(()));
            done(format!(
                "{name}: {}",
                if allow { "allowed" } else { "denied" }
            ))
        }
        Err(e) => {
            log("approval-answer", None, uid, username, &Err(e.clone()));
            Response::fail(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_handlers::{handle_set, SetFlags};
    use crate::daemon_store::testkit;

    fn err(r: Response) -> String {
        r.err_msg().unwrap_or("ok").to_string()
    }

    fn gated(uid: u32, name: &str) {
        let flags = SetFlags {
            requires_consent: Some(true),
            ..Default::default()
        };
        assert!(handle_set(uid, "t", name, Some("v"), None, flags).is_success());
    }

    #[test]
    fn approve_via_needs_a_consent_gated_credential() {
        let uid = testkit::uid();
        testkit::set(uid, "PLAIN", "v");
        assert!(err(handle_via(uid, 1, "t", "PLAIN", Some("ntfy"))).contains("consent-gated"));
        assert_eq!(
            err(handle_via(uid, 1, "t", "NOPE", Some("ntfy"))),
            "credential unavailable"
        );
        assert!(err(handle_via(uid, 1, "t", "PLAIN", Some("pager"))).contains("unknown"));
        assert!(err(handle_via(uid, 1, "t", "../X", None)).contains("invalid"));
        // Clearing needs no polkit approval.
        gated(uid, "GATED");
        let mut m = testkit::meta(uid, "GATED");
        m.approve_via = Some("any".into());
        let mp = expiry::meta_path_for(&cred_path(uid, "GATED"));
        expiry::write_meta(&mp, &m).unwrap();
        assert!(handle_via(uid, 1, "t", "gated", None).is_success());
        assert_eq!(testkit::meta(uid, "GATED").approve_via, None);
        assert_eq!(testkit::meta(uid, "GATED").requires_consent, Some(true));
    }

    #[test]
    fn consent_asks_the_live_approver() {
        let uid = testkit::uid();
        let key = approvals::register(uid, 77, || true).unwrap();
        let meta = CredMeta {
            requires_consent: Some(true),
            approve_via: Some("any".into()),
            ..Default::default()
        };
        let me = std::process::id() as i32;
        let asker = std::thread::spawn(move || consent(uid, me, "K", &meta));
        let p = loop {
            if let Some(p) = approvals::poll(uid, 77, &key).unwrap().pop() {
                break p;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert!(
            p.requester.ends_with(&format!("(pid {me})")),
            "{}",
            p.requester
        );
        assert!(handle_answer(uid, 77, "t", (&key, &p.id, &p.token), true).is_success());
        assert!(asker.join().unwrap());
    }
}
