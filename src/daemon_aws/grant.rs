// daemon_aws/grant.rs — just-in-time grants (T7.10).
//
// A sealed credential marked `jit` in its `.meta` is resolved for an
// agent session only while a grant for that session's harness is open:
//
//   kepr grant NAME --to claude --for 2h    open a window
//   kepr grant NAME --revoke [--to claude]  close it now
//   kepr grant NAME --jit off               stop asking for grants
//
// `check` is the whole gate-side policy and is called from
// `daemon_gate::resolve_for_gate`, after `check_resolvable`: a window
// only ever *refuses* a resolve, so no new path returns a sealed value.
//
// What this is and isn't: the harness name comes from the `StartGate`
// request of the process that started the session, so it is a routing
// aid like the policy batch's `harness`, not an isolation boundary — any
// process of the same uid can start a session and claim a name. What a
// grant does bound is *when* a credential can be used at all: outside
// every window no session resolves it, whatever it calls itself.

use kepr_core::protocol::Response;
use kepr_core::protocol_aws::{valid_harness, Grant, GrantOp, GRANT_MAX_SECS};

use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};

/// Gate policy: may a session running `harness` resolve this credential?
/// `Err` holds the audit-only reason (the gate sees nothing but the
/// generic refusal).
pub fn check(meta: &CredMeta, harness: Option<&str>, now: u64) -> Result<(), String> {
    if meta.jit != Some(true) {
        return Ok(());
    }
    let Some(h) = harness else {
        return Err("resolve: just-in-time, session has no harness".to_string());
    };
    let open = meta
        .grants
        .iter()
        .flatten()
        .any(|g| g.harness == h && g.until > now);
    if open {
        Ok(())
    } else {
        Err("resolve: no grant open".to_string())
    }
}

/// Drop the windows that have closed.
fn prune(grants: Vec<Grant>, now: u64) -> Vec<Grant> {
    grants.into_iter().filter(|g| g.until > now).collect()
}

/// Apply `op` to `m`; the grants to keep (`None` = none).
fn apply(m: &CredMeta, op: &GrantOp, now: u64) -> Result<(Option<bool>, Vec<Grant>), String> {
    let mut grants = prune(m.grants.clone().unwrap_or_default(), now);
    match op {
        GrantOp::Open { harness, for_secs } => {
            if m.sealed != Some(true) {
                return Err("grants apply to sealed credentials (kepr agent add)".into());
            }
            if !valid_harness(harness) {
                return Err("--to takes a harness name, e.g. claude".into());
            }
            if !(1..=GRANT_MAX_SECS).contains(for_secs) {
                return Err("--for must be between 1 second and 7 days".into());
            }
            grants.retain(|g| &g.harness != harness);
            grants.push(Grant {
                harness: harness.clone(),
                until: now.saturating_add(*for_secs),
            });
            Ok((Some(true), grants))
        }
        GrantOp::Revoke { harness } => {
            match harness {
                Some(h) => grants.retain(|g| &g.harness != h),
                None => grants.clear(),
            }
            Ok((m.jit, grants))
        }
        GrantOp::Jit { on: true } if m.sealed != Some(true) => {
            Err("--jit applies to sealed credentials (kepr agent add)".into())
        }
        // Keeping the windows of a credential nothing asks grants for
        // would be a surprise the next time it is turned back on.
        GrantOp::Jit { on } => Ok((
            Some(*on).filter(|v| *v),
            on.then_some(grants).unwrap_or_default(),
        )),
    }
}

fn grant(uid: u32, upper: &str, op: &GrantOp, now: u64) -> Result<(bool, Vec<Grant>), String> {
    let _lock = crate::daemon_credlock::lock(uid, upper);
    if !crate::store::cred_exists(uid, upper) {
        return Err(crate::crypto::SANITIZED_LOOKUP_ERROR.into());
    }
    let mp = expiry::meta_path_for(&cred_path(uid, upper));
    let mut m = match expiry::read_meta(&mp) {
        None => CredMeta::default(),
        Some(Ok(m)) => m,
        Some(Err(_)) => return Err("credential metadata unreadable".into()),
    };
    let (jit, grants) = apply(&m, op, now)?;
    m.jit = jit;
    m.grants = Some(grants.clone()).filter(|g| !g.is_empty());
    if m.is_empty() {
        expiry::delete_meta(&mp);
    } else {
        expiry::write_meta(&mp, &m)?;
    }
    Ok((jit == Some(true), grants))
}

pub fn handle_grant(uid: u32, username: &str, name: &str, op: GrantOp) -> Response {
    let upper = name.to_uppercase();
    let r = validate_name(name).and_then(|_| grant(uid, &upper, &op, expiry::now_unix()));
    let audit_op = match &op {
        GrantOp::Open { .. } => "grant",
        GrantOp::Revoke { .. } => "grant-revoke",
        GrantOp::Jit { .. } => "grant-jit",
    };
    super::audit_op(audit_op, &upper, uid, username, r.as_ref().map(drop));
    match r {
        Ok((jit, grants)) => Response::Aws(kepr_core::protocol_aws::AwsResponse::AwsGrants {
            name: upper,
            jit,
            grants,
        }),
        Err(e) => Response::fail(e),
    }
}

/// `handle_set` hook: a rotated value keeps the just-in-time policy and
/// its open windows (the credential is the same one).
pub fn carry_over(uid: u32, upper: &str, meta: &mut CredMeta) {
    let Some(Ok(old)) = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))) else {
        return;
    };
    meta.jit = old.jit;
    meta.grants = old.grants;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;
    use kepr_core::protocol::Response;

    fn open(h: &str, secs: u64) -> GrantOp {
        GrantOp::Open {
            harness: h.to_string(),
            for_secs: secs,
        }
    }

    fn grants_of(uid: u32, name: &str) -> (Option<bool>, Vec<Grant>) {
        let m = testkit::meta(uid, name);
        (m.jit, m.grants.unwrap_or_default())
    }

    #[test]
    fn resolve_is_allowed_inside_the_window_and_refused_after() {
        let mut m = CredMeta {
            sealed: Some(true),
            ..Default::default()
        };
        // Not just-in-time: no grant needed.
        assert!(check(&m, None, 0).is_ok());
        let (jit, grants) = apply(&m, &open("claude", 7200), 1000).unwrap();
        (m.jit, m.grants) = (jit, Some(grants));
        assert!(check(&m, Some("claude"), 1000).is_ok());
        assert!(check(&m, Some("claude"), 8199).is_ok());
        assert_eq!(
            check(&m, Some("claude"), 8200),
            Err("resolve: no grant open".into())
        );
        assert!(check(&m, Some("codex"), 1000).is_err());
        assert!(check(&m, None, 1000).is_err());
    }

    #[test]
    fn grant_revoke_and_jit_off() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "K", "v");
        testkit::set(uid, "PLAIN", "v");
        assert!(handle_grant(uid, "t", "PLAIN", open("claude", 60))
            .err_msg()
            .is_some());
        assert!(handle_grant(uid, "t", "NOPE", open("claude", 60))
            .err_msg()
            .is_some());
        assert!(handle_grant(uid, "t", "K", open("a b", 60))
            .err_msg()
            .is_some());
        assert!(handle_grant(uid, "t", "K", open("claude", 0))
            .err_msg()
            .is_some());
        let too_long = open("claude", GRANT_MAX_SECS + 1);
        assert!(handle_grant(uid, "t", "K", too_long).err_msg().is_some());
        let r = handle_grant(uid, "t", "k", open("claude", 7200));
        match r {
            Response::Aws(kepr_core::protocol_aws::AwsResponse::AwsGrants {
                name,
                jit,
                grants,
            }) => {
                assert_eq!((name.as_str(), jit, grants.len()), ("K", true, 1));
                assert!(grants[0].until > expiry::now_unix());
            }
            other => panic!("{other:?}"),
        }
        // A second grant for the same harness replaces the first.
        assert!(handle_grant(uid, "t", "K", open("claude", 60)).is_success());
        assert!(handle_grant(uid, "t", "K", open("codex", 60)).is_success());
        let (jit, grants) = grants_of(uid, "K");
        assert_eq!((jit, grants.len()), (Some(true), 2));
        // A `set` keeps the policy: rotating the key doesn't open it up.
        testkit::set_sealed(uid, "K", "v2");
        assert_eq!(grants_of(uid, "K").1.len(), 2);
        let revoke_one = GrantOp::Revoke {
            harness: Some("claude".into()),
        };
        assert!(handle_grant(uid, "t", "K", revoke_one).is_success());
        let (jit, grants) = grants_of(uid, "K");
        assert_eq!((jit, grants.len()), (Some(true), 1));
        assert_eq!(grants[0].harness, "codex");
        let m = testkit::meta(uid, "K");
        assert!(check(&m, Some("claude"), expiry::now_unix()).is_err());
        assert!(check(&m, Some("codex"), expiry::now_unix()).is_ok());
        // Revoking everything leaves it just-in-time: nothing resolves.
        assert!(handle_grant(uid, "t", "K", GrantOp::Revoke { harness: None }).is_success());
        assert_eq!(grants_of(uid, "K"), (Some(true), vec![]));
        assert!(check(&testkit::meta(uid, "K"), Some("codex"), 0).is_err());
        assert!(handle_grant(uid, "t", "K", GrantOp::Jit { on: false }).is_success());
        assert_eq!(grants_of(uid, "K"), (None, vec![]));
        assert!(check(&testkit::meta(uid, "K"), None, 0).is_ok());
        assert!(handle_grant(uid, "t", "PLAIN", GrantOp::Jit { on: true })
            .err_msg()
            .is_some());
        assert!(handle_grant(uid, "t", "K", GrantOp::Jit { on: true }).is_success());
        assert_eq!(grants_of(uid, "K"), (Some(true), vec![]));
    }

    /// The real resolve path (daemon_gate.rs), not just `check`.
    #[test]
    fn the_gate_resolves_a_jit_credential_only_inside_a_grant() {
        let uid = testkit::uid();
        testkit::set_sealed(uid, "JIT", "sk-test-value");
        assert!(handle_grant(uid, "t", "JIT", GrantOp::Jit { on: true }).is_success());
        let owner = |harness: Option<&str>| crate::daemon_gate::GateOwner {
            uid,
            username: "t".into(),
            pid: std::process::id() as i32,
            creds: ["JIT".to_string()].into_iter().collect(),
            rec: crate::daemon_gatex::recording::Recorder::new(uid, "0123456789abcdef", false),
            harness: harness.map(str::to_string),
        };
        let resolve = |h: Option<&str>| {
            crate::daemon_gate::resolve_for_gate(&owner(h), "JIT", "api.example.com", 443)
        };
        assert!(resolve(Some("claude")).is_err(), "no grant yet");
        assert!(resolve(None).is_err());
        assert!(handle_grant(uid, "t", "JIT", open("claude", 3600)).is_success());
        let (value, _) = resolve(Some("claude")).expect("granted");
        assert_eq!(value.as_str(), "sk-test-value");
        assert!(resolve(Some("codex")).is_err(), "another harness");
        let revoke = GrantOp::Revoke {
            harness: Some("claude".into()),
        };
        assert!(handle_grant(uid, "t", "JIT", revoke).is_success());
        assert!(resolve(Some("claude")).is_err(), "revoked");
        // Not just-in-time any more: the usual sealed rules apply.
        assert!(handle_grant(uid, "t", "JIT", GrantOp::Jit { on: false }).is_success());
        assert!(resolve(None).is_ok());
    }

    #[test]
    fn closed_windows_are_dropped_on_the_next_change() {
        let m = CredMeta {
            sealed: Some(true),
            jit: Some(true),
            grants: Some(vec![
                Grant {
                    harness: "old".into(),
                    until: 500,
                },
                Grant {
                    harness: "live".into(),
                    until: 2000,
                },
            ]),
            ..Default::default()
        };
        let (_, grants) = apply(&m, &GrantOp::Revoke { harness: None }, 1000).unwrap();
        assert!(grants.is_empty());
        let (_, grants) = apply(&m, &open("new", 60), 1000).unwrap();
        let names: Vec<&str> = grants.iter().map(|g| g.harness.as_str()).collect();
        assert_eq!(names, ["live", "new"]);
    }
}
