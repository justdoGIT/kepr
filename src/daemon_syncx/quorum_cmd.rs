// daemon_syncx/quorum_cmd.rs — T7.12 request handlers (quorum.rs holds
// the requirement, requests and windows; quorum_device.rs the device
// approvals).
//
//   QuorumSet      raise N at once; lowering it or `off` opens a request
//   QuorumRequest  ask for a use window
//   QuorumApprove  the owner here (polkit), or an enrolled device's approval
//   QuorumSign     on another device: approve a request it printed
//   QuorumList     requirements, open requests and windows

use kepr_core::protocol::Response;
use kepr_core::protocol_syncx::{QuorumKey, QuorumOpen, QuorumState, SyncxResponse};

use super::audit_r;
use super::quorum::{self, Action, Pending, MAX_APPROVALS, MAX_WINDOW, OWNER};
use super::quorum_device::{self, Ask};
use crate::daemon_sharing::kem::Recipient;
use crate::expiry::{self, CredMeta};
use crate::store::{cred_exists, cred_path, validate_name};

fn meta_of(uid: u32, name: &str) -> Result<CredMeta, String> {
    match expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, name))) {
        None => Ok(CredMeta::default()),
        Some(Ok(m)) => Ok(m),
        Some(Err(_)) => Err("credential unavailable".into()),
    }
}

/// `name`, upper-cased, if it is one of `uid`'s credentials.
fn existing(uid: u32, name: &str) -> Result<String, String> {
    validate_name(name)?;
    let upper = name.to_uppercase();
    if !cred_exists(uid, &upper) {
        return Err("credential unavailable".into());
    }
    Ok(upper)
}

fn devices(uid: u32) -> Vec<Recipient> {
    crate::daemon_sharing::devices::sync_recipients(uid)
        .iter()
        .filter_map(|t| Recipient::parse(t).ok())
        .collect()
}

/// The request as devices see it (owner = our share key).
fn ask(uid: u32, p: &Pending) -> Result<Ask, String> {
    let me = crate::daemon_share::load_secret(uid)?;
    Ok(Ask {
        owner: me.recipient().text(),
        id: p.id.clone(),
        name: p.name.clone(),
        action: p.action.text(),
        expires_at: p.expires_at,
    })
}

fn status(uid: u32, p: &Pending, done: bool, now: u64) -> Response {
    let request = match ask(uid, p) {
        Ok(a) => a.text(),
        Err(e) => return Response::fail(e),
    };
    SyncxResponse::QuorumStatus(Box::new(QuorumState {
        id: p.id.clone(),
        name: p.name.clone(),
        action: p.action.text(),
        have: p.approvers.len() as u32,
        need: u32::from(quorum::need(uid, &p.name)),
        expires_at: p.expires_at,
        request,
        until: quorum::window(uid, &p.name, now),
        done,
    }))
    .into()
}

/// Write the requirement into `name`'s meta, under its lock.
fn store_need(uid: u32, name: &str, n: u8) -> Result<(), String> {
    let _lock = crate::daemon_credlock::lock(uid, name);
    let mut meta = meta_of(uid, name)?;
    meta.approvals = (n >= 2).then_some(n);
    expiry::write_meta(&expiry::meta_path_for(&cred_path(uid, name)), &meta)
        .map_err(|e| e.to_string())?;
    crate::daemon_gate::bump_generation();
    Ok(())
}

pub fn handle_set(uid: u32, username: &str, name: &str, n: u32, now: u64) -> Response {
    let r = (|| {
        let upper = existing(uid, name)?;
        let n = u8::try_from(n)
            .ok()
            .filter(|n| *n == 0 || (2..=MAX_APPROVALS).contains(n));
        let n = n.ok_or(format!("approvals: 2 to {MAX_APPROVALS}, or off"))?;
        let meta = meta_of(uid, &upper)?;
        if meta.ssh.is_some() || meta.share_key == Some(true) {
            return Err("sign-only keys don't take approvals".into());
        }
        let current = meta.approvals.unwrap_or(0);
        if n >= current {
            store_need(uid, &upper, n)?;
            return Ok((upper, n, None));
        }
        // Weakening the requirement needs the current quorum.
        let p = quorum::open(uid, &upper, Action::Relax(n), now)?;
        Ok((upper, current, Some(p)))
    })();
    audit_r("quorum-set", uid, username, Some(name), &r);
    match r {
        Ok((_, _, Some(p))) => status(uid, &p, false, now),
        Ok((name, n, None)) => SyncxResponse::QuorumSetOk {
            name,
            approvals: u32::from(n),
        }
        .into(),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_request(uid: u32, username: &str, name: &str, secs: u64, now: u64) -> Response {
    let r = (|| {
        let upper = existing(uid, name)?;
        if !(1..=MAX_WINDOW).contains(&secs) {
            return Err("--for: 1 second to 24 hours".to_string());
        }
        if quorum::need(uid, &upper) < 2 {
            return Err(format!(
                "{upper} needs no approvals (kepr quorum set {upper} N)"
            ));
        }
        let p = quorum::open(uid, &upper, Action::Use(secs), now)?;
        ask(uid, &p)?; // a share key to show devices the request
        Ok(p)
    })();
    audit_r("quorum-request", uid, username, Some(name), &r);
    match r {
        Ok(p) => status(uid, &p, false, now),
        Err(e) => Response::fail(e),
    }
}

/// `approval`: an enrolled device's; None: the owner here, by polkit.
pub fn handle_approve(
    uid: u32,
    username: &str,
    (id, approval): (&str, Option<&str>),
    consent: impl FnOnce() -> bool,
    now: u64,
) -> Response {
    let r = (|| {
        let p = quorum::find(uid, id, now)?;
        let approver = match approval {
            Some(text) => {
                let me = crate::daemon_share::load_secret(uid)?;
                quorum_device::verify(&me, &devices(uid), &ask(uid, &p)?, text)?
            }
            None => OWNER.to_string(),
        };
        if p.approvers.contains(&approver) {
            let who = quorum::shown(&approver);
            return Err(format!("{who} already approved request {id}"));
        }
        if approval.is_none() && !consent() {
            return Err("approval denied".to_string());
        }
        let (p, done) = quorum::approve(uid, id, &approver, quorum::need(uid, &p.name), now)?;
        if let (true, Action::Relax(n)) = (done, p.action) {
            store_need(uid, &p.name, n)?;
        }
        Ok((p, done, approver))
    })();
    let name = r.as_ref().ok().map(|(p, _, _)| p.name.clone());
    audit_r("quorum-approve", uid, username, name.as_deref(), &r);
    match r {
        Ok((p, done, _)) => status(uid, &p, done, now),
        Err(e) => Response::fail(e),
    }
}

/// On another device: approve a request whose owner is enrolled here.
pub fn handle_sign(
    uid: u32,
    username: &str,
    request: &str,
    consent: impl FnOnce() -> bool,
    now: u64,
) -> Response {
    let r = (|| {
        let a = Ask::parse(request)?;
        if a.expires_at <= now {
            return Err("that approval request has expired".to_string());
        }
        let owner = Recipient::parse(&a.owner)?;
        let me = crate::daemon_share::load_secret(uid)?;
        if owner.x25519() == me.recipient().x25519() {
            return Err(format!(
                "that request is yours: kepr quorum approve {}",
                a.id
            ));
        }
        if !devices(uid).iter().any(|d| d.x25519() == owner.x25519()) {
            return Err("that request is from a device not enrolled here (kepr device ls)".into());
        }
        if !consent() {
            return Err("approval denied".into());
        }
        Ok((quorum_device::sign(&me, &a)?, a.name))
    })();
    let name = r.as_ref().ok().map(|(_, n)| n.clone());
    audit_r("quorum-sign", uid, username, name.as_deref(), &r);
    match r {
        Ok((approval, _)) => SyncxResponse::QuorumApproval { approval }.into(),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_list(uid: u32, now: u64) -> Response {
    let (pending, windows) = quorum::snapshot(uid, now);
    let keys = crate::store::list_for_uid(uid)
        .into_iter()
        .filter(|(n, _)| validate_name(n).is_ok())
        .filter_map(|(n, _)| {
            let need = quorum::need(uid, &n);
            (need >= 2).then(|| QuorumKey {
                until: windows.iter().find(|(w, _)| *w == n).map(|(_, u)| *u),
                name: n,
                approvals: u32::from(need),
            })
        })
        .collect();
    let open = pending
        .iter()
        .map(|p| QuorumOpen {
            id: p.id.clone(),
            name: p.name.clone(),
            action: p.action.text(),
            have: p.approvers.len() as u32,
            need: u32::from(quorum::need(uid, &p.name)),
            expires_at: p.expires_at,
        })
        .collect();
    SyncxResponse::QuorumList { keys, open }.into()
}

#[cfg(test)]
mod tests {
    use super::super::quorum::REQUEST_TTL;
    use super::super::testutil::{device, enroll, pair, try_enroll};
    use super::*;
    use crate::daemon_store::testkit;
    use crate::expiry::now_unix;

    fn readable(uid: u32, name: &str) -> bool {
        crate::daemon_handlers_get::precheck_meta(uid, 0, name).is_ok()
    }

    /// (id, have, done, request text)
    fn status_of(r: Response) -> (String, u32, bool, String) {
        match r {
            Response::Syncx(SyncxResponse::QuorumStatus(q)) => (q.id, q.have, q.done, q.request),
            other => panic!("{other:?}"),
        }
    }

    fn err(r: Response) -> String {
        r.err_msg()
            .unwrap_or_else(|| panic!("not an error: {r:?}"))
            .to_string()
    }

    fn sign(on: u32, request: &str, now: u64) -> String {
        match handle_sign(on, "t", request, || true, now) {
            Response::Syncx(SyncxResponse::QuorumApproval { approval }) => approval,
            other => panic!("{other:?}"),
        }
    }

    fn no_prompt() -> bool {
        panic!("no prompt expected")
    }

    /// `name` on `a` with `n` approvals required.
    fn guarded(a: u32, name: &str, n: u32, now: u64) {
        testkit::set(a, name, "v");
        let r = handle_set(a, "t", name, n, now);
        assert!(
            matches!(r, Response::Syncx(SyncxResponse::QuorumSetOk { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn one_approval_is_not_enough() {
        let (a, b) = pair();
        let now = now_unix();
        guarded(a, "QA_KEY", 2, now);
        assert!(!readable(a, "QA_KEY"));
        let (id, _, _, request) = status_of(handle_request(a, "t", "QA_KEY", 3600, now));
        let (_, have, done, _) = status_of(handle_approve(a, "t", (&id, None), || true, now));
        assert_eq!((have, done), (1, false));
        assert!(!readable(a, "QA_KEY"), "one approval opened it");
        let approval = sign(b, &request, now);
        let (_, have, done, _) = status_of(handle_approve(
            a,
            "t",
            (&id, Some(&approval)),
            no_prompt,
            now,
        ));
        assert_eq!((have, done), (2, true));
        assert!(readable(a, "QA_KEY"));
        // An agent gate's resolve checks the same window.
        testkit::set_sealed(a, "QA_SEALED", "s");
        guarded_meta(a, "QA_SEALED", now);
        let meta = testkit::meta(a, "QA_SEALED");
        assert!(super::super::quorum_gate(a, "QA_SEALED", &meta).is_err());
        // The window ends: closed by the sweeper, refused again.
        let (id, _, _, request) = status_of(handle_request(a, "t", "QA_SEALED", 60, now));
        status_of(handle_approve(a, "t", (&id, None), || true, now));
        status_of(handle_approve(
            a,
            "t",
            (&id, Some(&sign(b, &request, now))),
            no_prompt,
            now,
        ));
        assert!(super::super::quorum_gate(a, "QA_SEALED", &meta).is_ok());
        quorum::sweep(now + 61);
        assert!(super::super::quorum_gate(a, "QA_SEALED", &meta).is_err());
        assert!(readable(a, "QA_KEY"), "only the closed window went");
    }

    fn guarded_meta(a: u32, name: &str, now: u64) {
        let r = handle_set(a, "t", name, 2, now);
        assert!(
            matches!(r, Response::Syncx(SyncxResponse::QuorumSetOk { .. })),
            "{r:?}"
        );
    }

    /// `approval` with its `from` rewritten as the V1 text of the same
    /// X25519 key (the MAC doesn't cover that text).
    fn v1_alias(approval: &str) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let raw = b64
            .decode(approval.strip_prefix("kepr-approval1-").unwrap())
            .unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let from = Recipient::parse(v["from"].as_str().unwrap()).unwrap();
        assert!(matches!(from, Recipient::V2 { .. }));
        v["from"] = Recipient::V1(*from.x25519()).text().into();
        format!(
            "kepr-approval1-{}",
            b64.encode(serde_json::to_vec(&v).unwrap())
        )
    }

    /// Security review (T7.12): one device's approval re-encoded under
    /// another text of its key must not count as a second approver.
    #[test]
    fn one_device_counts_once_whatever_its_key_text() {
        let (a, b) = pair();
        let now = now_unix();
        guarded(a, "QV_KEY", 2, now);
        let (id, _, _, request) = status_of(handle_request(a, "t", "QV_KEY", 3600, now));
        let approval = sign(b, &request, now);
        let alias = v1_alias(&approval);
        let (_, have, done, _) = status_of(handle_approve(
            a,
            "t",
            (&id, Some(&approval)),
            no_prompt,
            now,
        ));
        assert_eq!((have, done), (1, false));
        let e = err(handle_approve(a, "t", (&id, Some(&alias)), no_prompt, now));
        assert!(e.contains("already approved"), "{e}");
        assert!(!readable(a, "QV_KEY"), "one device opened a 2-of-N window");
    }

    /// Security review (T7.12 / T6.10): a program running as the owner
    /// can't enrol keys it made itself (no human approved them) and then
    /// approve its own request with them.
    #[test]
    fn the_owners_malware_cannot_enrol_its_own_approvers() {
        let a = device();
        let (r1, r2) = (device(), device());
        for r in [r1, r2] {
            // A client whose polkit check can't pass (pid 0: fail closed).
            let e = err(try_enroll(a, r, 0));
            assert!(e.contains("approval"), "{e}");
            enroll(r, a);
        }
        let now = now_unix();
        guarded(a, "QM_KEY", 2, now);
        let (id, _, _, request) = status_of(handle_request(a, "t", "QM_KEY", 3600, now));
        for r in [r1, r2] {
            let approval = sign(r, &request, now);
            let e = err(handle_approve(
                a,
                "t",
                (&id, Some(&approval)),
                no_prompt,
                now,
            ));
            assert!(e.contains("not enrolled"), "{e}");
        }
        assert!(!readable(a, "QM_KEY"), "self-enrolled keys opened a window");
    }

    #[test]
    fn a_duplicate_approver_is_refused() {
        let (a, b) = pair();
        let now = now_unix();
        guarded(a, "QD_KEY", 3, now);
        let (id, _, _, request) = status_of(handle_request(a, "t", "QD_KEY", 600, now));
        status_of(handle_approve(a, "t", (&id, None), || true, now));
        let e = err(handle_approve(a, "t", (&id, None), no_prompt, now));
        assert!(e.contains("already approved"), "{e}");
        let approval = sign(b, &request, now);
        status_of(handle_approve(
            a,
            "t",
            (&id, Some(&approval)),
            no_prompt,
            now,
        ));
        let again = sign(b, &request, now);
        let e = err(handle_approve(a, "t", (&id, Some(&again)), no_prompt, now));
        assert!(e.contains("already approved"), "{e}");
        assert!(!readable(a, "QD_KEY"), "2 of 3");
    }

    #[test]
    fn an_expired_request_is_refused() {
        let (a, b) = pair();
        let now = now_unix();
        guarded(a, "QE_KEY", 2, now);
        let (id, _, _, request) = status_of(handle_request(a, "t", "QE_KEY", 600, now));
        let late = now + REQUEST_TTL;
        let e = err(handle_sign(b, "t", &request, no_prompt, late));
        assert!(e.contains("expired"), "{e}");
        let e = err(handle_approve(a, "t", (&id, None), no_prompt, late));
        assert!(e.contains("expired"), "{e}");
        let e = err(handle_approve(a, "t", (&id, None), no_prompt, now));
        assert!(e.contains("no such approval request"), "{e}");
    }

    #[test]
    fn strangers_refusals_and_own_requests_never_count() {
        let (a, b) = pair();
        let (c, now) = (device(), now_unix());
        enroll(c, a); // c trusts a; a never enrolled c
        guarded(a, "QS_KEY", 2, now);
        let (id, _, _, request) = status_of(handle_request(a, "t", "QS_KEY", 600, now));
        let e = err(handle_approve(
            a,
            "t",
            (&id, Some(&sign(c, &request, now))),
            no_prompt,
            now,
        ));
        assert!(e.contains("not enrolled here"), "{e}");
        assert!(err(handle_approve(a, "t", (&id, None), || false, now)).contains("denied"));
        assert!(err(handle_sign(a, "t", &request, no_prompt, now)).contains("is yours"));
        assert!(err(handle_sign(b, "t", &request, || false, now)).contains("denied"));
        let stranger = device();
        assert!(
            err(handle_sign(stranger, "t", &request, no_prompt, now)).contains("not enrolled here")
        );
        let (_, have, _, _) = status_of(handle_approve(a, "t", (&id, None), || true, now));
        assert_eq!(have, 1, "nothing above counted");
    }

    /// T7.10: on a just-in-time credential the approved window is a
    /// grant, and the owner's own grant is not one.
    #[test]
    fn an_approved_request_opens_a_jit_grant() {
        let (a, b) = pair();
        let now = now_unix();
        testkit::set_sealed(a, "QJ_KEY", "v");
        guarded_meta(a, "QJ_KEY", now);
        let jit = crate::daemon_aws::grant::handle_grant(
            a,
            "t",
            "QJ_KEY",
            kepr_core::protocol_aws::GrantOp::Jit { on: true },
        );
        assert!(jit.is_success(), "{jit:?}");
        let meta = || testkit::meta(a, "QJ_KEY");
        assert!(super::super::quorum_gate(a, "QJ_KEY", &meta()).is_err());
        // The owner's own grant doesn't satisfy the requirement.
        let own = crate::daemon_aws::grant::handle_grant(
            a,
            "t",
            "QJ_KEY",
            kepr_core::protocol_aws::GrantOp::Open {
                harness: "claude".into(),
                for_secs: 3600,
            },
        );
        assert!(own.is_success(), "{own:?}");
        assert!(super::super::quorum_gate(a, "QJ_KEY", &meta()).is_err());
        let (id, _, _, request) = status_of(handle_request(a, "t", "QJ_KEY", 3600, now));
        status_of(handle_approve(a, "t", (&id, None), || true, now));
        let (_, _, done, _) = status_of(handle_approve(
            a,
            "t",
            (&id, Some(&sign(b, &request, now))),
            no_prompt,
            now,
        ));
        assert!(done);
        let m = meta();
        assert!(super::super::quorum_gate(a, "QJ_KEY", &m).is_ok());
        assert_eq!(
            crate::daemon_aws::grant::approved_until(&m),
            Some(now + 3600)
        );
        // Persisted, for any session, and gone when it closes.
        assert!(crate::daemon_aws::grant::check(&m, None, now).is_ok());
        assert!(crate::daemon_aws::grant::check(&m, None, now + 3600).is_err());
        assert!(quorum::window(a, "QJ_KEY", now).is_some(), "shown by ls");
        // The window closes with its own grant: the in-memory sweep has
        // nothing to do, and after it nothing resolves again.
        assert!(quorum::window(a, "QJ_KEY", now + 3601).is_none());
        assert!(quorum::gate(a, "QJ_KEY", &meta(), now + 3601).is_err());
    }

    #[test]
    fn lowering_needs_the_quorum_and_set_keeps_it() {
        let (a, b) = pair();
        let now = now_unix();
        guarded(a, "QL_KEY", 2, now);
        assert!(err(handle_set(a, "t", "QL_KEY", 1, now)).contains("2 to 9"));
        assert!(err(handle_request(a, "t", "QL_KEY", MAX_WINDOW + 1, now)).contains("24 hours"));
        // A new value keeps the requirement.
        let r = crate::daemon_handlers::handle_set(
            a,
            "t",
            "QL_KEY",
            Some("w"),
            None,
            Default::default(),
        );
        assert!(r.is_success());
        assert_eq!(testkit::meta(a, "QL_KEY").approvals, Some(2));
        let (id, _, done, request) = status_of(handle_set(a, "t", "QL_KEY", 0, now));
        assert!(!done);
        assert_eq!(quorum::need(a, "QL_KEY"), 2);
        status_of(handle_approve(a, "t", (&id, None), || true, now));
        let (_, _, done, _) = status_of(handle_approve(
            a,
            "t",
            (&id, Some(&sign(b, &request, now))),
            no_prompt,
            now,
        ));
        assert!(done);
        assert_eq!(testkit::meta(a, "QL_KEY").approvals, None);
        assert!(readable(a, "QL_KEY"));
        let r = handle_list(a, now);
        assert!(
            matches!(r, Response::Syncx(SyncxResponse::QuorumList { ref keys, .. }) if keys.is_empty()),
            "{r:?}"
        );
    }
}
