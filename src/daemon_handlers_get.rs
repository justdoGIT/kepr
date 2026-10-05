// daemon_handlers_get.rs — handle_get and the pre-decrypt meta gate.
//
// Split from daemon_handlers.rs in Phase 2 η to keep the main handler
// file under the 350-LOC ceiling. precheck_meta and handle_get share
// a tight coupling (the meta gate's error string prefix is the
// dispatch signal the get handler uses to choose between "return
// Fido2Needed", "verify assertion", or "credential unavailable"),
// so they belong together even when the other handlers stay in the
// parent module.

use kepr_core::protocol::{Fido2Assertion, Response};

use crate::audit::{self, AuditEvent, AuditResult};
use crate::crypto;
use crate::expiry;
use crate::store::{cred_path, validate_name};

/// Pre-decrypt meta gate for `handle_get`. Returns `Ok(())` to
/// allow the decrypt; returns `Err(reason)` with a precise audit
/// reason that the caller logs and converts into the sanitised
/// wire error "credential unavailable". Pulled out of `handle_get`
/// to keep that function under the per-file LOC ceiling and to
/// give the multiple meta-fail branches one named home.
///
/// `peer_pid` is the SO_PEERCRED-captured PID of the calling
/// process, threaded down for the polkit consent check (Phase 2 ε).
/// Codex P1 from PR #77 review: the polkit subject must be the
/// CALLER's pid, not the daemon's, otherwise polkit evaluates
/// root's authorisation rather than the user's.
pub(crate) fn precheck_meta(uid: u32, peer_pid: i32, name_upper: &str) -> Result<(), String> {
    let mp = expiry::meta_path_for(&cred_path(uid, name_upper));
    let Some(meta_result) = expiry::read_meta(&mp) else {
        return Ok(()); // no meta = no flags = allow
    };
    let meta = match meta_result {
        Ok(m) => m,
        Err(e) => return Err(format!("meta parse: {e}")),
    };
    meta_gate(&meta, expiry::now_unix(), || {
        crate::daemon_polkit::consent_granted(peer_pid)
    })
}

/// Pure policy check over a parsed meta. Sealed wins over everything:
/// a sealed credential is never decrypted for `Get`, and no FIDO2
/// challenge is issued for it (agent vault plan §4.3).
fn meta_gate(
    meta: &expiry::CredMeta,
    now_unix: u64,
    consent: impl FnOnce() -> bool,
) -> Result<(), String> {
    if meta.sealed == Some(true) {
        return Err("sealed".to_string());
    }
    if meta.ssh.is_some() {
        return Err("ssh key (sign-only)".to_string());
    }
    if meta.share_key == Some(true) {
        return Err("share key".to_string());
    }
    if let Some(exp) = meta.expires_at_unix {
        if now_unix >= exp {
            return Err("expired".to_string());
        }
    }
    if matches!(meta.requires_consent, Some(true)) && !consent() {
        return Err("consent denied".to_string());
    }
    // Phase 2 η: FIDO2 gate. The "fido2:" prefix in the error
    // string is the signal `handle_get` uses to decide whether to
    // return a `Fido2Needed` challenge or proceed with assertion
    // verification. Must stay as the prefix for that dispatch.
    if matches!(meta.requires_fido2, Some(true)) {
        return Err("fido2: assertion required".to_string());
    }
    Ok(())
}

pub fn handle_get(
    uid: u32,
    peer_pid: i32,
    username: &str,
    name: &str,
    fido2_assertion: Option<&Fido2Assertion>,
) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(e);
    }

    let upper = name.to_uppercase();
    // T11.5: an alias reads its target, under the target's own policy.
    let (upper, asked) = (crate::daemon_store::resolve_alias(uid, &upper), upper);
    // Check and decrypt under one lock: a sealed `set` can't slip between.
    let _lock = crate::daemon_credlock::lock(uid, &upper);

    // Phase 2 α + ε + η — pre-decrypt meta gate. A cred whose meta
    // says expired/consent-required/parse-failed must look on the
    // wire identical to a not-found cred (sanitised "credential
    // unavailable"). FIDO2-gated creds get special handling: if no
    // assertion was sent, the daemon returns a challenge instead of
    // an error.
    if let Err(reason) = precheck_meta(uid, peer_pid, &upper) {
        // Phase 2 η: if the gate failure is specifically "fido2
        // required" and the client hasn't sent an assertion yet,
        // return a Fido2Needed challenge (which includes the
        // user's registered credential IDs) instead of a generic
        // "credential unavailable". This lets the CLI transparently
        // initiate the FIDO2 ceremony.
        if reason.starts_with("fido2:") && fido2_assertion.is_none() {
            let challenge = match crate::fido2::generate_challenge(uid, &upper) {
                Ok(c) => c,
                Err(e) => {
                    audit::log(&AuditEvent {
                        op: "get",
                        name: Some(&upper),
                        uid,
                        username,
                        result: AuditResult::Fail(format!("fido2 challenge generation: {e}")),
                    });
                    return Response::fail("credential unavailable");
                }
            };
            let credential_ids = crate::fido2::credential_ids_for_uid(uid);
            // If we have no registered credentials for this user,
            // we can't return a useful challenge. In that case,
            // fall through to "credential unavailable" (the user
            // needs to register a key first).
            if credential_ids.is_empty() {
                audit::log(&AuditEvent {
                    op: "get",
                    name: Some(&upper),
                    uid,
                    username,
                    result: AuditResult::Fail("fido2 required but no keys registered".to_string()),
                });
                return Response::fail(
                    "credential unavailable (fido2 required, no keys registered)",
                );
            }
            return Response::Fido2Needed {
                name: upper,
                challenge,
                credential_ids,
            };
        }
        // Phase 2 η: if an assertion WAS sent, verify it. On
        // failure, "credential unavailable" (the precise reason
        // goes to the audit log). A successful verification must
        // fall through to the decrypt path below.
        if reason.starts_with("fido2:") {
            if let Some(assertion) = fido2_assertion {
                if let Err(e) = crate::fido2::verify_assertion(uid, &upper, assertion) {
                    audit::log(&AuditEvent {
                        op: "get",
                        name: Some(&upper),
                        uid,
                        username,
                        result: AuditResult::Fail(format!("fido2 verify fail: {e}")),
                    });
                    return Response::fail("credential unavailable");
                }
            } else {
                return Response::fail("credential unavailable");
            }
        } else {
            // Non-FIDO2 meta failures: "credential unavailable" for
            // all remaining reasons (expired, consent denied, etc.).
            audit::log(&AuditEvent {
                op: "get",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Fail(reason.to_string()),
            });
            return Response::fail("credential unavailable");
        }
    }

    match crypto::default_backend().decrypt(uid, &upper) {
        Ok(secret) => {
            audit::log(&AuditEvent {
                op: "get",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Ok,
            });
            // Move the ZeroString directly into the response — the
            // protocol field is `value: ZeroString`, so the secret
            // bytes never touch a non-zeroising String on the way
            // out. The previous `secret.to_owned_string()` cloned
            // into a plain String that the serializer would then
            // walk; that String dropped without zeroizing.
            Response::GetOk {
                name: asked,
                value: secret,
            }
        }
        Err(e) => {
            audit::log(&AuditEvent {
                op: "get",
                name: Some(&upper),
                uid,
                username,
                result: AuditResult::Fail(e.clone()),
            });
            Response::fail(crypto::sanitize_lookup_error(&e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::binding::{Binding, Inject};

    /// Built directly (not via with_seal, which now rejects sealed +
    /// FIDO2): a meta file written by an older daemon may still hold it,
    /// and Get must refuse it all the same.
    fn sealed_meta() -> expiry::CredMeta {
        expiry::CredMeta {
            expires_at_unix: Some(u64::MAX),
            requires_fido2: Some(true),
            sealed: Some(true),
            bindings: Some(vec![Binding {
                host: "api.x.ai".into(),
                port: 443,
                inject: Inject::Bearer,
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn sealed_wins_over_fido2_and_valid_expiry() {
        assert_eq!(meta_gate(&sealed_meta(), 0, || true), Err("sealed".into()));
    }

    #[test]
    fn unsealed_meta_behaves_as_before() {
        let fido = expiry::CredMeta {
            requires_fido2: Some(true),
            ..Default::default()
        };
        assert!(meta_gate(&fido, 0, || true)
            .unwrap_err()
            .starts_with("fido2:"));
        let expired = expiry::CredMeta {
            expires_at_unix: Some(10),
            ..Default::default()
        };
        assert_eq!(meta_gate(&expired, 10, || true), Err("expired".into()));
        let consent = expiry::CredMeta {
            requires_consent: Some(true),
            ..Default::default()
        };
        assert_eq!(
            meta_gate(&consent, 0, || false),
            Err("consent denied".into())
        );
        assert_eq!(meta_gate(&consent, 0, || true), Ok(()));
        assert_eq!(meta_gate(&expiry::CredMeta::default(), 0, || false), Ok(()));
    }
}
