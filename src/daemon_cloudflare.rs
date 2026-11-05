// daemon_cloudflare.rs — daemon-only conversion of the standard Cloudflare
// token into a sealed structured login. No credential value crosses the wire.

use crate::crypto;
use crate::expiry::{self, CredMeta};
use crate::store::{self, cred_path};
use kepr_core::binding::{Binding, Inject};
use kepr_core::cloudflare::{GatewayCredential, CREDENTIAL, HOST};
use kepr_core::protocol::Response;

fn binding() -> Binding {
    Binding {
        host: HOST.to_string(),
        port: 443,
        inject: Inject::CloudflareGateway,
    }
}

fn fail(uid: u32, username: &str, message: impl Into<String>) -> Response {
    let message = message.into();
    crate::audit::log(&crate::audit::AuditEvent {
        op: "cloudflare-import",
        name: Some(CREDENTIAL),
        uid,
        username,
        result: crate::audit::AuditResult::Fail(message.clone()),
    });
    Response::fail(message)
}

pub(crate) fn handle_import(uid: u32, peer_pid: i32, username: &str) -> Response {
    let names = [
        CREDENTIAL.to_uppercase(),
        "CLOUDFLARE_ACCOUNT_ID".to_string(),
        "CLOUDFLARE_GATEWAY_ID".to_string(),
    ];
    let mut ordered = names.clone();
    ordered.sort();
    let _locks: Vec<_> = ordered
        .iter()
        .map(|name| crate::daemon_credlock::lock(uid, name))
        .collect();

    let upper = &names[0];
    let path = cred_path(uid, upper);
    if !store::cred_exists(uid, upper) {
        return fail(uid, username, "Cloudflare token credential is unavailable");
    }
    let meta_path = expiry::meta_path_for(&path);
    let meta = match expiry::read_meta(&meta_path) {
        None => CredMeta::default(),
        Some(Ok(m)) => m,
        Some(Err(_)) => return fail(uid, username, "Cloudflare token policy is unreadable"),
    };
    if meta.alias_of.is_some() {
        return fail(
            uid,
            username,
            "Cloudflare token credential is an alias; convert its target explicitly",
        );
    }
    let now = expiry::now_unix();
    if meta.expires_at_unix.is_some_and(|at| now >= at) {
        return fail(uid, username, "Cloudflare token is expired");
    }

    let expected = binding();
    if meta.sealed == Some(true)
        && meta.bindings.as_deref() == Some(std::slice::from_ref(&expected))
    {
        return Response::SetOk {
            name: upper.clone(),
            cred_name: store::to_cred_name(uid, upper),
            password_protected: crate::protected_master_key_path().exists(),
        };
    }
    if meta.sealed == Some(true)
        || meta.requires_fido2 == Some(true)
        || meta.ssh.is_some()
        || meta.share_key == Some(true)
    {
        return fail(
            uid,
            username,
            "Cloudflare token has a protected policy that cannot be converted safely",
        );
    }
    if meta.approvals.is_some()
        || meta.approve_via.is_some()
        || meta.self_destruct_share.is_some()
        || meta.view_window_secs.is_some()
        || meta.canary.is_some()
        || meta.folder_mark.is_some()
        || meta.must_rotate == Some(true)
        || meta.requires_reauth == Some(true)
        || meta.exe_digests.as_ref().is_some_and(|v| !v.is_empty())
        || meta.checkout.is_some()
        || meta.rotate_every_secs.is_some()
        || meta.rotate_via.is_some()
    {
        return fail(
            uid,
            username,
            "Cloudflare token has a policy that cannot be converted safely",
        );
    }
    if let Err(reason) = crate::daemon_handlers_get::precheck_meta(uid, peer_pid, upper) {
        return fail(
            uid,
            username,
            format!("Cloudflare token policy check failed: {reason}"),
        );
    }

    let mut identifiers = Vec::with_capacity(2);
    for name in [&names[1], &names[2]] {
        if !store::cred_exists(uid, name) {
            return fail(
                uid,
                username,
                "Cloudflare account or gateway metadata is unavailable",
            );
        }
        let source_path = cred_path(uid, name);
        let source_meta = match expiry::read_meta(&expiry::meta_path_for(&source_path)) {
            None => CredMeta::default(),
            Some(Ok(m)) => m,
            Some(Err(_)) => {
                return fail(
                    uid,
                    username,
                    "Cloudflare account or gateway policy is unreadable",
                )
            }
        };
        if source_meta.alias_of.is_some()
            || source_meta.gated().is_some()
            || source_meta.expires_at_unix.is_some()
            || source_meta.checkout.is_some()
            || source_meta.jit == Some(true)
            || source_meta.rotate_every_secs.is_some()
            || source_meta.rotate_via.is_some()
            || source_meta.self_destruct_share.is_some()
            || source_meta.must_rotate == Some(true)
            || source_meta.folder_mark.is_some()
        {
            return fail(
                uid,
                username,
                "Cloudflare account or gateway metadata has an incompatible policy",
            );
        }
        if source_meta.expires_at_unix.is_some_and(|at| now >= at) {
            return fail(
                uid,
                username,
                "Cloudflare account or gateway metadata is expired",
            );
        }
        if let Err(reason) = crate::daemon_handlers_get::precheck_meta(uid, peer_pid, name) {
            return fail(
                uid,
                username,
                format!("Cloudflare metadata policy check failed: {reason}"),
            );
        }
        match crypto::default_backend().decrypt(uid, name) {
            Ok(value) => identifiers.push(value),
            Err(_) => {
                return fail(
                    uid,
                    username,
                    "Cloudflare account or gateway metadata is unavailable",
                )
            }
        }
    }
    let token = match crypto::default_backend().decrypt(uid, upper) {
        Ok(value) => value,
        Err(_) => return fail(uid, username, "Cloudflare token credential is unavailable"),
    };
    let login = match GatewayCredential::new(
        token,
        identifiers[0].as_str().to_owned(),
        identifiers[1].as_str().to_owned(),
    ) {
        Ok(login) => login,
        Err(_) => {
            return fail(
                uid,
                username,
                "Cloudflare token or routing metadata is invalid",
            )
        }
    };
    let encoded = login.encode();
    // Credential locks are re-entrant; reuse the normal audited set transaction.
    let response = crate::daemon_handlers::handle_set(
        uid,
        username,
        upper,
        Some(encoded.as_str()),
        None,
        crate::daemon_handlers::SetFlags {
            requires_consent: meta.requires_consent,
            preserve_expires_at: meta.expires_at_unix,
            sealed: Some(true),
            bindings: Some(vec![expected]),
            ..Default::default()
        },
    );
    match response {
        Response::SetOk { .. } => {
            crate::audit::log(&crate::audit::AuditEvent {
                op: "cloudflare-import",
                name: Some(upper),
                uid,
                username,
                result: crate::audit::AuditResult::Ok,
            });
            response
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_handlers::{handle_set, SetFlags};

    fn seed(uid: u32) {
        crate::daemon_store::testkit::set(uid, CREDENTIAL, "synthetic-token");
        crate::daemon_store::testkit::set(uid, "CLOUDFLARE_ACCOUNT_ID", &"a".repeat(32));
        crate::daemon_store::testkit::set(uid, "CLOUDFLARE_GATEWAY_ID", "coding-gateway");
    }

    #[test]
    fn converts_in_place_and_is_idempotent() {
        let uid = crate::daemon_store::testkit::uid();
        seed(uid);
        let first = handle_import(uid, std::process::id() as i32, "t");
        assert!(first.is_success(), "{first:?}");
        let saved = crate::daemon_store::testkit::value(uid, CREDENTIAL).unwrap();
        let login = GatewayCredential::parse(&saved).unwrap();
        assert_eq!(login.token.as_str(), "synthetic-token");
        assert_eq!(login.gateway_id, "coding-gateway");
        assert_eq!(
            crate::daemon_store::testkit::meta(uid, CREDENTIAL).bindings,
            Some(vec![binding()])
        );
        let again = handle_import(uid, std::process::id() as i32, "t");
        assert!(again.is_success(), "{again:?}");
        assert_eq!(
            crate::daemon_store::testkit::value(uid, CREDENTIAL).as_deref(),
            Some(saved.as_str())
        );
    }

    #[test]
    fn missing_or_invalid_metadata_does_not_mutate_token() {
        let uid = crate::daemon_store::testkit::uid();
        crate::daemon_store::testkit::set(uid, CREDENTIAL, "synthetic-token");
        assert!(!handle_import(uid, std::process::id() as i32, "t").is_success());
        assert_eq!(
            crate::daemon_store::testkit::value(uid, CREDENTIAL).as_deref(),
            Some("synthetic-token")
        );
        crate::daemon_store::testkit::set(uid, "CLOUDFLARE_ACCOUNT_ID", "bad-account");
        crate::daemon_store::testkit::set(uid, "CLOUDFLARE_GATEWAY_ID", "coding-gateway");
        assert!(!handle_import(uid, std::process::id() as i32, "t").is_success());
        assert_eq!(
            crate::daemon_store::testkit::value(uid, CREDENTIAL).as_deref(),
            Some("synthetic-token")
        );
    }

    #[test]
    fn carries_expiry_and_refuses_fido2_policy() {
        let uid = crate::daemon_store::testkit::uid();
        seed(uid);
        let expiry_at = expiry::now_unix() + 3600;
        expiry::write_meta(
            &expiry::meta_path_for(&cred_path(uid, CREDENTIAL)),
            &CredMeta {
                expires_at_unix: Some(expiry_at),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(handle_import(uid, std::process::id() as i32, "t").is_success());
        let carried_expiry = crate::daemon_store::testkit::meta(uid, CREDENTIAL)
            .expires_at_unix
            .unwrap();
        assert!(carried_expiry <= expiry_at && carried_expiry >= expiry_at - 1);

        let uid = crate::daemon_store::testkit::uid();
        seed(uid);
        let flags = SetFlags {
            requires_fido2: Some(true),
            ..Default::default()
        };
        assert!(
            handle_set(uid, "t", CREDENTIAL, Some("synthetic-token"), None, flags).is_success()
        );
        assert!(!handle_import(uid, std::process::id() as i32, "t").is_success());
        assert_eq!(
            crate::daemon_store::testkit::value(uid, CREDENTIAL).as_deref(),
            Some("synthetic-token")
        );
    }
    #[test]
    fn metadata_policy_is_never_weakened_by_copying_identifiers() {
        for policy in [
            CredMeta {
                requires_consent: Some(true),
                ..Default::default()
            },
            CredMeta {
                expires_at_unix: Some(expiry::now_unix() + 3600),
                ..Default::default()
            },
            CredMeta {
                requires_reauth: Some(true),
                ..Default::default()
            },
        ] {
            let uid = crate::daemon_store::testkit::uid();
            seed(uid);
            expiry::write_meta(
                &expiry::meta_path_for(&cred_path(uid, "CLOUDFLARE_ACCOUNT_ID")),
                &policy,
            )
            .unwrap();
            assert!(!handle_import(uid, std::process::id() as i32, "t").is_success());
            assert_eq!(
                crate::daemon_store::testkit::value(uid, CREDENTIAL).as_deref(),
                Some("synthetic-token")
            );
            assert_ne!(
                crate::daemon_store::testkit::meta(uid, CREDENTIAL).sealed,
                Some(true)
            );
        }
    }
}
