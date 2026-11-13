//! Daemon-owned provider key rotation orchestration.
//!
//! The public request carries credential names only. The gate resolves both
//! sealed values over its private channel, validates the replacement upstream,
//! and asks this daemon to commit it before the old provider key is revoked.

use crate::daemon_gate::start;
use crate::store::{cred_path, validate_name};
use crate::{audit, expiry};
use kepr_core::gate_protocol::{GateLimits, GateRoute, RotationConfig};
use kepr_core::protocol::Response;

/// Start a one-shot provider rotation gate. Credential values never enter the
/// daemon request or CLI response.
pub fn handle(
    uid: u32,
    peer_pid: i32,
    username: &str,
    target: &str,
    provider: &str,
    bootstrap: &str,
) -> Response {
    let target = target.to_uppercase();
    let bootstrap = bootstrap.to_uppercase();
    if let Err(error) = validate_name(&target) {
        return Response::fail(error);
    }
    if let Err(error) = validate_name(&bootstrap) {
        return Response::fail(error);
    }
    if target == bootstrap {
        return Response::fail("provider rotation needs separate target and bootstrap credentials");
    }
    let is_sealed = |name: &str| {
        matches!(
            expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, name))),
            Some(Ok(meta)) if meta.sealed == Some(true)
        )
    };
    if !is_sealed(&target) || !is_sealed(&bootstrap) {
        return Response::fail(
            "provider rotation requires sealed target and bootstrap credentials",
        );
    }
    if !kepr_core::providers::supports_rotation(provider) {
        return Response::fail(format!(
            "provider '{provider}' has no documented automated key-creation flow"
        ));
    }
    let Some(host) = kepr_core::providers::lookup(provider).map(|p| p.host) else {
        return Response::fail("unknown provider");
    };
    let Some(bootstrap_route) = kepr_core::http_route::key(host, &bootstrap) else {
        return Response::fail("invalid bootstrap credential name");
    };
    let routes = vec![
        GateRoute {
            provider: kepr_core::gate_protocol::rotate_route_key(&target),
            cred: target.clone(),
            slot: 0,
            target: None,
        },
        GateRoute {
            provider: bootstrap_route,
            cred: bootstrap.clone(),
            slot: 1,
            target: None,
        },
    ];
    let result = start(
        uid,
        peer_pid,
        username,
        &routes,
        (None, GateLimits::default(), false, false),
        None,
        None,
        Some(RotationConfig {
            provider: provider.to_string(),
            target: target.clone(),
            bootstrap,
        }),
    );
    let response = match result {
        Ok(Response::GateStarted { .. }) => Response::ProviderRotated {
            name: target.clone(),
            provider: provider.to_string(),
        },
        Ok(other) => other,
        Err(error) => Response::fail(error),
    };
    audit::log(&audit::AuditEvent {
        op: "provider-rotate",
        name: Some(&target),
        uid,
        username,
        result: if response.is_success() {
            audit::AuditResult::Ok
        } else {
            audit::AuditResult::Fail("provider rotation failed".into())
        },
    });
    response
}
