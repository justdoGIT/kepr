//! MCP routes come only from sealed credential metadata. An explicit HTTPS
//! route names an account; the daemon still enforces its exact host binding.

use kepr_core::gate_protocol::{GateRoute, TargetKind};
use kepr_core::protocol::CredInfo;

pub fn session_routes(sealed: &[CredInfo]) -> Vec<GateRoute> {
    let mut routes: Vec<GateRoute> = Vec::new();
    for credential in sealed
        .iter()
        .filter(|c| c.sealed == Some(true) && c.record_type.is_none())
    {
        for destination in credential.bound_hosts.iter().flatten() {
            let Some(host) = destination.strip_suffix(":443") else {
                continue;
            };
            let provider = if let Some(preset) = kepr_core::providers::by_host(host) {
                preset.name.to_string()
            } else if let Some(route) = kepr_core::http_route::key(host, &credential.name) {
                route
            } else {
                continue;
            };
            if !routes.iter().any(|route| route.provider == provider) {
                routes.push(GateRoute {
                    provider,
                    cred: credential.name.clone(),
                    slot: routes.len() as u16,
                    target: None,
                });
            }
        }
    }
    // db_query speaks PostgreSQL; other typed records do not become HTTP routes.
    let databases = crate::cli_agent_db::routes(&routes, sealed);
    routes.extend(databases.into_iter().filter(|route| {
        route
            .target
            .as_ref()
            .is_some_and(|t| t.kind == TargetKind::Postgres)
    }));
    routes
}
