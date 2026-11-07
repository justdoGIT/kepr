//! OMP receives route metadata and placeholders, never credential values.
use kepr_core::{gate_protocol::GateRoute, protocol::CredInfo};
use std::collections::HashMap;

pub fn routes(sealed: &[CredInfo]) -> Result<Vec<GateRoute>, String> {
    let mut destinations = std::collections::BTreeSet::new();
    for credential in sealed
        .iter()
        .filter(|c| c.sealed == Some(true) && c.db_kind.is_none() && c.aws_sigv4 != Some(true))
    {
        for bound in credential.bound_hosts.iter().flatten() {
            let Some(host) = bound.strip_suffix(":443") else {
                continue;
            };
            if let Some(key) = kepr_core::http_route::key(host, &credential.name) {
                destinations.insert((key, credential.name.clone()));
            }
        }
    }
    if destinations.is_empty() {
        return Err(
            "OMP needs a sealed API credential with an HTTPS host binding; use kepr agent add NAME"
                .into(),
        );
    }
    let routes: Vec<_> = destinations
        .into_iter()
        .enumerate()
        .map(|(slot, (provider, cred))| GateRoute {
            provider,
            cred,
            slot: slot as u16,
            target: None,
        })
        .collect();
    kepr_core::gate_protocol::validate_routes(&routes)?;
    Ok(routes)
}

pub fn env(
    routes: &[GateRoute],
    placeholders: &HashMap<String, String>,
) -> Result<Vec<(String, String)>, String> {
    let mut env = std::collections::BTreeMap::new();
    let mut metadata = Vec::new();
    for route in routes {
        let Some((host, credential)) = kepr_core::http_route::parse(&route.provider) else {
            continue;
        };
        let placeholder = placeholders
            .get(&route.provider)
            .filter(|p| p.starts_with("kepr-ph-"))
            .ok_or("OMP did not receive its route placeholders")?;
        let variable = format!("KEPR_OMP_KEY_{}", route.slot);
        metadata.push(serde_json::json!({"host": host, "credential": credential, "route": route.provider, "variable": variable}));
        env.insert(variable, placeholder.clone());
        // Keep harness/process controls separate from credential aliases.
        if !credential.starts_with("KEPR_")
            && !credential.starts_with("XDG_")
            && !matches!(
                credential,
                "HOME" | "PATH" | "SHELL" | "PI_CODING_AGENT_DIR"
            )
        {
            env.entry(credential.to_string())
                .or_insert_with(|| placeholder.clone());
        }
    }
    env.insert(
        "KEPR_OMP_ROUTES".into(),
        serde_json::to_string(&metadata).map_err(|_| "could not encode OMP routes")?,
    );
    Ok(env.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn credential(name: &str, hosts: &[&str]) -> CredInfo {
        CredInfo {
            name: name.into(),
            sealed: Some(true),
            bound_hosts: Some(hosts.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        }
    }
    #[test]
    fn omp_routes_use_bindings_and_keep_accounts_distinct() {
        let mut unsealed = credential("UNSEALED", &["api.example.com:443"]);
        unsealed.sealed = None;
        let mut db = credential("DB", &["database.example.com:443"]);
        db.db_kind = Some("postgres".into());
        let routes = routes(&[
            credential(
                "WORK",
                &[
                    "api.example.com:443",
                    "other.example.com:443",
                    "insecure.example.com:80",
                ],
            ),
            credential("PERSONAL", &["api.example.com:443"]),
            unsealed,
            db,
        ])
        .unwrap();
        assert_eq!(routes.len(), 3);
        kepr_core::gate_protocol::validate_routes(&routes).unwrap();
        assert!(routes
            .iter()
            .all(|r| matches!(r.cred.as_str(), "WORK" | "PERSONAL")));
        let ph = routes
            .iter()
            .map(|r| (r.provider.clone(), format!("kepr-ph-example-{}", r.slot)))
            .collect();
        let vars: HashMap<_, _> = env(&routes, &ph).unwrap().into_iter().collect();
        assert!(vars["WORK"].starts_with("kepr-ph-"));
        let metadata: serde_json::Value = serde_json::from_str(&vars["KEPR_OMP_ROUTES"]).unwrap();
        assert_eq!(metadata.as_array().unwrap().len(), 3);
        assert!(!vars["KEPR_OMP_ROUTES"].contains("kepr-ph-"));
        assert!(env(&routes, &HashMap::new()).is_err());
    }
    #[test]
    fn omp_reports_empty_or_oversized_inventory() {
        assert!(routes(&[]).is_err());
        let creds: Vec<_> = (0..=kepr_core::http_route::MAX_ROUTES)
            .map(|i| credential(&format!("KEY_{i}"), &["api.example.com:443"]))
            .collect();
        assert!(routes(&creds).is_err());
    }
}
