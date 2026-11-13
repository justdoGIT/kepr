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

/// Required privacy grants only exact hosts with reviewed text adapters.
pub fn privacy_routes(sealed: &[CredInfo]) -> Result<Vec<GateRoute>, String> {
    let mut routes: Vec<_> = routes(sealed)?
        .into_iter()
        .filter(|r| kepr_core::privacy::supports_provider(&r.provider))
        .collect();
    if routes.is_empty() {
        return Err(
            "OMP privacy needs a sealed credential for a supported model-provider host".into(),
        );
    }
    for (slot, route) in routes.iter_mut().enumerate() {
        route.slot = slot as u16;
    }
    kepr_core::privacy::Policy::default().validate_routes(&routes, false)?;
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
            && !crate::cli_agent_run::reserved_environment_name(credential)
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

    #[test]
    fn required_omp_routes_exclude_uninspected_keys_and_keep_account_identity() {
        let routes = privacy_routes(&[
            credential("WORK", &["api.openai.com:443"]),
            credential("PERSONAL", &["api.openai.com:443"]),
            credential("ADMIN", &["api.github.com:443"]),
            credential("CUSTOM", &["uninspected.example.invalid:443"]),
        ])
        .unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes
            .iter()
            .all(|r| matches!(r.cred.as_str(), "WORK" | "PERSONAL")));
        assert_eq!(
            routes.iter().map(|r| r.slot).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(privacy_routes(&[credential("ADMIN", &["api.github.com:443"])]).is_err());
    }

    #[test]
    fn omp_credential_aliases_cannot_override_runtime_or_proxy_controls() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "BASH_ENV",
            "HTTPS_PROXY",
            "SSL_CERT_FILE",
            "DATABASE_URL",
            "CODEX_HOME",
            "LANG",
            "AWS_REGION",
            "DOCKER_CONFIG",
            "REGISTRY_AUTH_FILE",
            "NPM_CONFIG_USERCONFIG",
            "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
            "KUBECONFIG",
            "AWS_CONFIG_FILE",
        ] {
            let routes = routes(&[credential(name, &["api.example.com:443"])]).unwrap();
            let placeholders = routes
                .iter()
                .map(|r| (r.provider.clone(), "kepr-ph-test".to_string()))
                .collect();
            let vars = env(&routes, &placeholders).unwrap();
            assert!(
                !vars.iter().any(|(key, _)| key == name),
                "reserved alias was exported: {name}"
            );
            assert!(vars.iter().any(|(key, _)| key.starts_with("KEPR_OMP_KEY_")));
        }
    }
}
