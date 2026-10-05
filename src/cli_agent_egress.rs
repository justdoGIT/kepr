// cli_agent_egress.rs — the harness side of the gate's egress proxy (P2.1).
//
// Tools the agent runs (`gh`, `curl`, `git`, SDKs) reach hosts by name, so
// they get HTTPS_PROXY pointing at the gate. For hosts a sealed key is
// bound to, the gate terminates TLS with a per-session CA (name-limited
// to those hosts) and swaps the placeholder for the key; everything else
// is tunnelled (or refused under --isolate-net). Here: which extra routes
// to ask for, the CA files, and the variables that make tools use them.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use kepr_core::gate_protocol::GateRoute;
use kepr_core::protocol::CredInfo;
use kepr_core::providers::{self, PROVIDERS};

const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];

/// Routes for sealed keys bound to an egress provider's host (e.g. a
/// GitHub token bound to api.github.com), after the harness's own routes.
pub fn extra_routes(existing: &[GateRoute], sealed: &[CredInfo]) -> Vec<GateRoute> {
    let mut out = Vec::new();
    let mut slot = existing.iter().map(|r| r.slot + 1).max().unwrap_or(0);
    for p in PROVIDERS.iter().filter(|p| !p.egress_env.is_empty()) {
        if existing
            .iter()
            .chain(&out)
            .any(|r: &GateRoute| r.provider == p.name)
        {
            continue;
        }
        let target = format!("{}:443", p.host);
        let cred = sealed
            .iter()
            .find(|c| c.bound_hosts.as_ref().is_some_and(|h| h.contains(&target)));
        if let Some(c) = cred {
            out.push(GateRoute {
                provider: p.name.to_string(),
                cred: c.name.clone(),
                slot,
                target: None,
            });
            slot += 1;
        }
    }
    out
}

/// Variables the harness must not inherit: the real keys the egress
/// placeholders stand in for.
pub fn shadowed(placeholders: &HashMap<String, String>) -> Vec<&'static str> {
    placeholders
        .keys()
        .filter_map(|p| providers::lookup(p))
        .flat_map(|p| p.egress_env.iter().copied())
        .collect()
}

fn write_private(path: &PathBuf, data: &[u8]) -> Result<(), String> {
    let _ = std::fs::remove_file(path);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(data))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Write the session CA (alone, and appended to the system bundle) into a
/// private per-session directory; return (ca file, bundle file).
fn write_ca(ca_pem: &str) -> Result<(PathBuf, PathBuf), String> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    // An unpredictable name, created fresh: a directory someone else made
    // in advance (in a shared /tmp) could hand the agent their own CA.
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let dir = base.join(format!("kepr-agent-{}", hex::encode(rnd)));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let (ca, bundle) = (dir.join("session-ca.pem"), dir.join("ca-bundle.pem"));
    write_private(&ca, ca_pem.as_bytes())?;
    let mut all = SYSTEM_BUNDLES
        .iter()
        .find_map(|p| std::fs::read(p).ok())
        .unwrap_or_default();
    all.extend_from_slice(b"\n");
    all.extend_from_slice(ca_pem.as_bytes());
    write_private(&bundle, &all)?;
    Ok((ca, bundle))
}

/// Proxy, CA and placeholder variables for the harness.
pub fn env(
    port: u16,
    ca_pem: &str,
    placeholders: &HashMap<String, String>,
) -> Result<Vec<(String, String)>, String> {
    let (ca, bundle) = write_ca(ca_pem)?;
    let proxy = format!("http://127.0.0.1:{port}");
    let bundle = bundle.display().to_string();
    let mut env = vec![
        ("HTTPS_PROXY".to_string(), proxy.clone()),
        ("https_proxy".to_string(), proxy),
        ("NO_PROXY".to_string(), "127.0.0.1,localhost".to_string()),
        ("no_proxy".to_string(), "127.0.0.1,localhost".to_string()),
        ("NODE_EXTRA_CA_CERTS".to_string(), ca.display().to_string()),
    ];
    for var in [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
    ] {
        env.push((var.to_string(), bundle.clone()));
    }
    for (provider, ph) in placeholders {
        for var in providers::lookup(provider).map_or(&[][..], |p| p.egress_env) {
            env.push((var.to_string(), ph.clone()));
        }
    }
    Ok(env)
}

/// Variables `env` sets, so the inherited copies can be dropped.
pub const PROXY_VARS: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(name: &str, hosts: &[&str]) -> CredInfo {
        CredInfo {
            name: name.into(),
            cred_name: String::new(),
            size: 0,
            modified: String::new(),
            sealed: Some(true),
            bound_hosts: Some(hosts.iter().map(|h| h.to_string()).collect()),
            ..Default::default()
        }
    }

    #[test]
    fn adds_a_route_for_a_github_key_after_the_harness_routes() {
        let existing = vec![GateRoute {
            provider: "anthropic".into(),
            cred: "ANTHROPIC_API_KEY".into(),
            slot: 0,
            target: None,
        }];
        let creds = [
            cred("ANTHROPIC_API_KEY", &["api.anthropic.com:443"]),
            cred("GH", &["api.github.com:443"]),
        ];
        let r = extra_routes(&existing, &creds);
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].provider.as_str(), r[0].cred.as_str(), r[0].slot),
            ("github", "GH", 1)
        );
        assert!(extra_routes(&existing, &creds[..1]).is_empty());
    }

    #[test]
    fn github_placeholder_shadows_the_real_token_vars() {
        let ph: HashMap<String, String> = [("github".to_string(), "kepr-ph-x".to_string())].into();
        let mut s = shadowed(&ph);
        s.sort();
        assert_eq!(s, ["GH_TOKEN", "GITHUB_TOKEN"]);
    }
}
