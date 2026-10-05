// cli_gatex/tunnel.rs — `kepr agent run --tunnel NAME=HOST:PORT` (T7.03):
// gate routes for raw TCP tunnels and the KEPR_TUNNEL_<NAME> variables
// that tell the agent where each one listens.

use std::collections::HashMap;

use kepr_core::gate_protocol::{tunnel_route_key, DbTarget, GateRoute, TargetKind};

/// `NAME=host:port` → (NAME, host, port). NAME follows credential-name
/// rules (it is uppercased); the host must be a fully-qualified name or
/// an IPv4 address.
pub fn parse(spec: &str) -> Result<(String, String, u16), String> {
    let bad =
        || format!("--tunnel {spec}: use NAME=HOST:PORT, e.g. WIKI=wiki.internal.example:443");
    let (name, target) = spec.split_once('=').ok_or_else(bad)?;
    let (host, port) = target.rsplit_once(':').ok_or_else(bad)?;
    let name = name.to_uppercase();
    let port: u16 = port.parse().ok().filter(|p| *p > 0).ok_or_else(bad)?;
    if name.is_empty()
        || name.len() > 64
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(format!("--tunnel {spec}: NAME may only use A-Z, 0-9 and _"));
    }
    let host = host.to_ascii_lowercase();
    kepr_core::binding::validate_host(&host).map_err(|e| format!("--tunnel {spec}: {e}"))?;
    Ok((name, host, port))
}

/// One route per tunnel, with slots after `existing`'s.
pub fn routes(existing: &[GateRoute], specs: &[String]) -> Result<Vec<GateRoute>, String> {
    let first = existing.iter().map(|r| r.slot + 1).max().unwrap_or(0);
    let mut out = Vec::new();
    for (slot, spec) in (first..).zip(specs) {
        let (name, host, port) = parse(spec)?;
        out.push(GateRoute {
            provider: tunnel_route_key(&name),
            cred: name,
            slot,
            target: Some(DbTarget {
                host,
                port,
                kind: TargetKind::Tcp,
                ..Default::default()
            }),
        });
    }
    Ok(out)
}

/// KEPR_TUNNEL_<NAME>=127.0.0.1:<port> for each tunnel the gate opened.
pub fn env(ports: &HashMap<String, u16>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = ports
        .iter()
        .filter_map(|(key, port)| {
            let name = key.strip_prefix("tcp:")?;
            Some((format!("KEPR_TUNNEL_{name}"), format!("127.0.0.1:{port}")))
        })
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs() {
        assert_eq!(
            parse("wiki=Wiki.Internal.example:8080").unwrap(),
            ("WIKI".into(), "wiki.internal.example".into(), 8080)
        );
        assert_eq!(parse("db2=10.0.0.5:5432").unwrap().1, "10.0.0.5");
        for bad in [
            "wiki.example.com:80",
            "W=wiki.example.com",
            "W=wiki.example.com:0",
            "W=localhost:80",
            "a-b=wiki.example.com:80",
            "W=https://x.example.com:443",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn routes_follow_existing_slots_and_env_names_ports() {
        let existing = vec![GateRoute {
            provider: "anthropic".into(),
            cred: "ANTHROPIC_API_KEY".into(),
            slot: 0,
            target: None,
        }];
        let r = routes(&existing, &["wiki=wiki.example.com:80".into()]).unwrap();
        assert_eq!((r[0].provider.as_str(), r[0].slot), ("tcp:WIKI", 1));
        assert!(r[0].is_tunnel());
        let mut all = existing;
        all.extend(r);
        assert!(kepr_core::gate_protocol::validate_routes(&all).is_ok());
        let ports: HashMap<String, u16> = [
            ("tcp:WIKI".to_string(), 4000),
            ("db:PROD".to_string(), 5000),
        ]
        .into();
        assert_eq!(
            env(&ports),
            vec![("KEPR_TUNNEL_WIKI".to_string(), "127.0.0.1:4000".to_string())]
        );
    }
}
