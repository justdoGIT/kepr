// cli_agent_kube.rs — Kubernetes API servers for agents (T13.04).
//
//   kepr agent add-kube NAME --server https://HOST[:PORT]
//                       [--token-file FILE | --stdin] [--ca-file FILE]
//                       [--requires-consent]
//
// Stores a sealed `kube` record (server, bearer token, the cluster's CA
// certificate) bound to the API server's DNS name and port. In `kepr agent
// run` each one becomes a gate route and the harness gets a KUBECONFIG
// pointing at the same server URL with the session placeholder as the token,
// the session CA as the certificate authority, and the gate as the proxy;
// the gate puts the real token on the wire and verifies the cluster against
// the stored CA. The token is read from a file or stdin, never argv.
//
// `kubectl exec`, `attach` and `port-forward` are not supported (the gate
// serves plain HTTP/1.1 requests); the API server must have a DNS name.

use std::collections::HashMap;
use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};

use kepr_core::gate_protocol::{kube_route_key, DbTarget, GateRoute, TargetKind};
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{CredInfo, Request, Response};

use crate::cli_extra::flag;
use crate::{cli_input, cli_ui, client};

const USAGE: &str = "usage: kepr agent add-kube NAME --server https://HOST[:PORT] [--token-file FILE | --stdin] [--ca-file FILE] [--requires-consent]";
/// A service-account token or a CA bundle is a few KiB.
const MAX_FILE: u64 = 64 * 1024;

fn read_limited(path: &str, what: &str) -> Result<String, String> {
    use std::io::Read;
    let mut s = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_FILE + 1).read_to_string(&mut s))
        .map_err(|e| format!("{what} {path}: {e}"))?;
    if s.len() as u64 > MAX_FILE {
        return Err(format!("{what} {path} is larger than 64 KiB"));
    }
    Ok(s)
}

/// The fields of the `kube` record (what the daemon seals).
pub fn fields(server: &str, token: &str, ca_pem: &str) -> serde_json::Value {
    let mut f = serde_json::json!({ "server": server, "token": token });
    if !ca_pem.trim().is_empty() {
        f["ca_pem"] = ca_pem.trim().into();
    }
    f
}

pub fn cmd_add_kube(args: &[String]) -> Response {
    let (Some(name), Some(server)) = (
        args.first().filter(|a| !a.starts_with('-')),
        flag(args, "--server"),
    ) else {
        return Response::fail(USAGE);
    };
    let (host, port) = match kepr_core::binding::kube_server(server) {
        Ok(v) => v,
        Err(e) => return Response::fail(e),
    };
    let ca_pem = match flag(args, "--ca-file").map(|p| read_limited(p, "--ca-file")) {
        Some(Ok(p)) => p,
        Some(Err(e)) => return Response::fail(e),
        None => String::new(),
    };
    let token = match flag(args, "--token-file") {
        Some(p) => match read_limited(p, "--token-file") {
            Ok(t) => ZeroString::from_string(t.trim().to_string()),
            Err(e) => return Response::fail(e),
        },
        None if args.iter().any(|a| a == "--stdin") || !std::io::stdin().is_terminal() => {
            let mut s = zeroize::Zeroizing::new(String::new());
            let _ = std::io::stdin().lock().read_line(&mut s);
            ZeroString::from_string(s.trim().to_string())
        }
        None => cli_input::read_masked(&format!("Bearer token for {host}:{port} (input hidden): ")),
    };
    if token.as_str().is_empty() {
        return Response::fail("the token is empty");
    }
    let f = fields(server, token.as_str(), &ca_pem);
    let r = client::send_request(&Request::RecordSet {
        name: name.to_uppercase(),
        record_type: "kube".into(),
        fields: ZeroString::from_string(f.to_string()),
        requires_consent: args
            .iter()
            .any(|a| a == "--requires-consent")
            .then_some(true),
        seal: true,
    })
    .unwrap_or_else(Response::fail);
    if let Response::SetOk { name, .. } = &r {
        cli_ui::ok(&format!(
            "{name}: sealed Kubernetes login for {host}:{port}; agents reach it through `kepr agent run` (kubectl, no exec/port-forward)"
        ));
    }
    r
}

/// A gate route for every sealed `kube` record.
pub fn routes(existing: &[GateRoute], sealed: &[CredInfo]) -> Vec<GateRoute> {
    let mut slot = existing.iter().map(|r| r.slot + 1).max().unwrap_or(0);
    let mut out = Vec::new();
    for c in sealed
        .iter()
        .filter(|c| c.record_type.as_deref() == Some("kube"))
    {
        let Some((host, port)) = c
            .bound_hosts
            .as_ref()
            .and_then(|h| h.first())
            .and_then(|h| h.rsplit_once(':'))
            .and_then(|(h, p)| Some((h.to_string(), p.parse().ok()?)))
        else {
            continue;
        };
        out.push(GateRoute {
            provider: kube_route_key(&c.name),
            cred: c.name.clone(),
            slot,
            target: Some(DbTarget {
                host,
                port,
                kind: TargetKind::Kube,
                ..Default::default()
            }),
        });
        slot += 1;
    }
    out
}

/// One cluster of the session's KUBECONFIG.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    /// Context, cluster and user name.
    pub context: String,
    pub host: String,
    pub port: u16,
    pub placeholder: String,
}

/// The session's kube routes with their placeholders, by name.
pub fn entries(routes: &[GateRoute], placeholders: &HashMap<String, String>) -> Vec<Entry> {
    let mut out: Vec<Entry> = routes
        .iter()
        .filter_map(|r| {
            let t = r.target.as_ref().filter(|t| t.kind == TargetKind::Kube)?;
            Some(Entry {
                context: r.cred.to_ascii_lowercase().replace('_', "-"),
                host: t.host.clone(),
                port: t.port,
                placeholder: placeholders.get(&r.provider)?.clone(),
            })
        })
        .collect();
    out.sort_by(|a, b| a.context.cmp(&b.context));
    out
}

/// A YAML double-quoted scalar (JSON string syntax is valid YAML).
fn q(s: &str) -> String {
    serde_json::Value::String(s.into()).to_string()
}

/// The KUBECONFIG text: every cluster via the gate, the placeholder as the
/// token, the session CA as the authority.
pub fn kubeconfig(entries: &[Entry], ca: &Path, proxy_port: u16) -> String {
    let mut out = String::from("apiVersion: v1\nkind: Config\nclusters:\n");
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    for e in entries {
        out += &format!(
            "- name: {n}\n  cluster:\n    server: {s}\n    certificate-authority: {c}\n    proxy-url: {p}\n",
            n = q(&e.context),
            s = q(&format!("https://{}:{}", e.host, e.port)),
            c = q(&ca.display().to_string()),
            p = q(&proxy),
        );
    }
    out += "users:\n";
    for e in entries {
        out += &format!(
            "- name: {}\n  user:\n    token: {}\n",
            q(&e.context),
            q(&e.placeholder)
        );
    }
    out += "contexts:\n";
    for e in entries {
        let n = q(&e.context);
        out += &format!("- name: {n}\n  context:\n    cluster: {n}\n    user: {n}\n");
    }
    if let Some(first) = entries.first() {
        out += &format!("current-context: {}\n", q(&first.context));
    }
    out
}

/// Write the KUBECONFIG into the session directory; the variable for it.
pub fn write(
    dir: &Path,
    ca: &Path,
    proxy_port: u16,
    entries: &[Entry],
) -> Result<Vec<(String, String)>, String> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let path: PathBuf = dir.join("kubeconfig");
    crate::cli_agent_egress::write_private(&path, kubeconfig(entries, ca, proxy_port).as_bytes())?;
    Ok(vec![("KUBECONFIG".into(), path.display().to_string())])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(name: &str, kind: &str, hosts: &[&str]) -> CredInfo {
        CredInfo {
            name: name.into(),
            sealed: Some(true),
            record_type: Some(kind.into()),
            bound_hosts: Some(hosts.iter().map(|h| h.to_string()).collect()),
            ..Default::default()
        }
    }

    #[test]
    fn routes_come_from_sealed_kube_records_only() {
        let creds = [
            cred("PROD_K8S", "kube", &["api.prod.example.com:6443"]),
            cred("DB", "database", &["db.example.com:5432"]),
            cred("BAD", "kube", &["no-port"]),
        ];
        let existing = [GateRoute {
            provider: "anthropic".into(),
            cred: "K".into(),
            slot: 4,
            target: None,
        }];
        let r = routes(&existing, &creds);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].provider.as_str(), r[0].slot), ("kube:PROD_K8S", 5));
        let t = r[0].target.as_ref().unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.kind),
            ("api.prod.example.com", 6443, TargetKind::Kube)
        );
        assert!(kepr_core::gate_protocol::validate_routes(&r).is_ok());
    }

    #[test]
    fn the_kubeconfig_holds_only_the_placeholder_and_the_session_ca() {
        let routes = routes(
            &[],
            &[cred("PROD_K8S", "kube", &["api.prod.example.com:6443"])],
        );
        let ph: HashMap<String, String> = [(
            "kube:PROD_K8S".to_string(),
            "kepr-ph-abc-0000-ff".to_string(),
        )]
        .into();
        let e = entries(&routes, &ph);
        assert_eq!(e[0].context, "prod-k8s");
        let text = kubeconfig(
            &e,
            Path::new("/run/user/1/kepr-agent-x/session-ca.pem"),
            4321,
        );
        for want in [
            "server: \"https://api.prod.example.com:6443\"",
            "certificate-authority: \"/run/user/1/kepr-agent-x/session-ca.pem\"",
            "proxy-url: \"http://127.0.0.1:4321\"",
            "token: \"kepr-ph-abc-0000-ff\"",
            "current-context: \"prod-k8s\"",
        ] {
            assert!(text.contains(want), "{want}\n{text}");
        }
        assert!(!text.contains("certificate-authority-data"));
        assert!(
            serde_json::from_str::<serde_json::Value>(&text).is_err(),
            "it is YAML"
        );
    }

    #[test]
    fn a_route_without_a_placeholder_is_left_out_and_paths_are_quoted() {
        let routes = routes(&[], &[cred("A", "kube", &["a.example.com:443"])]);
        assert!(entries(&routes, &HashMap::new()).is_empty());
        let e = [Entry {
            context: "a".into(),
            host: "a.example.com".into(),
            port: 443,
            placeholder: "p".into(),
        }];
        let text = kubeconfig(&e, Path::new("/tmp/with \"quote\" and space/ca.pem"), 1);
        assert!(
            text.contains(r#"certificate-authority: "/tmp/with \"quote\" and space/ca.pem""#),
            "{text}"
        );
    }

    #[test]
    fn the_record_carries_the_token_and_the_ca() {
        let f = fields(
            "https://k8s.example.com",
            "tok",
            "  -----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        );
        assert_eq!(f["server"], "https://k8s.example.com");
        assert_eq!(f["token"], "tok");
        assert!(f["ca_pem"].as_str().unwrap().starts_with("-----BEGIN"));
        assert!(fields("https://x.example.com", "t", "  \n")
            .get("ca_pem")
            .is_none());
    }

    #[test]
    fn write_makes_a_private_file_and_names_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kepr-kube-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let e = [Entry {
            context: "a".into(),
            host: "a.example.com".into(),
            port: 443,
            placeholder: "p".into(),
        }];
        let env = write(&dir, &dir.join("session-ca.pem"), 9, &e).unwrap();
        let path = dir.join("kubeconfig");
        assert_eq!(
            env,
            [("KUBECONFIG".to_string(), path.display().to_string())]
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write(&dir, &dir.join("x"), 9, &[]).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
