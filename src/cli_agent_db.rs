// cli_agent_db.rs — database logins for agents (agent vault P7.1).
//
//   kepr agent add-db NAME --url postgres://USER@HOST[:PORT]/DB
//                     [--sslmode verify-full|disable] [--ca FILE] [--stdin]
//
// Stores a sealed `database` record (password asked for, hidden). In
// `kepr agent run`, each one becomes a gate route with its own loopback
// port; the harness gets DATABASE_URL / PG* pointing there with the
// session placeholder as password, and the gate logs in for it.

use std::collections::HashMap;
use std::io::{BufRead, IsTerminal};

use kepr_core::gate_protocol::{db_route_key, DbTarget, GateRoute};
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{CredInfo, Request, Response};

use crate::{cli_input, cli_ui, client};

const USAGE: &str = "usage: kepr agent add-db NAME --url postgres://USER@HOST[:PORT]/DB [--sslmode verify-full|disable] [--ca FILE] [--stdin]";

/// `postgres://user@host:port/db` → (user, host, port, db). No password
/// in the URL: it would land in shell history.
pub fn parse_url(url: &str) -> Result<(String, String, u16, String), String> {
    let rest = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))
        .ok_or("the URL must start with postgres://")?;
    let (auth, rest) = rest.split_once('@').ok_or("the URL needs USER@HOST")?;
    if auth.contains(':') {
        return Err("leave the password out of the URL; kepr asks for it".into());
    }
    let (hostport, db) = rest.split_once('/').ok_or("the URL needs /DATABASE")?;
    let db = db.split('?').next().unwrap_or_default();
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| "invalid port")?),
        None => (hostport, 5432),
    };
    if auth.is_empty() || host.is_empty() || db.is_empty() {
        return Err("the URL needs a user, a host and a database".into());
    }
    Ok((auth.into(), host.to_ascii_lowercase(), port, db.into()))
}

fn flag<'a>(args: &'a [String], f: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == f)?;
    args.get(i + 1).map(String::as_str)
}

pub fn cmd_add_db(args: &[String]) -> Response {
    let (Some(name), Some(url)) = (
        args.first().filter(|a| !a.starts_with('-')),
        flag(args, "--url"),
    ) else {
        return Response::fail(USAGE);
    };
    let (user, host, port, database) = match parse_url(url) {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
    let sslmode = flag(args, "--sslmode").unwrap_or("verify-full");
    let ca_pem = match flag(args, "--ca").map(std::fs::read_to_string) {
        Some(Ok(p)) => p,
        Some(Err(e)) => return Response::fail(format!("--ca: {e}")),
        None => String::new(),
    };
    let password = if args.iter().any(|a| a == "--stdin") || !std::io::stdin().is_terminal() {
        let mut s = zeroize::Zeroizing::new(String::new());
        let _ = std::io::stdin().lock().read_line(&mut s);
        ZeroString::from_string(s.trim_end_matches(['\n', '\r']).to_string())
    } else {
        cli_input::read_masked(&format!("Password for {user}@{host} (input hidden): "))
    };
    let mut fields = serde_json::json!({
        "host": host, "port": port.to_string(), "user": user,
        "password": password.as_str(), "database": database, "sslmode": sslmode,
    });
    if !ca_pem.is_empty() {
        fields["ca_pem"] = serde_json::Value::String(ca_pem);
    }
    let r = client::send_request(&Request::RecordSet {
        name: name.to_uppercase(),
        record_type: "database".into(),
        fields: ZeroString::from_string(fields.to_string()),
        requires_consent: args
            .iter()
            .any(|a| a == "--requires-consent")
            .then_some(true),
        seal: true,
    })
    .unwrap_or_else(Response::fail);
    if let Response::SetOk { name, .. } = &r {
        cli_ui::ok(&format!(
            "{name}: sealed PostgreSQL login for {host}:{port}; agents reach it through `kepr agent run`"
        ));
    }
    r
}

/// A gate route for every sealed `database` record.
pub fn routes(existing: &[GateRoute], sealed: &[CredInfo]) -> Vec<GateRoute> {
    let mut slot = existing.iter().map(|r| r.slot + 1).max().unwrap_or(0);
    let mut out = Vec::new();
    for c in sealed
        .iter()
        .filter(|c| c.record_type.as_deref() == Some("database"))
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
            provider: db_route_key(&c.name),
            cred: c.name.clone(),
            slot,
            target: Some(DbTarget {
                host,
                port,
                rotate: false,
            }),
        });
        slot += 1;
    }
    out
}

/// Inherited variables the database env replaces.
pub const DB_VARS: &[&str] = &[
    "DATABASE_URL",
    "PGHOST",
    "PGPORT",
    "PGUSER",
    "PGPASSWORD",
    "PGDATABASE",
    "PGSSLMODE",
];

/// DATABASE_URL / PG* for one database (when there is exactly one), and
/// KEPR_DB_<NAME>_URL for each.
pub fn env(
    placeholders: &HashMap<String, String>,
    ports: &HashMap<String, u16>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (key, port) in ports {
        let (Some(name), Some(ph)) = (key.strip_prefix("db:"), placeholders.get(key)) else {
            continue;
        };
        let url = format!("postgres://kepr:{ph}@127.0.0.1:{port}/kepr?sslmode=disable");
        out.push((format!("KEPR_DB_{name}_URL"), url.clone()));
        if ports.len() == 1 {
            out.push(("DATABASE_URL".into(), url));
            for (k, v) in [
                ("PGHOST", "127.0.0.1".to_string()),
                ("PGPORT", port.to_string()),
                ("PGUSER", "kepr".into()),
                ("PGPASSWORD", ph.clone()),
                ("PGDATABASE", "kepr".into()),
                ("PGSSLMODE", "disable".into()),
            ] {
                out.push((k.into(), v));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(
            parse_url("postgres://app@DB.example.com:6543/prod?sslmode=require").unwrap(),
            ("app".into(), "db.example.com".into(), 6543, "prod".into())
        );
        assert_eq!(parse_url("postgresql://u@h.io/d").unwrap().2, 5432);
        assert!(parse_url("postgres://u:pw@h.io/d")
            .unwrap_err()
            .contains("password"));
        assert!(parse_url("mysql://u@h.io/d").is_err());
        assert!(parse_url("postgres://u@h.io").is_err());
    }

    #[test]
    fn one_database_gets_the_standard_variables() {
        let ph: HashMap<String, String> = [("db:PROD".to_string(), "kepr-ph-1".to_string())].into();
        let ports: HashMap<String, u16> = [("db:PROD".to_string(), 5555)].into();
        let e: HashMap<String, String> = env(&ph, &ports).into_iter().collect();
        assert_eq!(e["PGPASSWORD"], "kepr-ph-1");
        assert_eq!(e["PGPORT"], "5555");
        assert!(e["DATABASE_URL"].contains("kepr-ph-1@127.0.0.1:5555"));
        assert_eq!(e["KEPR_DB_PROD_URL"], e["DATABASE_URL"]);
    }
}
