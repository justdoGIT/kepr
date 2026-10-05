// cli_agent_db.rs — database logins for agents (agent vault P7.1).
//
//   kepr agent add-db NAME --url postgres://USER@HOST[:PORT]/DB
//                     [--kind postgres|mysql|redis] [--sslmode verify-full|disable]
//                     [--ca FILE] [--stdin]
//   kepr agent add-db NAME --url redis[s]://[USER@]HOST[:PORT][/DB]
//   kepr agent add-db NAME --url mysql://USER@HOST[:PORT]/DB
//
// Stores a sealed `database` record (password asked for, hidden; `kind`
// for anything but PostgreSQL). In `kepr agent run`, each one becomes a
// gate route with its own loopback port; the harness gets DATABASE_URL /
// PG*, MYSQL_* or REDIS_URL pointing there with the session placeholder as
// password, and the gate logs in for it.

use std::collections::HashMap;
use std::io::{BufRead, IsTerminal};

use kepr_core::gate_protocol::{db_route_key, DbTarget, GateRoute, TargetKind};
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{CredInfo, Request, Response};

use crate::cli_extra::flag;
use crate::{cli_input, cli_ui, client};

const USAGE: &str = "usage: kepr agent add-db NAME --url postgres://USER@HOST[:PORT]/DB | mysql://USER@HOST[:PORT]/DB | redis[s]://[USER@]HOST[:PORT][/DB] [--kind postgres|mysql|redis] [--sslmode verify-full|disable] [--ca FILE] [--stdin]";

/// A database URL as `kepr agent add-db` takes it (never with a password).
#[derive(Debug, PartialEq)]
pub struct DbUrl {
    pub kind: TargetKind,
    pub user: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    /// What the scheme implies: `rediss://` and SQL URLs verify TLS.
    pub sslmode: &'static str,
}

/// `postgres://user@host:port/db`, `redis[s]://[user@]host[:port][/n]`.
/// No password in the URL: it would land in shell history.
pub fn parse_url(url: &str) -> Result<DbUrl, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or("the URL must start with postgres://, mysql://, redis:// or rediss://")?;
    let (kind, sslmode) = match scheme {
        "postgres" | "postgresql" => (TargetKind::Postgres, "verify-full"),
        "mysql" => (TargetKind::Mysql, "verify-full"),
        "redis" => (TargetKind::Redis, "disable"),
        "rediss" => (TargetKind::Redis, "verify-full"),
        _ => {
            return Err(
                "the URL must start with postgres://, mysql://, redis:// or rediss://".into(),
            )
        }
    };
    let (auth, rest) = rest.split_once('@').unwrap_or(("", rest));
    if auth.contains(':') {
        return Err("leave the password out of the URL; kepr asks for it".into());
    }
    let (hostport, db) = rest.split_once('/').unwrap_or((rest, ""));
    let db = db.split('?').next().unwrap_or_default();
    let default_port = kepr_core::binding::Inject::for_db_kind(kind.name()).map_or(0, |d| d.1);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| "invalid port")?),
        None => (hostport, default_port),
    };
    let (user, database) = match kind {
        TargetKind::Redis => {
            if !db.is_empty() && db.parse::<u32>().is_err() {
                return Err("a Redis database is a number, e.g. redis://host:6379/0".into());
            }
            let or = |s: &str, d: &str| {
                if s.is_empty() {
                    d.to_string()
                } else {
                    s.into()
                }
            };
            (or(auth, "default"), or(db, "0"))
        }
        _ => (auth.to_string(), db.to_string()),
    };
    if user.is_empty() || host.is_empty() || database.is_empty() {
        return Err("the URL needs a user, a host and a database".into());
    }
    Ok(DbUrl {
        kind,
        user,
        host: host.to_ascii_lowercase(),
        port,
        database,
        sslmode,
    })
}

fn label(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Postgres => "PostgreSQL",
        TargetKind::Redis => "Redis",
        TargetKind::Mysql => "MySQL",
    }
}

pub fn cmd_add_db(args: &[String]) -> Response {
    let (Some(name), Some(url)) = (
        args.first().filter(|a| !a.starts_with('-')),
        flag(args, "--url"),
    ) else {
        return Response::fail(USAGE);
    };
    let u = match parse_url(url) {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
    if let Some(k) = flag(args, "--kind") {
        if TargetKind::parse(k) != Some(u.kind) {
            return Response::fail(format!("--kind {k} does not match the URL ({url})"));
        }
    }
    let sslmode = flag(args, "--sslmode").unwrap_or(u.sslmode);
    let ca_pem = match flag(args, "--ca").map(std::fs::read_to_string) {
        Some(Ok(p)) => p,
        Some(Err(e)) => return Response::fail(format!("--ca: {e}")),
        None => String::new(),
    };
    let (user, host, port) = (&u.user, &u.host, u.port);
    let password = if args.iter().any(|a| a == "--stdin") || !std::io::stdin().is_terminal() {
        let mut s = zeroize::Zeroizing::new(String::new());
        let _ = std::io::stdin().lock().read_line(&mut s);
        ZeroString::from_string(s.trim_end_matches(['\n', '\r']).to_string())
    } else {
        cli_input::read_masked(&format!("Password for {user}@{host} (input hidden): "))
    };
    let mut fields = serde_json::json!({
        "host": host, "port": port.to_string(), "user": user,
        "password": password.as_str(), "database": u.database, "sslmode": sslmode,
    });
    if !u.kind.is_postgres() {
        fields["kind"] = u.kind.name().into();
    }
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
            "{name}: sealed {} login for {host}:{port}; agents reach it through `kepr agent run`",
            label(u.kind)
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
        // No kind from the daemon: an older one, whose logins are all
        // PostgreSQL. A kind this CLI doesn't know gets no route.
        let Some(kind) = c
            .db_kind
            .as_deref()
            .map_or(Some(TargetKind::Postgres), TargetKind::parse)
        else {
            continue;
        };
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
                kind,
                ..Default::default()
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
    "REDIS_URL",
    "MYSQL_HOST",
    "MYSQL_TCP_PORT",
    "MYSQL_PWD",
];

/// The standard variables for the one database of a kind.
fn standard(kind: TargetKind, url: &str, ph: &str, port: u16) -> Vec<(String, String)> {
    let mut out = vec![];
    let mut put = |k: &str, v: String| out.push((k.to_string(), v));
    match kind {
        TargetKind::Postgres => {
            put("DATABASE_URL", url.into());
            put("PGHOST", "127.0.0.1".into());
            put("PGPORT", port.to_string());
            put("PGUSER", "kepr".into());
            put("PGPASSWORD", ph.into());
            put("PGDATABASE", "kepr".into());
            put("PGSSLMODE", "disable".into());
        }
        TargetKind::Redis => put("REDIS_URL", url.into()),
        TargetKind::Mysql => {
            put("MYSQL_HOST", "127.0.0.1".into());
            put("MYSQL_TCP_PORT", port.to_string());
            put("MYSQL_PWD", ph.into());
        }
    }
    out
}

/// KEPR_DB_<NAME>_URL for each database route, and the standard
/// variables (DATABASE_URL / PG*, REDIS_URL) when a session has exactly
/// one database of that kind.
pub fn env(
    routes: &[GateRoute],
    placeholders: &HashMap<String, String>,
    ports: &HashMap<String, u16>,
) -> Vec<(String, String)> {
    let dbs: Vec<(&str, TargetKind, &String, u16)> = routes
        .iter()
        .filter_map(|r| {
            let name = r.provider.strip_prefix("db:")?;
            let ph = placeholders.get(&r.provider)?;
            Some((name, r.target.as_ref()?.kind, ph, *ports.get(&r.provider)?))
        })
        .collect();
    let mut out = Vec::new();
    for (name, kind, ph, port) in &dbs {
        let url = match kind {
            TargetKind::Postgres => {
                format!("postgres://kepr:{ph}@127.0.0.1:{port}/kepr?sslmode=disable")
            }
            TargetKind::Redis => format!("redis://kepr:{ph}@127.0.0.1:{port}"),
            TargetKind::Mysql => {
                format!("mysql://kepr:{ph}@127.0.0.1:{port}/kepr?ssl-mode=DISABLED")
            }
        };
        out.push((format!("KEPR_DB_{name}_URL"), url.clone()));
        if dbs.iter().filter(|d| d.1 == *kind).count() == 1 {
            out.extend(standard(*kind, &url, ph, *port));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("postgres://app@DB.example.com:6543/prod?sslmode=require").unwrap();
        assert_eq!(
            (
                u.user.as_str(),
                u.host.as_str(),
                u.port,
                u.database.as_str()
            ),
            ("app", "db.example.com", 6543, "prod")
        );
        assert_eq!((u.kind, u.sslmode), (TargetKind::Postgres, "verify-full"));
        assert_eq!(parse_url("postgresql://u@h.io/d").unwrap().port, 5432);
        assert!(parse_url("postgres://u:pw@h.io/d")
            .unwrap_err()
            .contains("password"));
        assert!(parse_url("ftp://u@h.io/d").is_err());
        assert!(parse_url("postgres://u@h.io").is_err());
    }

    #[test]
    fn redis_urls() {
        let u = parse_url("redis://cache.example.com").unwrap();
        assert_eq!(
            (u.kind, u.user.as_str(), u.port, u.database.as_str()),
            (TargetKind::Redis, "default", 6379, "0")
        );
        assert_eq!(u.sslmode, "disable");
        let s = parse_url("rediss://app@cache.example.com:6380/3").unwrap();
        assert_eq!(
            (s.user.as_str(), s.port, s.database.as_str(), s.sslmode),
            ("app", 6380, "3", "verify-full")
        );
        let m = parse_url("mysql://app@MY.example.com/prod").unwrap();
        assert_eq!(
            (m.kind, m.port, m.database.as_str(), m.sslmode),
            (TargetKind::Mysql, 3306, "prod", "verify-full")
        );
        assert!(parse_url("mysql://app@my.example.com").is_err());
        assert!(parse_url("redis://:pw@cache.example.com").is_err());
        assert!(parse_url("redis://cache.example.com/x").is_err());
    }

    fn db_route(name: &str, kind: TargetKind, slot: u16) -> GateRoute {
        GateRoute {
            provider: db_route_key(name),
            cred: name.into(),
            slot,
            target: Some(DbTarget {
                kind,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn one_database_gets_the_standard_variables() {
        let ph: HashMap<String, String> = [("db:PROD".to_string(), "kepr-ph-1".to_string())].into();
        let ports: HashMap<String, u16> = [("db:PROD".to_string(), 5555)].into();
        let routes = [db_route("PROD", TargetKind::Postgres, 0)];
        let e: HashMap<String, String> = env(&routes, &ph, &ports).into_iter().collect();
        assert_eq!(e["PGPASSWORD"], "kepr-ph-1");
        assert_eq!(e["PGPORT"], "5555");
        assert!(e["DATABASE_URL"].contains("kepr-ph-1@127.0.0.1:5555"));
        assert_eq!(e["KEPR_DB_PROD_URL"], e["DATABASE_URL"]);
    }

    #[test]
    fn redis_routes_get_redis_url_and_their_kind() {
        let ph: HashMap<String, String> = [
            ("db:PROD".to_string(), "kepr-ph-1".to_string()),
            ("db:CACHE".to_string(), "kepr-ph-2".to_string()),
        ]
        .into();
        let ports: HashMap<String, u16> = [
            ("db:PROD".to_string(), 5555),
            ("db:CACHE".to_string(), 6666),
        ]
        .into();
        let rs = [
            db_route("PROD", TargetKind::Postgres, 0),
            db_route("CACHE", TargetKind::Redis, 1),
        ];
        let e: HashMap<String, String> = env(&rs, &ph, &ports).into_iter().collect();
        assert_eq!(e["REDIS_URL"], "redis://kepr:kepr-ph-2@127.0.0.1:6666");
        assert!(e["DATABASE_URL"].starts_with("postgres://"));
        let mut c: CredInfo = serde_json::from_str(
            r#"{"name":"CACHE","cred_name":"","size":0,"modified":"","sealed":true,
                "bound_hosts":["cache.example.com:6379"],"record_type":"database","db_kind":"redis"}"#,
        )
        .unwrap();
        let r = routes_for_one(&c);
        assert_eq!(r.target.unwrap().kind, TargetKind::Redis);
        c.db_kind = None;
        assert_eq!(
            routes_for_one(&c).target.unwrap().kind,
            TargetKind::Postgres
        );
        c.db_kind = Some("oracle".into());
        assert!(routes(&[], &[c]).is_empty());
    }

    fn routes_for_one(c: &CredInfo) -> GateRoute {
        routes(&[], std::slice::from_ref(c)).remove(0)
    }
}
