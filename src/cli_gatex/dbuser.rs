// cli_gatex/dbuser.rs — `kepr agent run --db-user NAME=ROLE[:TTL]` (T13.02):
// the PostgreSQL route NAME logs the agent in as a login role the gate makes
// for the session (a member of ROLE, valid for TTL seconds, default 3600)
// and drops when the agent exits. NAME's sealed record is an admin login
// that may CREATE ROLE; the agent never holds a long-lived database
// password, and the admin's password never leaves the gate.

use kepr_core::gate_protocol::{
    db_route_key, Ephemeral, GateRoute, EPHEMERAL_DEFAULT_TTL, EPHEMERAL_TTL,
};

/// `NAME=ROLE[:TTL]` → (NAME, ephemeral). A final `:digits` is the TTL; a
/// role name that itself ends in `:digits` is not expressible here.
pub fn parse(spec: &str) -> Result<(String, Ephemeral), String> {
    let bad = || format!("--db-user {spec}: use NAME=ROLE[:TTL_SECONDS], e.g. APP_DB=analyst:3600");
    let (name, rest) = spec.split_once('=').ok_or_else(bad)?;
    let (role, ttl) = match rest.rsplit_once(':') {
        Some((r, t)) if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) => {
            (r, t.parse::<u64>().map_err(|_| bad())?)
        }
        _ => (rest, EPHEMERAL_DEFAULT_TTL),
    };
    if name.is_empty() || role.is_empty() {
        return Err(bad());
    }
    if !EPHEMERAL_TTL.contains(&ttl) {
        return Err(format!(
            "--db-user {spec}: the TTL is {} to {} seconds",
            EPHEMERAL_TTL.start(),
            EPHEMERAL_TTL.end()
        ));
    }
    Ok((
        name.to_uppercase(),
        Ephemeral {
            role: role.to_string(),
            ttl_secs: ttl,
        },
    ))
}

/// Attach each spec to its database route. The daemon validates the
/// result again (`validate_routes`).
pub fn apply(routes: &mut [GateRoute], specs: &[String]) -> Result<(), String> {
    for spec in specs {
        let (name, e) = parse(spec)?;
        let key = db_route_key(&name);
        let target = routes
            .iter_mut()
            .find(|r| r.provider == key)
            .and_then(|r| r.target.as_mut())
            .ok_or_else(|| {
                format!("--db-user: no sealed database login {name} (see `kepr agent add-db`)")
            })?;
        if target.ephemeral.is_some() {
            return Err(format!("--db-user: {name} is given twice"));
        }
        target.ephemeral = Some(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::gate_protocol::{validate_routes, DbTarget, TargetKind};

    fn db(name: &str, kind: TargetKind) -> GateRoute {
        GateRoute {
            provider: db_route_key(name),
            cred: name.into(),
            slot: 0,
            target: Some(DbTarget {
                host: "db.example.com".into(),
                port: 5432,
                kind,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn specs() {
        let (n, e) = parse("app_db=analyst").unwrap();
        assert_eq!(
            (n.as_str(), e.role.as_str(), e.ttl_secs),
            ("APP_DB", "analyst", 3600)
        );
        let (_, e) = parse("A=Read Only:900").unwrap();
        assert_eq!((e.role.as_str(), e.ttl_secs), ("Read Only", 900));
        // A trailing non-number is part of the role.
        let (_, e) = parse("A=team:ops").unwrap();
        assert_eq!((e.role.as_str(), e.ttl_secs), ("team:ops", 3600));
        for bad in [
            "APP_DB",
            "=r",
            "A=",
            "A=r:30",
            "A=r:999999",
            "A=r:99999999999999999999999",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn applies_to_a_postgres_route_only() {
        let mut routes = vec![db("APP_DB", TargetKind::Postgres)];
        apply(&mut routes, &["app_db=analyst:600".into()]).unwrap();
        assert!(validate_routes(&routes).is_ok());
        assert_eq!(
            routes[0]
                .target
                .as_ref()
                .unwrap()
                .ephemeral
                .as_ref()
                .unwrap()
                .ttl_secs,
            600
        );
        assert!(apply(&mut routes, &["APP_DB=x".into()])
            .unwrap_err()
            .contains("twice"));
        assert!(apply(&mut routes, &["NOPE=x".into()])
            .unwrap_err()
            .contains("no sealed database login"));

        let mut redis = vec![db("CACHE", TargetKind::Redis)];
        apply(&mut redis, &["CACHE=x".into()]).unwrap();
        assert!(validate_routes(&redis).unwrap_err().contains("PostgreSQL"));
    }

    #[test]
    fn it_does_not_mix_with_grants_or_rotation() {
        let mut routes = vec![db("APP_DB", TargetKind::Postgres)];
        apply(&mut routes, &["APP_DB=x".into()]).unwrap();
        routes[0].target.as_mut().unwrap().rotate = true;
        assert!(validate_routes(&routes).unwrap_err().contains("--grant"));
    }
}
