// cli_gatex/grant.rs — `kepr agent run --grant NAME=ROLE:ADMIN` (T7.18):
// the PostgreSQL route NAME holds ROLE only while the session runs. The
// gate grants it with the sealed ADMIN login before the route's first
// login and revokes it when the agent exits. ADMIN's own route is taken
// out of the session: the agent never holds the admin login.

use kepr_core::gate_protocol::{db_route_key, GateRoute, RoleGrant};

/// `NAME=ROLE:ADMIN` → (NAME, grant). NAME and ADMIN are credential
/// names (uppercased); ROLE is the database's role name, case kept, and
/// may itself contain `:` (ADMIN can't).
pub fn parse(spec: &str) -> Result<(String, RoleGrant), String> {
    let bad = || format!("--grant {spec}: use NAME=ROLE:ADMIN, e.g. APP_DB=analyst:APP_DB_ADMIN");
    let (name, rest) = spec.split_once('=').ok_or_else(bad)?;
    let (role, admin) = rest.rsplit_once(':').ok_or_else(bad)?;
    if name.is_empty() || role.is_empty() || admin.is_empty() {
        return Err(bad());
    }
    let grant = RoleGrant {
        role: role.to_string(),
        admin: admin.to_uppercase(),
    };
    Ok((name.to_uppercase(), grant))
}

/// Attach each grant to its database route and drop the admins' routes.
/// The daemon validates the result again (`validate_routes`).
pub fn apply(routes: &mut Vec<GateRoute>, specs: &[String]) -> Result<(), String> {
    let grants = specs
        .iter()
        .map(|s| parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    routes.retain(|r| {
        !grants
            .iter()
            .any(|(_, g)| r.provider == db_route_key(&g.admin))
    });
    for (name, g) in grants {
        let key = db_route_key(&name);
        let target = routes
            .iter_mut()
            .find(|r| r.provider == key)
            .and_then(|r| r.target.as_mut())
            .ok_or_else(|| {
                format!("--grant: no sealed database login {name} (see `kepr agent add-db`)")
            })?;
        if target.grant.is_some() {
            return Err(format!("--grant: {name} is given twice"));
        }
        target.grant = Some(g);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::gate_protocol::{validate_routes, DbTarget, TargetKind};

    fn db(name: &str, slot: u16, kind: TargetKind) -> GateRoute {
        GateRoute {
            provider: db_route_key(name),
            cred: name.into(),
            slot,
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
        let (name, g) = parse("app_db=Read:Only:app_admin").unwrap();
        assert_eq!(name, "APP_DB");
        assert_eq!(
            (g.role.as_str(), g.admin.as_str()),
            ("Read:Only", "APP_ADMIN")
        );
        for bad in ["APP_DB", "APP_DB=analyst", "=r:A", "A=:B", "A=r:"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_admin_route_leaves_the_session() {
        let mut routes = vec![
            db("APP_DB", 0, TargetKind::Postgres),
            db("APP_ADMIN", 1, TargetKind::Postgres),
            db("CACHE", 2, TargetKind::Redis),
        ];
        apply(&mut routes, &["app_db=analyst:app_admin".into()]).unwrap();
        let keys: Vec<&str> = routes.iter().map(|r| r.provider.as_str()).collect();
        assert_eq!(keys, vec!["db:APP_DB", "db:CACHE"]);
        let g = routes[0].target.as_ref().unwrap().grant.as_ref().unwrap();
        assert_eq!(
            (g.role.as_str(), g.admin.as_str()),
            ("analyst", "APP_ADMIN")
        );
        assert!(validate_routes(&routes).is_ok());
    }

    #[test]
    fn unknown_or_repeated_routes_are_refused() {
        let base = vec![db("APP_DB", 0, TargetKind::Postgres)];
        let mut r = base.clone();
        assert!(apply(&mut r, &["OTHER=analyst:APP_ADMIN".into()]).is_err());
        let mut r = base.clone();
        let twice = [
            "APP_DB=a:X_ADMIN".to_string(),
            "APP_DB=b:X_ADMIN".to_string(),
        ];
        assert!(apply(&mut r, &twice).unwrap_err().contains("twice"));
        // A Redis route takes the grant here but the daemon refuses it.
        let mut r = vec![db("CACHE", 0, TargetKind::Redis)];
        apply(&mut r, &["CACHE=analyst:APP_ADMIN".into()]).unwrap();
        assert!(validate_routes(&r).unwrap_err().contains("PostgreSQL"));
    }
}
