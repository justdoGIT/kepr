// Session route, framing contract and isolation regressions.
use super::*;

#[test]
fn explicit_https_routes_are_bounded_and_cannot_spoof_credentials() {
    let routes: Vec<_> = (0..crate::http_route::MAX_ROUTES)
        .map(|slot| {
            let cred = format!("KEY_{slot}");
            GateRoute {
                provider: crate::http_route::key("api.example.com", &cred).unwrap(),
                cred,
                slot: slot as u16,
                target: None,
            }
        })
        .collect();
    assert!(validate_routes(&routes).is_ok());
    let mut bad = routes.clone();
    bad[0].cred = "OTHER".into();
    assert!(validate_routes(&bad).is_err());
    let mut too_many = routes;
    too_many.push(GateRoute {
        provider: "xai".into(),
        cred: "XAI_API_KEY".into(),
        slot: crate::http_route::MAX_ROUTES as u16,
        target: None,
    });
    assert!(validate_routes(&too_many)
        .unwrap_err()
        .contains(&format!("1-{}", crate::http_route::MAX_ROUTES)));
}

#[test]
fn rotation_messages_and_routes() {
    let r = GateRequest::RotateCommit {
        id: 4,
        name: "GH".into(),
        value: ZeroString::from("new"),
    };
    let wire = serde_json::to_string(&r).unwrap();
    assert!(wire.contains("rotatecommit"));
    assert!(matches!(
        serde_json::from_str::<GateRequest>(&wire).unwrap(),
        GateRequest::RotateCommit { id: 4, .. }
    ));
    let ok = serde_json::to_string(&GateResponse::Rotated { id: 4 }).unwrap();
    assert_eq!(serde_json::from_str::<GateResponse>(&ok).unwrap().id(), 4);
    let route = |provider: &str| GateRoute {
        provider: provider.into(),
        cred: "GH".into(),
        slot: 0,
        target: None,
    };
    assert!(validate_routes(&[route("rotate:GH")]).is_ok());
    assert!(validate_routes(&[route("rotate:OTHER")]).is_err());
    assert_eq!(rotatable_creds(&[route("rotate:GH")]).len(), 1);
    assert!(rotatable_creds(&[route("anthropic")]).is_empty());
}

#[test]
fn gate_messages_round_trip() {
    let r = GateRequest::Resolve {
        id: 7,
        name: "A".into(),
        host: "api.x.ai".into(),
        port: 443,
    };
    let j = serde_json::to_string(&r).unwrap();
    assert!(j.contains(r#""cmd":"resolve""#));
    let _: GateRequest = serde_json::from_str(&j).unwrap();
    let ok = GateResponse::ResolveOk {
        id: 7,
        value: ZeroString::from_string("v".into()),
        inject: Inject::Bearer,
    };
    let j = serde_json::to_string(&ok).unwrap();
    let back: GateResponse = serde_json::from_str(&j).unwrap();
    assert_eq!(back.id(), 7);
}

#[test]
fn route_rules() {
    let r = |p: &str, slot: u16| GateRoute {
        provider: p.into(),
        cred: "K".into(),
        slot,
        target: None,
    };
    assert!(validate_routes(&[r("anthropic", 0), r("xai", 1)]).is_ok());
    assert!(validate_routes(&[]).is_err());
    assert!(validate_routes(&[r("nope", 0)]).is_err());
    assert!(validate_routes(&[r("xai", 0), r("xai", 1)]).is_err());
    assert!(validate_routes(&[r("xai", 0), r("openai", 0)]).is_err());
    assert!(validate_routes(&(0..17).map(|i| r("xai", i)).collect::<Vec<_>>()).is_err());
    // T2.02: an AWS route is keyed by its own credential only.
    assert!(validate_routes(&[r("xai", 0), r("aws:K", 1)]).is_ok());
    assert!(validate_routes(&[r("aws:OTHER", 0)]).is_err());
    assert!(validate_routes(&[r("aws:", 0)]).is_err());
}

#[test]
fn target_kind_defaults_to_postgres_and_round_trips() {
    let t: DbTarget = serde_json::from_str(r#"{"host":"db.x.io","port":5432}"#).unwrap();
    assert_eq!(t.kind, TargetKind::Postgres);
    assert!(!serde_json::to_string(&t).unwrap().contains("kind"));
    let r = DbTarget {
        kind: TargetKind::Redis,
        ..t
    };
    let j = serde_json::to_string(&r).unwrap();
    assert!(j.contains(r#""kind":"redis""#), "{j}");
    assert_eq!(serde_json::from_str::<DbTarget>(&j).unwrap(), r);
    for k in [TargetKind::Postgres, TargetKind::Redis, TargetKind::Mysql] {
        assert_eq!(
            TargetKind::parse(k.inject().unwrap().db_kind().unwrap()),
            Some(k)
        );
    }
}

#[test]
fn tunnel_routes_need_their_own_key_and_are_never_resolved() {
    let tunnel = |provider: &str, slot| GateRoute {
        provider: provider.into(),
        cred: "WIKI".into(),
        slot,
        target: Some(DbTarget {
            host: "wiki.internal.example".into(),
            port: 8080,
            kind: TargetKind::Tcp,
            ..Default::default()
        }),
    };
    let api = GateRoute {
        provider: "anthropic".into(),
        cred: "ANTHROPIC_API_KEY".into(),
        slot: 0,
        target: None,
    };
    assert!(validate_routes(&[api.clone(), tunnel("tcp:WIKI", 1)]).is_ok());
    assert!(validate_routes(&[tunnel("db:WIKI", 1)]).is_err());
    let as_db = GateRoute {
        target: Some(DbTarget {
            kind: TargetKind::Postgres,
            ..tunnel("", 0).target.unwrap()
        }),
        ..tunnel("tcp:WIKI", 1)
    };
    assert!(validate_routes(&[as_db]).is_err());
    let creds = resolvable_creds(&[api, tunnel("tcp:WIKI", 1)]);
    assert_eq!(
        creds.into_iter().collect::<Vec<_>>(),
        vec!["ANTHROPIC_API_KEY"]
    );
    assert_eq!(TargetKind::parse("tcp"), None);
}

#[test]
fn role_grants_are_postgres_only_and_make_the_admin_resolvable() {
    let db = |kind, role: &str, admin: &str| GateRoute {
        provider: "db:APP_DB".into(),
        cred: "APP_DB".into(),
        slot: 0,
        target: Some(DbTarget {
            host: "db.example.com".into(),
            port: 5432,
            kind,
            grant: Some(RoleGrant {
                role: role.into(),
                admin: admin.into(),
            }),
            ..Default::default()
        }),
    };
    let ok = db(TargetKind::Postgres, "Analyst \"rw\"", "APP_ADMIN");
    assert!(validate_routes(std::slice::from_ref(&ok)).is_ok());
    let j = serde_json::to_string(&ok).unwrap();
    assert!(j.contains(r#""grant":{"role":"#), "{j}");
    assert_eq!(serde_json::from_str::<GateRoute>(&j).unwrap(), ok);
    let plain: DbTarget = serde_json::from_str(r#"{"host":"db.x.io","port":5432}"#).unwrap();
    assert!(plain.grant.is_none());
    assert!(!serde_json::to_string(&plain).unwrap().contains("grant"));
    for bad in [
        db(TargetKind::Mysql, "analyst", "APP_ADMIN"),
        db(TargetKind::Postgres, "", "APP_ADMIN"),
        db(TargetKind::Postgres, &"r".repeat(64), "APP_ADMIN"),
        db(TargetKind::Postgres, "a\0b", "APP_ADMIN"),
        db(TargetKind::Postgres, "a\\b", "APP_ADMIN"),
        db(TargetKind::Postgres, "analyst", "../x"),
        db(TargetKind::Postgres, "analyst", ""),
        db(TargetKind::Postgres, "analyst", "app_db"),
    ] {
        assert!(
            validate_routes(std::slice::from_ref(&bad)).is_err(),
            "{bad:?}"
        );
    }
    // The admin login must not be reachable by the agent itself.
    let admin_route = GateRoute {
        provider: "db:APP_ADMIN".into(),
        cred: "APP_ADMIN".into(),
        slot: 1,
        target: Some(DbTarget {
            host: "db.example.com".into(),
            port: 5432,
            ..Default::default()
        }),
    };
    let both = [ok.clone(), admin_route];
    assert!(validate_routes(&both).unwrap_err().contains("APP_ADMIN"));
    let mut creds: Vec<_> = resolvable_creds(&[ok]).into_iter().collect();
    creds.sort();
    assert_eq!(creds, vec!["APP_ADMIN", "APP_DB"]);
}

#[test]
fn limits_validate_and_default_to_none() {
    assert!(GateLimits::default().is_none());
    assert!(GateLimits::default().validate().is_ok());
    let l = |r, t, m| GateLimits {
        max_requests: r,
        max_tokens: t,
        per_minute: m,
        ..Default::default()
    };
    assert!(l(Some(10), Some(1000), Some(60)).validate().is_ok());
    assert!(l(Some(0), None, None).validate().is_err());
    assert!(l(None, Some(0), None).validate().is_err());
    assert!(l(None, None, Some(0)).validate().is_err());
    assert!(l(None, None, Some(20_000)).validate().is_err());
    let cfg: SessionConfig =
        serde_json::from_str(r#"{"session_id":"a","session_key_hex":"b","routes":[]}"#).unwrap();
    assert!(cfg.limits.is_none());
}

#[test]
fn daily_caps_and_usage_reports() {
    let day = GateLimits {
        max_requests_day: Some(100),
        max_tokens_day: Some(50_000),
        ..Default::default()
    };
    assert!(day.validate().is_ok() && !day.is_none());
    let zero = GateLimits {
        max_tokens_day: Some(0),
        ..Default::default()
    };
    assert!(zero.validate().is_err());
    let wire = serde_json::to_string(&GateRequest::DayUsage {
        id: 7,
        name: "K".into(),
        requests: 1,
        tokens: 0,
    })
    .unwrap();
    assert_eq!(
        wire,
        r#"{"cmd":"dayusage","id":7,"name":"K","requests":1,"tokens":0}"#
    );
    assert!(serde_json::from_str::<crate::protocol::Request>(&wire).is_err());
    let back: GateResponse = serde_json::from_str(
        &serde_json::to_string(&GateResponse::UsageToday {
            id: 7,
            requests: 3,
            tokens: 9,
        })
        .unwrap(),
    )
    .unwrap();
    assert_eq!(back.id(), 7);
}

#[test]
fn canary_checks_are_private() {
    let wire = serde_json::to_string(&GateRequest::Canary {
        id: 3,
        fingerprints: vec!["ab".into()],
    })
    .unwrap();
    assert_eq!(wire, r#"{"cmd":"canary","id":3,"fingerprints":["ab"]}"#);
    assert!(serde_json::from_str::<crate::protocol::Request>(&wire).is_err());
    let r = GateResponse::CanaryChecked {
        id: 3,
        tripped: true,
    };
    assert_eq!(r.id(), 3);
}

#[test]
fn resolve_is_not_a_public_request() {
    let j = r#"{"cmd":"resolve","name":"A","host":"api.x.ai","port":443}"#;
    assert!(serde_json::from_str::<crate::protocol::Request>(j).is_err());
}
