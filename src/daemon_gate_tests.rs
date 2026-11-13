use super::*;
use kepr_core::binding::Binding;

fn route(cred: &str, slot: u16) -> GateRoute {
    GateRoute {
        provider: "anthropic".into(),
        cred: cred.into(),
        slot,
        target: None,
    }
}

fn sealed(exp: Option<u64>) -> expiry::CredMeta {
    expiry::CredMeta {
        expires_at_unix: exp,
        ..Default::default()
    }
    .with_seal(
        Some(true),
        Some(vec![Binding {
            host: "api.anthropic.com".into(),
            port: 443,
            inject: Inject::Header {
                name: "x-api-key".into(),
            },
        }]),
    )
    .unwrap()
}

#[test]
fn resolvable_only_when_sealed_bound_and_fresh() {
    let m = sealed(Some(100));
    assert!(check_resolvable(Some(&m), 10, "API.anthropic.com", 443).is_ok());
    assert_eq!(
        check_resolvable(Some(&m), 10, "evil.example.com", 443),
        Err("resolve: host not bound".into())
    );
    assert!(check_resolvable(Some(&m), 10, "api.anthropic.com", 8443).is_err());
    assert_eq!(
        check_resolvable(Some(&m), 100, "api.anthropic.com", 443),
        Err("resolve: expired".into())
    );
    assert!(check_resolvable(
        Some(&expiry::CredMeta::default()),
        0,
        "api.anthropic.com",
        443
    )
    .is_err());
    assert!(check_resolvable(None, 0, "api.anthropic.com", 443).is_err());
}

#[test]
fn route_validation() {
    assert!(validate_routes(&[route("A", 0)]).is_ok());
    assert!(validate_routes(&[]).is_err());
    assert!(validate_routes(&(0..17).map(|i| route("A", i)).collect::<Vec<_>>()).is_err());
    assert!(validate_routes(&[route("A", 0), route("B", 0)]).is_err());
    assert!(validate_routes(&[route("../x", 0)]).is_err());
    let mut bad = route("A", 0);
    bad.provider = "Evil/../".into();
    assert!(validate_routes(&[bad]).is_err());
}
