// Host, injection and binding validation regressions.
use super::*;

fn b(host: &str, port: u16, inject: Inject) -> Binding {
    Binding {
        host: host.to_string(),
        port,
        inject,
    }
}

#[test]
fn inject_variants_round_trip() {
    for i in [
        Inject::Bearer,
        Inject::Basic,
        Inject::Header {
            name: "x-api-key".into(),
        },
        Inject::Query {
            param: "key".into(),
        },
        Inject::Redis,
        Inject::Mysql,
    ] {
        let bb = b("api.example.com", 443, i);
        let json = serde_json::to_string(&bb).unwrap();
        let back: Binding = serde_json::from_str(&json).unwrap();
        assert_eq!(bb, back);
    }
}

#[test]
fn db_kinds_map_to_injects() {
    for kind in ["postgres", "redis", "mysql"] {
        let (inject, _) = Inject::for_db_kind(kind).unwrap();
        assert_eq!(inject.db_kind(), Some(kind));
    }
    assert_eq!(Inject::for_db_kind(""), Some((Inject::Postgres, 5432)));
    assert_eq!(Inject::for_db_kind("redis").unwrap().1, 6379);
    assert!(Inject::for_db_kind("oracle").is_none());
    assert_eq!(Inject::Bearer.db_kind(), None);
}

#[test]
fn port_defaults_to_443() {
    let bb: Binding =
        serde_json::from_str(r#"{"host":"api.x.ai","inject":{"kind":"bearer"}}"#).unwrap();
    assert_eq!(bb.port, 443);
}

#[test]
fn validate_rejects_bad_bindings() {
    for host in [
        "https://x.com",
        "x.com/path",
        "EXAMPLE.COM",
        "localhost",
        ".x.com",
        "x.com-",
    ] {
        assert!(
            validate_binding(&b(host, 443, Inject::Bearer)).is_err(),
            "{host}"
        );
    }
    assert!(validate_binding(&b("x.com", 0, Inject::Bearer)).is_err());
    let bad_header = Inject::Header {
        name: "x api".into(),
    };
    assert!(validate_binding(&b("x.com", 443, bad_header)).is_err());
    assert!(validate_binding(&b("api.openai.com", 443, Inject::Bearer)).is_ok());
}

#[test]
fn sigv4_binds_only_amazonaws_hosts() {
    assert_eq!(
        parse_binding("sts.amazonaws.com:sigv4").unwrap(),
        b("sts.amazonaws.com", 443, Inject::Sigv4)
    );
    assert!(parse_binding("s3.eu-west-1.amazonaws.com:sigv4").is_ok());
    for bad in [
        "api.example.com:sigv4",
        "amazonaws.com:sigv4",
        "evilamazonaws.com:sigv4",
        "sts.amazonaws.com.evil.com:sigv4",
        "sts.amazonaws.com:8443:sigv4",
    ] {
        assert!(parse_binding(bad).is_err(), "{bad}");
    }
    let j = serde_json::to_string(&b("sts.amazonaws.com", 443, Inject::Sigv4)).unwrap();
    assert!(j.contains(r#"{"kind":"sigv4"}"#), "{j}");
}

#[test]
fn github_app_binds_only_api_github_com() {
    let app = |a, i| Inject::GithubApp {
        app_id: a,
        installation_id: i,
    };
    assert!(validate_binding(&b("api.github.com", 443, app(1, 2))).is_ok());
    assert!(validate_binding(&b("github.com", 443, app(1, 2))).is_err());
    assert!(validate_binding(&b("api.github.com", 8443, app(1, 2))).is_err());
    assert!(validate_binding(&b("api.github.com", 443, app(0, 2))).is_err());
    assert!(validate_binding(&b("api.github.com", 443, app(1, 0))).is_err());
    let j = serde_json::to_string(&b("api.github.com", 443, app(7, 9))).unwrap();
    assert!(
        j.contains(r#"{"kind":"github_app","app_id":7,"installation_id":9}"#),
        "{j}"
    );
    assert_eq!(
        serde_json::from_str::<Binding>(&j).unwrap().inject,
        app(7, 9)
    );
}

#[test]
fn a_kube_login_needs_a_dns_name() {
    let k = |h: &str, p| b(h, p, Inject::KubeToken);
    assert!(validate_binding(&k("api.cluster.example.com", 6443)).is_ok());
    assert!(validate_binding(&k("k8s.internal", 443)).is_ok());
    assert!(validate_binding(&k("10.0.0.1", 6443)).is_err());
    assert!(validate_binding(&k("api.cluster.example.com", 0)).is_err());
    let j = serde_json::to_string(&k("k8s.internal", 6443)).unwrap();
    assert!(j.contains(r#""kind":"kube_token""#), "{j}");
}

#[test]
fn basic_password_binds_like_basic() {
    assert_eq!(
        parse_binding("github.com:basic-password").unwrap(),
        b("github.com", 443, Inject::BasicPassword)
    );
    let j = serde_json::to_string(&b("github.com", 443, Inject::BasicPassword)).unwrap();
    assert!(j.contains(r#"{"kind":"basic_password"}"#), "{j}");
    assert_eq!(
        serde_json::from_str::<Binding>(&j).unwrap().inject,
        Inject::BasicPassword
    );
    let err = parse_binding("github.com:basic-pass").unwrap_err();
    assert!(err.contains("basic-password"), "{err}");
}

#[test]
fn gcp_token_binds_only_google_api_hosts() {
    let gcp = |scopes: &[&str], imp: Option<&str>| Inject::GcpToken {
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        impersonate: imp.map(str::to_string),
    };
    let cloud = "https://www.googleapis.com/auth/cloud-platform";
    let email = "deploy@proj.iam.gserviceaccount.com";
    let sa = Some(email);
    assert!(validate_binding(&b("storage.googleapis.com", 443, gcp(&[cloud], None))).is_ok());
    assert!(validate_binding(&b("www.googleapis.com", 443, gcp(&[cloud], sa))).is_ok());
    assert!(validate_binding(&b("api.openai.com", 443, gcp(&[cloud], None))).is_err());
    let bad_scope = gcp(&["https://evil.example/scope"], None);
    assert!(validate_binding(&b("storage.googleapis.com", 443, bad_scope)).is_err());
    let bad_sa = gcp(&[cloud], Some("me@example.com"));
    assert!(validate_binding(&b("storage.googleapis.com", 443, bad_sa)).is_err());

    let bb = b("storage.googleapis.com", 443, gcp(&[cloud], sa));
    let j = serde_json::to_string(&bb).unwrap();
    assert!(
        j.contains(&format!(
            r#"{{"kind":"gcp_token","scopes":["{cloud}"],"impersonate":"{email}"}}"#
        )),
        "{j}"
    );
    assert_eq!(serde_json::from_str::<Binding>(&j).unwrap(), bb);
    let plain = format!(
        r#"{{"host":"x.googleapis.com","inject":{{"kind":"gcp_token","scopes":["{cloud}"]}}}}"#
    );
    let back: Binding = serde_json::from_str(&plain).unwrap();
    assert_eq!(back.inject, gcp(&[cloud], None));
    assert!(!serde_json::to_string(&back)
        .unwrap()
        .contains("impersonate"));
}

#[test]
fn parse_binding_forms() {
    assert_eq!(
        parse_binding("api.openai.com:bearer").unwrap(),
        b("api.openai.com", 443, Inject::Bearer)
    );
    assert_eq!(
        parse_binding("h.example.com:8443:query=key").unwrap(),
        b(
            "h.example.com",
            8443,
            Inject::Query {
                param: "key".into()
            }
        )
    );
    assert!(parse_binding("api.openai.com").is_err());
    assert!(parse_binding("a.b:99999:bearer").is_err());
    assert!(parse_binding("a.b:443:token").is_err());
}
