use super::*;
use crate::cli_agent_install::{upsert_grok, upsert_omp};

fn is_ok(c: &Check) -> bool {
    matches!(c, Check::Ok(_))
}
fn is_problem(c: &Check) -> bool {
    matches!(c, Check::Problem(_))
}

#[test]
fn configs_route_through_the_gate_or_not() {
    for upsert in [upsert_omp as fn(&str, Option<u16>) -> String, upsert_grok] {
        let dynamic = upsert("", None);
        assert!(is_ok(&check_config(Some(&dynamic), None, upsert)));
        assert!(is_problem(&check_config(
            Some(&dynamic),
            Some(9000),
            upsert
        )));
        let fixed = upsert("", Some(7879));
        assert!(is_ok(&check_config(Some(&fixed), Some(7879), upsert)));
        assert!(is_problem(&check_config(Some(&fixed), None, upsert)));
        assert!(matches!(
            check_config(None, None, upsert),
            Check::NotInstalled
        ));
    }
}

#[test]
fn dynamic_omp_configuration_preserves_user_provider_routes() {
    assert!(is_ok(&check_config(
        Some("providers: {}\n"),
        None,
        upsert_omp
    )));
    assert!(is_problem(&check_config(
        Some("other = 1\n"),
        None,
        upsert_grok
    )));
}

#[test]
fn problems_carry_the_fix_and_never_file_contents() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let omp = home.join(".config/omp/agent/models.yml");
    std::fs::create_dir_all(omp.parent().unwrap()).unwrap();
    std::fs::write(
        &omp,
        "providers:\n  mine:\n    apiKey: PRIVATE_CONFIG_MARKER\n",
    )
    .unwrap();
    let r = reports_at(home, None, None, None, &|| None, &|_| Ok(()));
    let omp_r = r.iter().find(|r| r.harness == "omp").unwrap();
    let p = omp_r.problems();
    assert!(
        p.iter().any(|m| m.contains("kepr agent install omp")),
        "{p:?}"
    );
    assert!(p.iter().all(|m| !m.contains("PRIVATE_CONFIG_MARKER")));
    assert!(p.iter().any(|m| m.contains("plugin")), "{p:?}");
    let grok_r = r.iter().find(|r| r.harness == "grok").unwrap();
    assert!(grok_r.problems().is_empty(), "grok isn't installed here");
}

#[test]
fn healthy_harness_and_one_json_entry_each() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let omp = home.join(".config/omp/agent/models.yml");
    crate::cli_agent_install::apply(&omp, |t| upsert_omp(t, None)).unwrap();
    let (plugin, files) = crate::cli_agent_plugin::plugin_path("omp", home, None, None).unwrap();
    crate::cli_agent_plugin::write_plugin(&plugin, files).unwrap();
    let grok = home.join(".grok/config.toml");
    crate::cli_agent_install::apply(&grok, |t| upsert_grok(t, None)).unwrap();
    let (dir, files) = crate::cli_agent_plugin::plugin_path("grok", home, None, None).unwrap();
    crate::cli_agent_plugin::write_plugin(&dir, files).unwrap();
    // Both callbacks are injected: no vault, environment, PATH or external process.
    let r = reports_at(home, None, None, None, &|| Some(false), &|_| Ok(()));
    let res = results(&r);
    assert_eq!(res.len(), 2);
    assert_eq!(res["omp"], "ok");
    assert!(res["grok"].starts_with("problem: ") && res["grok"].contains("grok plugin"));
    let r = reports_at(home, None, None, None, &|| None, &|_| Ok(()));
    assert_eq!(results(&r)["grok"], "ok");
    assert!(r.iter().all(|r| r.problems().is_empty()));
    let none = reports_at(
        &home.join("nobody"),
        None,
        None,
        None,
        &|| panic!("uninstalled grok must not be queried"),
        &|_| panic!("uninstalled harness must not start a gate"),
    );
    let res = results(&none);
    assert_eq!(
        (res["omp"].as_str(), res["grok"].as_str()),
        ("not installed", "not installed")
    );
}

#[test]
fn startup_failure_does_not_hide_config_or_plugin_problems() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let grok = home.join(".grok/config.toml");
    std::fs::create_dir_all(grok.parent().unwrap()).unwrap();
    std::fs::write(&grok, "other = 'PRIVATE_CONFIG_MARKER'\n").unwrap();
    let calls = std::cell::RefCell::new(Vec::new());
    let reports = reports_at(home, None, None, None, &|| None, &|harness| {
        calls.borrow_mut().push(harness.to_string());
        Err("kepr-gate readiness timed out".into())
    });
    assert_eq!(*calls.borrow(), ["grok"]);
    let result = &results(&reports)["grok"];
    assert!(result.starts_with("problem: "));
    assert!(result.contains("does not route through the session gate"));
    assert!(result.contains("plugin missing"));
    assert!(result.contains("gate startup failed: kepr-gate readiness timed out"));
    assert!(!result.contains("PRIVATE_CONFIG_MARKER"));
}

#[test]
fn startup_checks_plugin_only_installations() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let (dir, files) = crate::cli_agent_plugin::plugin_path("omp", home, None, None).unwrap();
    crate::cli_agent_plugin::write_plugin(&dir, files).unwrap();
    let reports = reports_at(home, None, None, None, &|| None, &|harness| {
        assert_eq!(harness, "omp");
        Err("kepr-gate sent a malformed ready line".into())
    });
    let result = &results(&reports)["omp"];
    assert!(result.contains("is missing"));
    assert!(result.contains("malformed ready line"));
}

#[test]
fn parses_port_and_json() {
    assert_eq!(parse(&[]).unwrap(), (None, false));
    let a: Vec<String> = ["--port", "9000", "--json"].map(String::from).into();
    assert_eq!(parse(&a).unwrap(), (Some(9000), true));
    assert!(parse(&["--port".to_string()]).is_err());
    assert!(parse(&["x".to_string()]).is_err());
}
