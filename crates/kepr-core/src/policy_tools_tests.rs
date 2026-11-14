use super::*;

fn rule(effect: Effect, tools: &[&str], actions: &[&str]) -> ToolRule {
    let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect();
    ToolRule {
        effect,
        tools: v(tools),
        actions: v(actions),
        resources: Vec::new(),
        tenants: Vec::new(),
        workspaces: Vec::new(),
        connector_accounts: Vec::new(),
        role: Vec::new(),
    }
}

fn req(tool: &str, resource: &str, action: &str) -> GrantRequest {
    GrantRequest::new(tool, resource, action)
}

#[test]
fn no_rules_is_left_to_the_command_line_grant() {
    // `PolicyFile::decide_tool` answers for the empty case; here the
    // evaluator itself refuses rather than silently allowing.
    assert!(decide(&[], &[], &req("db_query", "APP_DB", "query"))
        .reason()
        .is_some());
}

#[test]
fn first_matching_rule_decides() {
    let rules = vec![
        rule(Effect::Deny, &["db_query"], &["query"]),
        rule(Effect::Allow, &["db_query"], &["query"]),
    ];
    assert!(decide(&rules, &[], &req("db_query", "APP_DB", "query"))
        .reason()
        .is_some());
    let rules = vec![
        rule(Effect::Allow, &["db_query"], &["query"]),
        rule(Effect::Deny, &["db_query"], &["query"]),
    ];
    assert!(decide(&rules, &[], &req("db_query", "APP_DB", "query")).allowed());
}

#[test]
fn a_rule_for_another_tool_does_not_match() {
    let rules = vec![rule(Effect::Allow, &["db_query"], &["query"])];
    let d = decide(&rules, &[], &req("ssh_run", "web1", "exec"));
    assert!(d.reason().unwrap().contains("no tool rule allows"));
}

#[test]
fn tenant_and_workspace_conditions_scope_the_rule() {
    let mut r = rule(Effect::Allow, &["db_query"], &["query"]);
    r.tenants = vec!["acme".into()];
    r.workspaces = vec!["/home/kk/projects/acme".into()];
    let rules = vec![r];

    let mut personal = req("db_query", "APP_DB", "query");
    personal.tenant = "personal".into();
    personal.workspace = "/home/kk/projects/acme".into();
    assert!(decide(&rules, &[], &personal).reason().is_some());

    let mut outside = req("db_query", "APP_DB", "query");
    outside.tenant = "acme".into();
    outside.workspace = "/home/kk/scratch".into();
    assert!(decide(&rules, &[], &outside).reason().is_some());

    let mut inside = req("db_query", "APP_DB", "query");
    inside.tenant = "acme".into();
    inside.workspace = "/home/kk/projects/acme".into();
    assert!(decide(&rules, &[], &inside).allowed());
}

#[test]
fn an_action_outside_the_rule_denies_even_though_the_rule_matched() {
    let rules = vec![rule(Effect::Allow, &["db_query"], &["query"])];
    let d = decide(&rules, &[], &req("db_query", "APP_DB", "delete"));
    assert!(d.reason().is_some());
    // The later permissive rule is unreachable: first match already decided.
    let rules = vec![
        rule(Effect::Allow, &["db_query"], &["query"]),
        rule(Effect::Allow, &["db_query"], &["*"]),
    ];
    assert!(decide(&rules, &[], &req("db_query", "APP_DB", "delete"))
        .reason()
        .is_some());
}

#[test]
fn an_empty_action_list_allows_nothing() {
    let rules = vec![rule(Effect::Allow, &["db_query"], &[])];
    assert!(decide(&rules, &[], &req("db_query", "APP_DB", "query"))
        .reason()
        .is_some());
}

#[test]
fn approve_prefix_asks_rather_than_allowing() {
    let rules = vec![rule(Effect::Allow, &["ssh_run"], &["approve:exec"])];
    let d = decide(&rules, &[], &req("ssh_run", "web1", "exec"));
    assert_eq!(d, Decision::NeedsApproval);
}

#[test]
fn a_role_condition_requires_the_caller_to_hold_it() {
    let mut r = rule(Effect::Allow, &["db_query"], &["query"]);
    r.role = vec!["ops".into()];
    let rules = vec![r.clone()];
    assert!(decide(&rules, &[], &req("db_query", "APP_DB", "query"))
        .reason()
        .is_some());
    assert!(decide(&rules, &["ops".into()], &req("db_query", "APP_DB", "query")).allowed());
    assert!(
        decide(&rules, &["dev".into()], &req("db_query", "APP_DB", "query"))
            .reason()
            .is_some()
    );
}

#[test]
fn validation_rejects_typos_and_dangling_roles() {
    let roles = vec!["ops".to_string()];
    let mut bad = rule(Effect::Allow, &["db_query"], &["read"]);
    assert!(bad
        .validate(1, &roles)
        .unwrap_err()
        .contains("unknown action"));
    bad = rule(Effect::Allow, &["db_query"], &["approve:"]);
    assert!(bad
        .validate(1, &roles)
        .unwrap_err()
        .contains("names no action"));
    bad = rule(Effect::Allow, &["db_query"], &["query"]);
    bad.role = vec!["nope".into()];
    assert!(bad
        .validate(1, &roles)
        .unwrap_err()
        .contains("unknown role"));
    let good = rule(
        Effect::Allow,
        &["db_query"],
        &["query", "approve:write", "*"],
    );
    assert!(good.validate(1, &roles).is_ok());
}

#[test]
fn resource_globs_narrow_the_granted_credential() {
    let mut r = rule(Effect::Allow, &["db_query"], &["query"]);
    r.resources = vec!["APP_*".into()];
    let rules = vec![r];
    assert!(decide(&rules, &[], &req("db_query", "APP_DB", "query")).allowed());
    assert!(decide(&rules, &[], &req("db_query", "PAYROLL", "query"))
        .reason()
        .is_some());
}

#[test]
fn deny_reasons_never_echo_the_requested_values() {
    let mut r = rule(Effect::Allow, &["db_query"], &["query"]);
    r.resources = vec!["APP_*".into()];
    let d = decide(&[r], &[], &req("db_query", "PAYROLL_SECRET", "query"));
    let why = d.reason().unwrap();
    assert!(!why.contains("PAYROLL"));
    assert!(!why.contains("db_query"));
}
