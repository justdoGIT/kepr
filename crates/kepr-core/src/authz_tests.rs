// authz_tests.rs — F1: the composite grant decision.
use super::*;

fn grant() -> Grant {
    Grant {
        actor: Actor::default(),
        tenant: "acme".into(),
        workspace: "/home/kk/projects/acme".into(),
        tool: "db_query".into(),
        connector_account: "prod".into(),
        resource: vec!["app_db".into()],
        action: vec!["query".into()],
    }
}

fn req() -> GrantRequest {
    GrantRequest {
        tenant: "acme".into(),
        workspace: "/home/kk/projects/acme".into(),
        tool: "db_query".into(),
        connector_account: "prod".into(),
        resource: "app_db".into(),
        action: "query".into(),
    }
}

#[test]
fn matching_tuple_is_allowed() {
    assert_eq!(decide(&grant(), &req()), Decision::Allow);
}

#[test]
fn workspace_mismatch_is_denied() {
    let mut r = req();
    r.workspace = "/home/kk/projects/other".into();
    assert_eq!(
        decide(&grant(), &r),
        Decision::Deny("workspace outside the grant".into())
    );
}

#[test]
fn tenant_mismatch_is_denied() {
    let mut r = req();
    r.tenant = "personal".into();
    assert_eq!(
        decide(&grant(), &r),
        Decision::Deny("tenant outside the grant".into())
    );
}

#[test]
fn tool_and_connector_account_are_part_of_the_tuple() {
    let mut r = req();
    r.tool = "ssh_run".into();
    assert_eq!(
        decide(&grant(), &r),
        Decision::Deny("tool outside the grant".into())
    );
    let g = grant();
    let mut r = req();
    r.connector_account = "personal".into();
    assert_eq!(
        decide(&g, &r),
        Decision::Deny("connector_account outside the grant".into())
    );
}

#[test]
fn a_star_scope_matches_any_value_but_not_an_unset_field() {
    let mut g = grant();
    g.tenant = "*".into();
    let mut r = req();
    r.tenant = "personal".into();
    assert_eq!(decide(&g, &r), Decision::Allow);
    // A grant field that is empty still matches only an empty request field.
    let mut g = grant();
    g.workspace = String::new();
    assert_eq!(
        decide(&g, &req()),
        Decision::Deny("workspace outside the grant".into())
    );
}

#[test]
fn resource_glob_hit_allows_and_a_miss_denies() {
    let mut g = grant();
    g.resource = vec!["app_*".into()];
    assert_eq!(decide(&g, &req()), Decision::Allow);
    let mut r = req();
    r.resource = "billing_db".into();
    assert_eq!(
        decide(&g, &r),
        Decision::Deny("resource outside the grant".into())
    );
}

#[test]
fn empty_resource_denies() {
    let mut g = grant();
    g.resource.clear();
    assert_eq!(
        decide(&g, &req()),
        Decision::Deny("the grant names no resource".into())
    );
}

#[test]
fn unlisted_action_denies_and_star_allows() {
    let g = grant();
    let mut r = req();
    r.action = "write".into();
    assert_eq!(
        decide(&g, &r),
        Decision::Deny("action outside the grant".into())
    );
    let mut g = grant();
    g.action = vec!["*".into()];
    assert_eq!(decide(&g, &r), Decision::Allow);
}

#[test]
fn approve_prefix_needs_approval_and_does_not_allow() {
    let mut g = grant();
    g.action = vec!["approve:delete".into()];
    let mut r = req();
    r.action = "delete".into();
    assert_eq!(decide(&g, &r), Decision::NeedsApproval);
    assert!(!decide(&g, &r).allowed());
}

#[test]
fn deny_reasons_never_echo_requested_values() {
    let g = grant();
    let mut r = req();
    r.resource = "SECRET_RESOURCE".into();
    r.workspace = "/secret/place".into();
    let d = decide(&g, &r);
    let reason = d.reason().unwrap();
    assert!(!reason.contains("SECRET_RESOURCE"), "{reason}");
    assert_eq!(reason, "workspace outside the grant");
}

fn scoped<'a>(tenant: &'a [String], resource: &'a [String], action: &'a [String]) -> Scopes<'a> {
    Scopes {
        tenant,
        resource,
        action,
        ..Default::default()
    }
}

#[test]
fn empty_scope_lists_match_any_value() {
    let resources = ["app_*".to_string()];
    let actions = ["query".to_string(), "exec".to_string()];
    let s = scoped(&[], &resources, &actions);
    let mut r = req();
    r.workspace = String::new();
    r.tenant = "anything".into();
    r.tool = "ssh_run".into();
    assert_eq!(decide_scoped(&s, &r), Decision::Allow);
}

#[test]
fn scope_glob_lists_narrow_and_empty_actions_allow_nothing() {
    let tenants = ["acme".to_string(), "acme-lab".to_string()];
    let resources = ["app_*".to_string()];
    let s = scoped(&tenants, &resources, &[]);
    let mut r = req();
    r.tenant = "acme-lab".into();
    assert_eq!(
        decide_scoped(&s, &r),
        Decision::Deny("action outside the grant".into())
    );
    let actions = ["*".to_string()];
    let s = scoped(&tenants, &resources, &actions);
    assert_eq!(decide_scoped(&s, &r), Decision::Allow);
    r.tenant = "globex".into();
    assert_eq!(
        decide_scoped(&s, &r),
        Decision::Deny("tenant outside the grant".into())
    );
}

#[test]
fn a_resource_list_that_names_no_glob_still_denies_a_miss() {
    let resources = ["app_db".to_string()];
    let actions = ["query".to_string()];
    let s = scoped(&[], &resources, &actions);
    let mut r = req();
    r.resource = "app_dbx".into();
    assert_eq!(
        decide_scoped(&s, &r),
        Decision::Deny("resource outside the grant".into())
    );
}
