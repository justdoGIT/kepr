//! `[[tool_rule]]` in `policy.toml` (F1/F8): who may call which tool,
//! on which resource, in which tenant / workspace / connector account.
//!
//! Tool rules reuse `authz`'s scope decision and the policy file's
//! first-match semantics: the first rule whose conditions all match
//! decides, and a policy file with tool rules but no matching rule denies.
//! A file with no tool rules at all leaves tool calls to the grant the
//! operator passed on the command line, which is what every existing setup
//! does (`PolicyFile::decide_tool`).
//!
//! Conditions are glob lists; an empty list matches any value, except
//! `actions`, where an empty list means "no action is allowed" - the same
//! rule `authz::Scopes` applies. A rule that names a `role` matches only a
//! caller in one of them, so a rule with roles never applies to a caller
//! whose roles could not be resolved.
//!
//! ```toml
//! [[tool_rule]]
//! effect = "allow"
//! tools = ["db_query"]
//! actions = ["query"]
//! resources = ["app_*"]
//! tenants = ["acme"]
//! workspaces = ["/home/kk/projects/acme"]
//! connector_accounts = ["prod"]
//! role = ["ops"]
//! ```

use serde::Deserialize;

use crate::authz::{decide_scoped, Decision, GrantRequest, Scopes};
use crate::policy::Effect;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    pub effect: Effect,
    /// Tool names (`db_query`, `ssh_run`, …). Empty = any.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Actions from `authz::ACTIONS`, `*`, or `approve:NAME`. Empty = none.
    #[serde(default)]
    pub actions: Vec<String>,
    /// Resource globs (credential names, hosts, paths). Empty = any.
    #[serde(default)]
    pub resources: Vec<String>,
    /// Tenant globs. Empty = any.
    #[serde(default)]
    pub tenants: Vec<String>,
    /// Workspace globs. Empty = any.
    #[serde(default)]
    pub workspaces: Vec<String>,
    /// Connector-account globs. Empty = any.
    #[serde(default)]
    pub connector_accounts: Vec<String>,
    /// Roles the caller must hold one of. Empty = any caller.
    #[serde(default)]
    pub role: Vec<String>,
}

impl ToolRule {
    fn conditions(&self) -> Scopes<'_> {
        Scopes {
            tenant: &self.tenants,
            workspace: &self.workspaces,
            tool: &self.tools,
            connector_account: &self.connector_accounts,
            resource: &self.resources,
            action: &self.actions,
        }
    }

    /// Checked when the file is loaded: a rule that can never mean what it
    /// says is an error, not a silent no-op.
    pub fn validate(&self, n: usize, roles: &[String]) -> Result<(), String> {
        if let Some(a) = self.actions.iter().find(|a| {
            a.as_str() != "*"
                && !a.starts_with("approve:")
                && !crate::authz::ACTIONS.contains(&a.as_str())
        }) {
            return Err(format!(
                "tool_rule {n}: unknown action `{a}` (one of {}, *, or approve:NAME)",
                crate::authz::ACTIONS.join(", ")
            ));
        }
        if self
            .actions
            .iter()
            .any(|a| a.strip_prefix("approve:").is_some_and(str::is_empty))
        {
            return Err(format!("tool_rule {n}: `approve:` names no action"));
        }
        if self.role.iter().any(|r| !roles.contains(r)) {
            let unknown = self
                .role
                .iter()
                .find(|r| !roles.contains(r))
                .expect("one is unknown");
            return Err(format!("tool_rule {n}: unknown role `{unknown}`"));
        }
        Ok(())
    }

    /// Every declared condition holds and the caller holds a named role.
    /// Scope checks come first so a rule that fails one never matches, but
    /// the action is reported last: a rule whose scope matches and whose
    /// action does not is still the first match, and denies.
    fn matches(&self, roles: &[String], req: &GrantRequest) -> bool {
        if !self.role.is_empty() && !self.role.iter().any(|r| roles.contains(r)) {
            return false;
        }
        let scopes = self.conditions();
        for (patterns, value) in [
            (scopes.tenant, req.tenant.as_str()),
            (scopes.workspace, req.workspace.as_str()),
            (scopes.tool, req.tool.as_str()),
            (scopes.connector_account, req.connector_account.as_str()),
        ] {
            if !scope_hit(patterns, value) {
                return false;
            }
        }
        scope_hit(scopes.resource, req.resource.as_str())
    }
}

/// An empty pattern list matches any value.
fn scope_hit(patterns: &[String], value: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| crate::policy_glob::glob(p, value))
}

/// First matching rule decides; none matching denies, naming the rule count
/// so the operator can tell "no rules" from "no rule matched".
pub fn decide(rules: &[ToolRule], roles: &[String], req: &GrantRequest) -> Decision {
    for rule in rules.iter().filter(|r| r.matches(roles, req)) {
        let verdict = decide_scoped(&rule.conditions(), req);
        return match rule.effect {
            Effect::Deny => Decision::Deny("denied by tool rule".into()),
            Effect::Allow => verdict,
        };
    }
    Decision::Deny(format!(
        "no tool rule allows this call ({} rules)",
        rules.len()
    ))
}

#[cfg(test)]
#[path = "policy_tools_tests.rs"]
mod tests;
