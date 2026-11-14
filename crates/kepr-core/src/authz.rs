//! Composite authorization (F1): the tuple one tool call is checked
//! against, and the pure decision function over it.
//!
//! A [`Grant`] is what an operator handed a session — which actor, tenant,
//! workspace, tool, connector account, resource globs and actions. A
//! [`GrantRequest`] is what one call asks for. [`decide`] is pure, so the
//! same function runs at the MCP boundary (`kepr mcp`), in the
//! `policy.toml` `[[tool_rule]]` evaluator (`crate::policy_tools`) and in
//! tests.
//!
//! Checks run in this order and the first failure denies:
//!
//! 1. scope — `tenant`, `workspace`, `tool`, `connector_account`.
//! 2. resource — globs (`*`, `?`) over the resource name.
//! 3. action — an exact entry (or `*`) allows, `approve:NAME` allows only
//!    after operator approval, anything else denies.
//!
//! Every field is a glob list in [`Scopes`], where an empty list means any
//! value. [`Grant`] is the single-value convenience form the CLI builds: a
//! grant that names no resource authorizes nothing, and an empty scope
//! field matches only an empty request field, so an unscoped grant cannot
//! silently widen.
//!
//! The actor is carried for the audit trail (see the gate journal's
//! `DecisionRecord`), not consulted here: the caller was already
//! authenticated at the socket.

use crate::policy_glob::glob;

/// Actions a tool call can ask for. A grant or tool rule may also use `*`.
pub const ACTIONS: &[&str] = &["query", "exec", "write", "send", "delete", "admin"];

/// Who the grant was issued to. Owned so it can outlive the peer lookup
/// that produced it; `gids` and `groups` are filled by the daemon, which
/// has the requesting pid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Actor {
    pub uid: u32,
    pub user: String,
    pub gids: Vec<u32>,
    pub groups: Vec<String>,
}

/// What a session may do. Built by the operator-facing layer (CLI flags or
/// `policy.toml`), never by the model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grant {
    pub actor: Actor,
    /// `*` = any tenant.
    pub tenant: String,
    /// `*` = any workspace.
    pub workspace: String,
    /// `*` = any tool.
    pub tool: String,
    /// `*` = any connector account.
    pub connector_account: String,
    /// Globs over the resource name. Empty authorizes nothing.
    pub resource: Vec<String>,
    /// Allowed actions; `*` = any, `approve:NAME` = `NAME` after approval.
    pub action: Vec<String>,
}

/// The glob-list form every policy rule writes. An empty list matches any
/// value, except for `action`, where an empty list allows nothing.
#[derive(Debug, Clone, Default)]
pub struct Scopes<'a> {
    pub tenant: &'a [String],
    pub workspace: &'a [String],
    pub tool: &'a [String],
    pub connector_account: &'a [String],
    pub resource: &'a [String],
    pub action: &'a [String],
}

/// One call's tuple.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantRequest {
    pub tenant: String,
    pub workspace: String,
    pub tool: String,
    pub connector_account: String,
    pub resource: String,
    pub action: String,
}

impl GrantRequest {
    /// A request that names only what a tool call itself knows; the scope
    /// fields stay empty and are filled by the caller that owns them.
    pub fn new(tool: &str, resource: &str, action: &str) -> Self {
        Self {
            tool: tool.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            ..Self::default()
        }
    }
}

/// The outcome. `Deny` carries a reason that names the failing field, never
/// a value from either side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    NeedsApproval,
    Deny(String),
}

impl Decision {
    pub fn allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Decision::Deny(reason) => Some(reason),
            _ => None,
        }
    }
}

/// An empty pattern list matches any value.
fn any(patterns: &[String], value: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| glob(p, value))
}

/// One scope field: an empty list means any value.
fn in_scope(patterns: &[String], value: &str) -> bool {
    any(patterns, value)
}

/// Glob lists in, decision out; the single-value [`Grant`] form delegates
/// here after enforcing its own extra restrictions.
pub fn decide_scoped(scopes: &Scopes, req: &GrantRequest) -> Decision {
    if !in_scope(scopes.tenant, &req.tenant) {
        return Decision::Deny("tenant outside the grant".into());
    }
    if !in_scope(scopes.workspace, &req.workspace) {
        return Decision::Deny("workspace outside the grant".into());
    }
    if !in_scope(scopes.tool, &req.tool) {
        return Decision::Deny("tool outside the grant".into());
    }
    if !in_scope(scopes.connector_account, &req.connector_account) {
        return Decision::Deny("connector_account outside the grant".into());
    }
    if !any(scopes.resource, &req.resource) {
        return Decision::Deny("resource outside the grant".into());
    }
    action_decision(scopes.action, &req.action)
}

/// `*` or an exact entry allows; `approve:NAME` asks; nothing else does.
pub fn action_decision(actions: &[String], action: &str) -> Decision {
    if actions.iter().any(|a| a == "*" || a == action) {
        return Decision::Allow;
    }
    if actions
        .iter()
        .any(|a| a.strip_prefix("approve:") == Some(action))
    {
        return Decision::NeedsApproval;
    }
    Decision::Deny("action outside the grant".into())
}

/// The single-value grant: empty scope fields match only an empty request
/// field, and an empty resource list authorizes nothing.
pub fn decide(grant: &Grant, req: &GrantRequest) -> Decision {
    if grant.resource.is_empty() {
        return Decision::Deny("the grant names no resource".into());
    }
    let single = |s: &String| vec![s.clone()];
    let (tenant, workspace, tool, account) = (
        single(&grant.tenant),
        single(&grant.workspace),
        single(&grant.tool),
        single(&grant.connector_account),
    );
    decide_scoped(
        &Scopes {
            tenant: &tenant,
            workspace: &workspace,
            tool: &tool,
            connector_account: &account,
            resource: &grant.resource,
            action: &grant.action,
        },
        req,
    )
}

#[cfg(test)]
#[path = "authz_tests.rs"]
mod tests;
