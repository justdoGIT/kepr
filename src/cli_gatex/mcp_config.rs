//! Operator-owned MCP grants and finite request budgets.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use kepr_core::authz::{self, Actor, Decision, Grant, GrantRequest};
use kepr_core::gate_protocol::GateLimits;

const MAX_NOTE: usize = 4096;
const MAX_SCOPE: usize = 4096;
const MAX_GRANTS: usize = 256;
const DEFAULT_LIMITS: GateLimits = GateLimits {
    max_requests: Some(500),
    max_tokens: None,
    per_minute: Some(60),
    max_requests_day: None,
    max_tokens_day: None,
};
pub const USAGE: &str = "usage: kepr mcp [--credential NAME]... [--read-only] \
    [--allow-writes] [--allow-admin] [--tenant NAME] [--workspace PATH] \
    [--connector-account NAME] [--ssh HOST]... [--ssh-key NAME]... \
    [--context TARGET=NOTE]... [--max-requests N] [--per-minute N] [--max-tokens N]";

#[derive(Debug, PartialEq)]
pub struct McpConfig {
    pub read_only: bool,
    pub allow_writes: bool,
    pub allow_admin: bool,
    pub tenant: String,
    pub workspace: String,
    pub connector_account: String,
    pub credentials: Vec<String>,
    pub ssh_hosts: Vec<String>,
    pub ssh_keys: Vec<String>,
    pub context: Vec<(String, String)>,
    pub limits: GateLimits,
}

pub static NO_CONFIG: McpConfig = McpConfig {
    read_only: true,
    allow_writes: false,
    allow_admin: false,
    tenant: String::new(),
    workspace: String::new(),
    connector_account: String::new(),
    credentials: Vec::new(),
    ssh_hosts: Vec::new(),
    ssh_keys: Vec::new(),
    context: Vec::new(),
    limits: DEFAULT_LIMITS,
};

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            read_only: true,
            allow_writes: false,
            allow_admin: false,
            tenant: String::new(),
            workspace: String::new(),
            connector_account: String::new(),
            credentials: Vec::new(),
            ssh_hosts: Vec::new(),
            ssh_keys: Vec::new(),
            context: Vec::new(),
            limits: DEFAULT_LIMITS,
        }
    }
}

fn name(value: &str) -> Result<String, String> {
    if !(1..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return Err("credential and SSH key grants require a kepr NAME".into());
    }
    Ok(value.to_ascii_uppercase())
}
fn scope(value: &str, what: &str) -> Result<String, String> {
    if !(1..=MAX_SCOPE).contains(&value.len()) || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(format!(
            "--{what} requires a non-empty value without control characters"
        ));
    }
    Ok(value.to_string())
}

impl McpConfig {
    pub fn parse(raw: &[String]) -> Result<Self, String> {
        let mut c = Self::default();
        let (mut read_only, mut writes, mut admins) = (false, false, false);
        let mut it = raw.iter();
        while let Some(arg) = it.next() {
            let mut value = || {
                it.next()
                    .ok_or_else(|| format!("{arg} needs a value\n{USAGE}"))
            };
            match arg.as_str() {
                "--read-only" => read_only = true,
                "--allow-writes" => writes = true,
                "--allow-admin" => admins = true,
                "--tenant" => c.tenant = scope(value()?, "tenant")?,
                "--workspace" => c.workspace = scope(value()?, "workspace")?,
                "--connector-account" => {
                    c.connector_account = scope(value()?, "connector-account")?
                }
                "--credential" | "--ssh-key" => {
                    let grant = name(value()?)?;
                    let grants = if arg == "--credential" {
                        &mut c.credentials
                    } else {
                        &mut c.ssh_keys
                    };
                    if !grants.contains(&grant) {
                        grants.push(grant);
                    }
                }
                "--ssh" => {
                    let host = value()?;
                    if !super::super::mcp_ssh::valid_host(host) {
                        return Err("--ssh requires a valid [USER@]HOST".into());
                    }
                    c.ssh_hosts.push(host.clone());
                }
                "--context" => {
                    let (target, note) = value()?
                        .split_once('=')
                        .filter(|(t, n)| !t.is_empty() && n.len() <= MAX_NOTE)
                        .ok_or("--context requires TARGET=NOTE, at most 4096 bytes")?;
                    c.context.push((target.into(), note.into()));
                }
                "--max-requests" => {
                    c.limits.max_requests =
                        Some(value()?.parse().map_err(|_| "invalid request limit")?);
                }
                "--max-tokens" => {
                    c.limits.max_tokens =
                        Some(value()?.parse().map_err(|_| "invalid token limit")?);
                }
                "--per-minute" => {
                    c.limits.per_minute =
                        Some(value()?.parse().map_err(|_| "invalid per-minute limit")?);
                }
                "--json" => {}
                _ => return Err(format!("unexpected argument\n{USAGE}")),
            }
        }
        if read_only && (writes || admins) {
            return Err("--read-only conflicts with --allow-writes/--allow-admin".into());
        }
        if [
            c.credentials.len(),
            c.ssh_keys.len(),
            c.ssh_hosts.len(),
            c.context.len(),
        ]
        .iter()
        .any(|n| *n > MAX_GRANTS)
        {
            return Err("too many MCP grants".into());
        }
        c.allow_writes = writes;
        c.allow_admin = admins;
        c.read_only = !(writes || admins);
        c.limits.validate()?;
        Ok(c)
    }

    pub fn permits_credential(&self, target: &str) -> bool {
        self.credentials
            .iter()
            .any(|n| n.eq_ignore_ascii_case(target))
    }
    /// Build the operator-owned grant for one MCP tool.
    pub fn grant_for(&self, tool: &str) -> Grant {
        let resource = match tool {
            "db_query" => self.credentials.clone(),
            "ssh_run" => self.ssh_hosts.clone(),
            _ => Vec::new(),
        };
        let action = match tool {
            "db_query" => {
                let mut actions = vec!["query".into()];
                if self.allow_writes || (!self.read_only && !self.allow_admin) {
                    actions.push("write".into());
                }
                if self.allow_admin {
                    actions.push("admin".into());
                }
                actions
            }
            "ssh_run" => vec!["exec".into()],
            _ => Vec::new(),
        };
        Grant {
            actor: Actor::default(),
            tenant: self.tenant.clone(),
            workspace: self.workspace.clone(),
            tool: tool.to_string(),
            connector_account: self.connector_account.clone(),
            resource,
            action,
        }
    }

    pub fn request_for(&self, tool: &str, resource: &str, action: &str) -> GrantRequest {
        GrantRequest {
            tenant: self.tenant.clone(),
            workspace: self.workspace.clone(),
            tool: tool.to_string(),
            connector_account: self.connector_account.clone(),
            resource: resource.to_string(),
            action: action.to_string(),
        }
    }

    pub fn authorize(&self, tool: &str, resource: &str, action: &str) -> Result<(), String> {
        match authz::decide(
            &self.grant_for(tool),
            &self.request_for(tool, resource, action),
        ) {
            Decision::Allow => Ok(()),
            Decision::NeedsApproval => Err("MCP authorization requires operator approval".into()),
            Decision::Deny(reason) => Err(format!("MCP authorization denied: {reason}")),
        }
    }

    pub fn authorize_db(
        &self,
        resource: &str,
        action: &str,
        read_only: bool,
    ) -> Result<(), String> {
        if read_only && action != "query" {
            return Err("read-only MCP calls may run query statements only".into());
        }
        self.authorize("db_query", resource, action)
    }

    pub fn context_for(&self, target: &str) -> Option<&str> {
        self.context
            .iter()
            .rev()
            .find(|(t, _)| t.eq_ignore_ascii_case(target))
            .map(|(_, note)| note.as_str())
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new(&NO_CONFIG)
    }
}

pub struct Budget {
    remaining: u64,
    per_minute: u32,
    recent: VecDeque<Instant>,
}

impl Budget {
    pub fn new(cfg: &McpConfig) -> Self {
        Self {
            remaining: cfg.limits.max_requests.unwrap_or(500),
            per_minute: cfg.limits.per_minute.unwrap_or(60),
            recent: VecDeque::new(),
        }
    }

    pub fn charge(&mut self, now: Instant) -> Result<(), String> {
        while self
            .recent
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= Duration::from_secs(60))
        {
            self.recent.pop_front();
        }
        if self.remaining == 0 {
            return Err(
                "MCP session request budget exhausted; operator must start a new session".into(),
            );
        }
        if self.recent.len() >= self.per_minute as usize {
            return Err("MCP session per-minute budget exhausted".into());
        }
        self.remaining -= 1;
        self.recent.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_are_explicit_and_limits_stay_positive() {
        let parse =
            |s: &[&str]| McpConfig::parse(&s.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let default = parse(&[]).unwrap();
        assert!(default.credentials.is_empty() && default.ssh_keys.is_empty());
        assert_eq!(default.limits.max_requests, Some(500));
        assert_eq!(default.limits.per_minute, Some(60));
        assert_eq!(default.limits.max_tokens, None);
        let cfg = parse(&[
            "--credential",
            "app_db",
            "--ssh-key",
            "deploy",
            "--allow-writes",
        ])
        .unwrap();
        assert!(cfg.permits_credential("APP_DB"));
        assert!(!cfg.permits_credential("OTHER"));
        assert_eq!(cfg.ssh_keys, ["DEPLOY"]);
        assert!(!cfg.read_only);
        for flags in [
            &["--max-requests", "0"][..],
            &["--per-minute", "0"],
            &["--max-tokens", "0"],
            &["--credential", "../x"],
            &["--allow-writes", "--read-only"],
            &["--read-only", "--allow-writes"],
            &["--allow-admin", "--read-only"],
        ] {
            assert!(parse(flags).is_err());
        }
    }
    #[test]
    fn grant_scopes_and_actions_are_operator_bound() {
        let parse =
            |s: &[&str]| McpConfig::parse(&s.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let cfg = parse(&[
            "--credential",
            "APP_DB",
            "--ssh",
            "web1",
            "--allow-writes",
            "--allow-admin",
            "--tenant",
            "acme",
            "--workspace",
            "/work/acme",
            "--connector-account",
            "work",
        ])
        .unwrap();
        let grant = cfg.grant_for("db_query");
        let req = cfg.request_for("db_query", "APP_DB", "query");
        assert!(authz::decide(&grant, &req).allowed());
        let mut personal = req.clone();
        personal.connector_account = "personal".into();
        assert!(!authz::decide(&grant, &personal).allowed());
        let mut other_workspace = req;
        other_workspace.workspace = "/work/other".into();
        assert!(!authz::decide(&grant, &other_workspace).allowed());

        let ro = parse(&["--credential", "APP_DB"]).unwrap();
        assert!(ro.authorize_db("APP_DB", "write", false).is_err());
        assert!(parse(&["--allow-admin"])
            .unwrap()
            .authorize_db("APP_DB", "admin", false)
            .is_err());
    }

    #[test]
    fn local_budget_covers_all_operations_and_never_resets_total() {
        let cfg = McpConfig {
            limits: GateLimits {
                max_requests: Some(2),
                per_minute: Some(1),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut b = Budget::new(&cfg);
        let now = Instant::now();
        assert!(b.charge(now).is_ok());
        assert!(b.charge(now).unwrap_err().contains("per-minute"));
        assert!(b.charge(now + Duration::from_secs(60)).is_ok());
        assert!(b
            .charge(now + Duration::from_secs(120))
            .unwrap_err()
            .contains("request budget"));
    }
}
