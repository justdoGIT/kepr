//! T6.11: the access policy (`policy.toml`): parser types and a pure,
//! first-match evaluator shared by the daemon (which enforces it) and
//! `kepr policy test` (which runs the file's `[[test]]` cases).
//!
//! Deny by default: once a policy file exists, an operation it governs
//! (`get`, `exec`, `export`, `share`, `set`, `seal`) is allowed only if
//! the first rule that matches it says `allow` and the rule's limits
//! (`max_ttl`, `hosts`) hold. No file means no policy (allow, as before).
//!
//! ```toml
//! [[rule]]
//! effect = "allow"
//! ops = ["get", "exec"]
//! names = ["GITHUB_*"]
//! parent = ["/usr/bin/git"]     # the program that ran the kepr client
//!
//! [[rule]]
//! effect = "allow"
//! ops = ["seal"]
//! names = ["OPENAI_*"]
//! hosts = ["api.openai.com"]    # every binding must be one of these
//! max_ttl = 2592000             # seconds; a key without a TTL is refused
//!
//! [[test]]
//! op = "get"
//! name = "GITHUB_TOKEN"
//! parent = "/usr/bin/git"
//! expect = "allow"
//! ```
//!
//! Roles (T13.13) name sets of callers; a rule with `role` applies only
//! to a caller in one of them (no role, no match):
//!
//! ```toml
//! [roles.ops]
//! members = ["group:ops", "user:alice", "uid:1007", "gid:2000"]
//!
//! [[rule]]
//! effect = "allow"
//! ops = ["get"]
//! names = ["PROD_*"]
//! role = ["ops"]
//! ```
//!
//! The caller provides the TOML parser (`toml::from_str::<PolicyFile>`);
//! this crate stays free of it. Unknown keys are errors, so a typo in a
//! condition can't silently widen a rule.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::policy_glob::any_glob;
pub use crate::policy_glob::glob;
pub use crate::policy_roles::{Identity, Role};

/// Operations a policy governs; anything else is not policed.
pub const OPS: &[&str] = &["get", "exec", "export", "share", "set", "seal"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    #[serde(default)]
    pub roles: BTreeMap<String, Role>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    /// `[[tool_rule]]`: which tool calls a session may make (F1/F8).
    #[serde(default, rename = "tool_rule")]
    pub tool_rules: Vec<crate::policy_tools::ToolRule>,
    #[serde(default, rename = "test")]
    pub tests: Vec<TestCase>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub effect: Effect,
    /// Ops this rule covers (`*` = all governed ops).
    pub ops: Vec<String>,
    /// Credential-name globs (`*`, `?`; case-insensitive). Empty = any.
    #[serde(default)]
    pub names: Vec<String>,
    /// Globs over the calling program's path (`/proc/PID/exe`). Empty = any.
    #[serde(default)]
    pub exe: Vec<String>,
    /// Globs over the path of the caller's parent process. Empty = any.
    #[serde(default)]
    pub parent: Vec<String>,
    /// `true`: only inside `kepr agent run`; `false`: only outside it.
    #[serde(default)]
    pub agent: Option<bool>,
    /// Globs over the agent harness name (implies `agent = true`).
    #[serde(default)]
    pub harness: Vec<String>,
    /// The caller must hold one of these roles (T13.13). Empty = any.
    #[serde(default)]
    pub role: Vec<String>,
    /// `seal`: every bound host must match one of these globs.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// `set` / `seal`: the TTL (seconds) must be present and at most this.
    #[serde(default)]
    pub max_ttl: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCase {
    pub op: String,
    pub name: String,
    #[serde(default)]
    pub exe: Option<String>,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub harness: Option<String>,
    /// Roles the simulated caller holds (T13.13).
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub ttl: Option<u64>,
    pub expect: Effect,
}

/// Who asks for what. `None` for a process field = it could not be read
/// (a rule that names it then doesn't match).
#[derive(Debug, Default, Clone)]
pub struct Ctx<'a> {
    pub op: &'a str,
    pub name: &'a str,
    pub exe: Option<&'a str>,
    pub parent: Option<&'a str>,
    /// `Some(harness)` when the caller runs inside an agent session.
    pub harness: Option<&'a str>,
    /// The roles the caller holds (`PolicyFile::roles_of`).
    pub roles: &'a [String],
    pub hosts: &'a [String],
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Allowed by rule N (1-based).
    Allow(usize),
    /// Denied by rule N, or by default (`None`), with the reason.
    Deny(Option<usize>, String),
}

impl Decision {
    pub fn allowed(&self) -> bool {
        matches!(self, Decision::Allow(_))
    }
}

impl Rule {
    fn covers(&self, op: &str) -> bool {
        self.ops.iter().any(|o| o == "*" || o == op)
    }

    /// Does this rule apply to `ctx` (ignoring its `hosts` / `max_ttl` limits)?
    fn matches(&self, ctx: &Ctx) -> bool {
        let agent_ok = !matches!(
            (self.agent, ctx.harness),
            (Some(true), None) | (Some(false), Some(_))
        );
        self.covers(ctx.op)
            && any_glob(&self.names, Some(ctx.name), true)
            && any_glob(&self.exe, ctx.exe, false)
            && any_glob(&self.parent, ctx.parent, false)
            && agent_ok
            && any_glob(&self.harness, ctx.harness, false)
            && (self.role.is_empty() || self.role.iter().any(|r| ctx.roles.contains(r)))
    }

    /// An allow rule's limits; `Err` names the one that failed.
    fn limits(&self, ctx: &Ctx) -> Result<(), String> {
        if let Some(max) = self.max_ttl.filter(|_| matches!(ctx.op, "set" | "seal")) {
            match ctx.ttl {
                None => return Err(format!("needs a TTL of at most {max}s")),
                Some(t) if t > max => return Err(format!("TTL {t}s is over {max}s")),
                Some(_) => {}
            }
        }
        if ctx.op == "seal" && !self.hosts.is_empty() {
            if let Some(h) = ctx
                .hosts
                .iter()
                .find(|h| !self.hosts.iter().any(|g| glob(g, &h.to_ascii_lowercase())))
            {
                return Err(format!("host {h} is not allowed"));
            }
        }
        Ok(())
    }

    fn validate(&self, n: usize) -> Result<(), String> {
        if self.ops.is_empty() {
            return Err(format!("rule {n}: `ops` is empty"));
        }
        match self
            .ops
            .iter()
            .find(|o| *o != "*" && !OPS.contains(&o.as_str()))
        {
            Some(o) => Err(format!(
                "rule {n}: unknown op `{o}` (one of {}, or *)",
                OPS.join(", ")
            )),
            None => Ok(()),
        }
    }
}

impl PolicyFile {
    /// Reject rules that would never mean what they say.
    pub fn validate(&self) -> Result<(), String> {
        for (name, role) in &self.roles {
            role.validate(name)?;
        }
        for (i, r) in self.rules.iter().enumerate() {
            r.validate(i + 1)?;
            if let Some(unknown) = r.role.iter().find(|n| !self.roles.contains_key(*n)) {
                return Err(format!("rule {}: unknown role `{unknown}`", i + 1));
            }
        }
        let declared: Vec<String> = self.roles.keys().cloned().collect();
        for (i, r) in self.tool_rules.iter().enumerate() {
            r.validate(i + 1, &declared)?;
        }
        for (i, t) in self.tests.iter().enumerate() {
            if !OPS.contains(&t.op.as_str()) {
                return Err(format!("test {}: unknown op `{}`", i + 1, t.op));
            }
        }
        Ok(())
    }

    /// The roles `id` holds.
    pub fn roles_of(&self, id: &Identity) -> Vec<String> {
        self.roles
            .iter()
            .filter(|(_, r)| r.has(id))
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// First matching rule decides; none matching = deny.
    pub fn check(&self, ctx: &Ctx) -> Decision {
        for (i, rule) in self.rules.iter().enumerate() {
            if !rule.matches(ctx) {
                continue;
            }
            return match rule.effect {
                Effect::Deny => Decision::Deny(Some(i + 1), format!("denied by rule {}", i + 1)),
                Effect::Allow => match rule.limits(ctx) {
                    Ok(()) => Decision::Allow(i + 1),
                    Err(why) => Decision::Deny(Some(i + 1), format!("rule {}: {why}", i + 1)),
                },
            };
        }
        Decision::Deny(None, format!("no rule allows {} of {}", ctx.op, ctx.name))
    }

    /// What a session may do with `req` (F1/F8). A file with no
    /// `[[tool_rule]]` leaves the decision to the operator's command-line
    /// grant, so existing setups keep working; once the file has rules,
    /// only they decide.
    pub fn decide_tool(
        &self,
        roles: &[String],
        req: &crate::authz::GrantRequest,
    ) -> Option<crate::authz::Decision> {
        match self.tool_rules.is_empty() {
            true => None,
            false => Some(crate::policy_tools::decide(&self.tool_rules, roles, req)),
        }
    }

    /// Allow rules that can apply to `op` on `name` for some caller, with
    /// their conditions, until one applies to every caller (T6.12).
    pub fn paths(&self, op: &str, name: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (i, r) in self.rules.iter().enumerate() {
            if !r.covers(op) || !any_glob(&r.names, Some(name), true) {
                continue;
            }
            let mut cond = Vec::new();
            for (k, v) in [
                ("exe", &r.exe),
                ("parent", &r.parent),
                ("harness", &r.harness),
                ("role", &r.role),
            ] {
                if !v.is_empty() {
                    cond.push(format!("{k}={}", v.join("|")));
                }
            }
            if let Some(a) = r.agent {
                cond.push(format!("agent={a}"));
            }
            if r.effect == Effect::Allow {
                let who = if cond.is_empty() {
                    "anyone".to_string()
                } else {
                    cond.join(" ")
                };
                out.push(format!("{op} allowed by rule {} ({who})", i + 1));
            }
            if cond.is_empty() {
                break; // later rules are unreachable for this op and name
            }
        }
        out
    }
}

#[path = "policy_tests_runner.rs"]
mod test_runner;
#[cfg(test)]
mod tests {
    use super::*;

    fn rule(effect: Effect, ops: &[&str], names: &[&str]) -> Rule {
        Rule {
            effect,
            ops: ops.iter().map(|s| s.to_string()).collect(),
            names: names.iter().map(|s| s.to_string()).collect(),
            exe: vec![],
            parent: vec![],
            agent: None,
            harness: vec![],
            role: vec![],
            hosts: vec![],
            max_ttl: None,
        }
    }

    fn ctx<'a>(op: &'a str, name: &'a str) -> Ctx<'a> {
        Ctx {
            op,
            name,
            ..Default::default()
        }
    }

    #[test]
    fn globs() {
        assert!(glob("GITHUB_*", "GITHUB_TOKEN"));
        assert!(glob("*", ""));
        assert!(glob("/usr/*/git", "/usr/local/bin/git"));
        assert!(glob("A?C", "ABC"));
        assert!(!glob("A?C", "AC"));
        assert!(!glob("GITHUB_*", "GITLAB_TOKEN"));
        assert!(glob("*_KEY*", "OPENAI_KEY_2"));
        assert!(!glob("api.*.com", "api.x.ai"));
        assert!(any_glob(
            &["github_?oken".into()],
            Some("GITHUB_TOKEN"),
            true
        ));
    }

    #[test]
    fn deny_by_default_and_first_match() {
        let empty = PolicyFile::default();
        assert!(!empty.check(&ctx("get", "A")).allowed());
        let p = PolicyFile {
            rules: vec![
                rule(Effect::Deny, &["get"], &["PROD_*"]),
                rule(Effect::Allow, &["*"], &["*"]),
            ],
            tests: vec![],
            ..Default::default()
        };
        assert_eq!(
            p.check(&ctx("get", "PROD_DB")),
            Decision::Deny(Some(1), "denied by rule 1".into())
        );
        assert_eq!(p.check(&ctx("exec", "PROD_DB")), Decision::Allow(2));
        assert_eq!(p.check(&ctx("get", "DEV_DB")), Decision::Allow(2));
    }

    #[test]
    fn caller_conditions() {
        let mut r = rule(Effect::Allow, &["get"], &["gh_*"]);
        r.parent = vec!["/usr/bin/git".into()];
        let p = PolicyFile {
            rules: vec![r],
            tests: vec![],
            ..Default::default()
        };
        let mut c = ctx("get", "GH_TOKEN");
        assert!(!p.check(&c).allowed(), "unknown parent never matches");
        c.parent = Some("/usr/bin/git");
        assert!(p.check(&c).allowed());
        c.parent = Some("/usr/bin/curl");
        assert!(!p.check(&c).allowed());

        let mut agent_only = rule(Effect::Allow, &["get"], &[]);
        agent_only.harness = vec!["claude".into()];
        let mut human = rule(Effect::Allow, &["get"], &[]);
        human.agent = Some(false);
        let p = PolicyFile {
            rules: vec![agent_only, human],
            tests: vec![],
            ..Default::default()
        };
        let mut c = ctx("get", "X");
        assert_eq!(p.check(&c), Decision::Allow(2));
        c.harness = Some("claude");
        assert_eq!(p.check(&c), Decision::Allow(1));
        c.harness = Some("aider");
        assert!(!p.check(&c).allowed());
    }

    #[test]
    fn ttl_and_host_limits() {
        let mut r = rule(Effect::Allow, &["seal", "set"], &["*"]);
        r.max_ttl = Some(3600);
        r.hosts = vec!["api.openai.com".into(), "*.anthropic.com".into()];
        let p = PolicyFile {
            rules: vec![r],
            tests: vec![],
            ..Default::default()
        };
        let hosts = vec!["API.ANTHROPIC.COM".to_string()];
        let mut c = Ctx {
            op: "seal",
            name: "K",
            hosts: &hosts,
            ttl: Some(60),
            ..Default::default()
        };
        assert!(p.check(&c).allowed());
        c.ttl = None;
        assert!(matches!(p.check(&c), Decision::Deny(Some(1), w) if w.contains("needs a TTL")));
        c.ttl = Some(7200);
        assert!(matches!(p.check(&c), Decision::Deny(Some(1), w) if w.contains("over 3600")));
        let bad = vec!["evil.example".to_string()];
        c.ttl = Some(1);
        c.hosts = &bad;
        assert!(matches!(p.check(&c), Decision::Deny(_, w) if w.contains("evil.example")));
    }

    fn identity<'a>(
        uid: u32,
        user: &'a str,
        gids: &'a [u32],
        groups: &'a [String],
    ) -> Identity<'a> {
        Identity {
            uid,
            user,
            gids,
            groups,
        }
    }

    fn role_policy() -> PolicyFile {
        let mut r = rule(Effect::Allow, &["get"], &["PROD_*"]);
        r.role = vec!["ops".into()];
        let mut p = PolicyFile {
            rules: vec![r],
            ..Default::default()
        };
        p.roles.insert(
            "ops".into(),
            Role {
                members: vec!["group:ops".into(), "user:alice".into(), "uid:1007".into()],
            },
        );
        p.roles.insert(
            "dev".into(),
            Role {
                members: vec!["gid:2000".into()],
            },
        );
        p
    }

    #[test]
    fn roles_come_from_uid_user_gid_and_group() {
        let p = role_policy();
        let ops = vec!["ops".to_string()];
        assert_eq!(p.roles_of(&identity(1, "bob", &[], &ops)), ["ops"]);
        assert_eq!(p.roles_of(&identity(1, "alice", &[], &[])), ["ops"]);
        assert_eq!(p.roles_of(&identity(1007, "x", &[], &[])), ["ops"]);
        assert_eq!(p.roles_of(&identity(1, "x", &[2000], &[])), ["dev"]);
        // A user in two roles holds both.
        assert_eq!(
            p.roles_of(&identity(1007, "x", &[2000], &[])),
            ["dev", "ops"]
        );
        assert!(p.roles_of(&identity(1, "bob", &[5], &[])).is_empty());
    }

    #[test]
    fn a_role_rule_needs_the_role() {
        let p = role_policy();
        let mut c = ctx("get", "PROD_DB");
        assert!(!p.check(&c).allowed(), "no role, no match");
        let dev = vec!["dev".to_string()];
        c.roles = &dev;
        assert!(!p.check(&c).allowed(), "another role");
        let both = vec!["dev".to_string(), "ops".to_string()];
        c.roles = &both;
        assert_eq!(p.check(&c), Decision::Allow(1));
    }

    #[test]
    fn roles_are_validated() {
        let mut p = role_policy();
        assert!(p.validate().is_ok());
        p.rules[0].role = vec!["nobody".into()];
        assert!(p.validate().unwrap_err().contains("unknown role `nobody`"));
        let mut p = role_policy();
        p.roles.insert(
            "bad".into(),
            Role {
                members: vec!["alice".into()],
            },
        );
        assert!(p.validate().unwrap_err().contains("role `bad`"));
        p.roles.insert("bad".into(), Role { members: vec![] });
        assert!(p.validate().unwrap_err().contains("empty"));
    }

    #[test]
    fn validation_rejects_unknown_ops() {
        let p = PolicyFile {
            rules: vec![rule(Effect::Allow, &["read"], &[])],
            tests: vec![],
            ..Default::default()
        };
        assert!(p.validate().unwrap_err().contains("unknown op `read`"));
        let p = PolicyFile {
            rules: vec![rule(Effect::Allow, &[], &[])],
            tests: vec![],
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn tests_report_pass_and_fail() {
        let p = PolicyFile {
            rules: vec![rule(Effect::Allow, &["get"], &["A*"])],
            tests: vec![
                TestCase {
                    op: "get".into(),
                    name: "abc".into(),
                    exe: Some("/bin/x".into()),
                    parent: None,
                    harness: None,
                    roles: vec![],
                    hosts: vec![],
                    ttl: None,
                    expect: Effect::Allow,
                },
                TestCase {
                    op: "exec".into(),
                    name: "ABC".into(),
                    exe: None,
                    parent: None,
                    harness: None,
                    roles: vec![],
                    hosts: vec![],
                    ttl: None,
                    expect: Effect::Allow,
                },
            ],
            ..Default::default()
        };
        let (ok, lines) = p.run_tests();
        assert!(!ok);
        assert_eq!(
            lines[0],
            "ok    test 1: get ABC exe=/bin/x -> allow (rule 1)"
        );
        assert!(lines[1].starts_with("FAIL  test 2: exec ABC -> deny (no rule allows exec of ABC)"));
        assert!(lines[1].ends_with("expected allow"));
    }

    #[test]
    fn paths_list_reachable_allow_rules() {
        let mut git = rule(Effect::Allow, &["get"], &["GH_*"]);
        git.parent = vec!["/usr/bin/git".into()];
        let p = PolicyFile {
            rules: vec![
                git,
                rule(Effect::Allow, &["get"], &["*"]),
                rule(Effect::Allow, &["get"], &["GH_X"]),
            ],
            tests: vec![],
            ..Default::default()
        };
        assert_eq!(
            p.paths("get", "GH_X"),
            vec![
                "get allowed by rule 1 (parent=/usr/bin/git)".to_string(),
                "get allowed by rule 2 (anyone)".to_string()
            ]
        );
        assert!(p.paths("share", "GH_X").is_empty());
    }
}
