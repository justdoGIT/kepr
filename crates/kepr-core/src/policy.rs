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
//! The caller provides the TOML parser (`toml::from_str::<PolicyFile>`);
//! this crate stays free of it. Unknown keys are errors, so a typo in a
//! condition can't silently widen a rule.

use serde::Deserialize;

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
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
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

/// `*` matches any run of characters (including `/`), `?` one character.
pub fn glob(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    let mut back: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            back = Some((pi, ti));
            pi += 1;
        } else if let Some((bp, bt)) = back {
            pi = bp + 1;
            ti = bt + 1;
            back = Some((bp, bt + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

fn any_glob(globs: &[String], value: Option<&str>, fold: bool) -> bool {
    if globs.is_empty() {
        return true;
    }
    let Some(v) = value else { return false };
    let v = if fold {
        v.to_ascii_uppercase()
    } else {
        v.into()
    };
    globs.iter().any(|g| {
        let g = if fold {
            g.to_ascii_uppercase()
        } else {
            g.clone()
        };
        glob(&g, &v)
    })
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
        self.rules
            .iter()
            .enumerate()
            .try_for_each(|(i, r)| r.validate(i + 1))?;
        for (i, t) in self.tests.iter().enumerate() {
            if !OPS.contains(&t.op.as_str()) {
                return Err(format!("test {}: unknown op `{}`", i + 1, t.op));
            }
        }
        Ok(())
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

    /// Run the `[[test]]` cases: `(passed, one line per case)`.
    pub fn run_tests(&self) -> (bool, Vec<String>) {
        let mut all = true;
        let mut lines = Vec::new();
        for (i, t) in self.tests.iter().enumerate() {
            let name = t.name.to_ascii_uppercase();
            let ctx = Ctx {
                op: &t.op,
                name: &name,
                exe: t.exe.as_deref(),
                parent: t.parent.as_deref(),
                harness: t.harness.as_deref(),
                hosts: &t.hosts,
                ttl: t.ttl,
            };
            let got = self.check(&ctx);
            let pass = got.allowed() == (t.expect == Effect::Allow);
            all &= pass;
            let who = [
                ("exe", &t.exe),
                ("parent", &t.parent),
                ("harness", &t.harness),
            ]
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| format!(" {k}={v}")))
            .collect::<String>();
            let verdict = match &got {
                Decision::Allow(n) => format!("allow (rule {n})"),
                Decision::Deny(_, why) => format!("deny ({why})"),
            };
            let expect = match t.expect {
                Effect::Allow => "allow",
                Effect::Deny => "deny",
            };
            lines.push(match pass {
                true => format!("ok    test {}: {} {name}{who} -> {verdict}", i + 1, t.op),
                false => format!(
                    "FAIL  test {}: {} {name}{who} -> {verdict}, expected {expect}",
                    i + 1,
                    t.op
                ),
            });
        }
        (all, lines)
    }
}

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

    #[test]
    fn validation_rejects_unknown_ops() {
        let p = PolicyFile {
            rules: vec![rule(Effect::Allow, &["read"], &[])],
            tests: vec![],
        };
        assert!(p.validate().unwrap_err().contains("unknown op `read`"));
        let p = PolicyFile {
            rules: vec![rule(Effect::Allow, &[], &[])],
            tests: vec![],
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
                    hosts: vec![],
                    ttl: None,
                    expect: Effect::Allow,
                },
            ],
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
