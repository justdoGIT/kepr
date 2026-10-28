// cli_desktop/ss/policy.rs — which programs may use the Secret Service.
//
// GNOME Keyring lets every process in the session read everything once it
// is unlocked. This server knows who is asking (the bus names the process;
// /proc names its program) and can say no. `~/.config/kepr/secret-service.toml`:
//
//   default = "allow"            # or "deny": then only `allow` rules pass
//
//   [[rule]]
//   exe = "/usr/bin/chromium*"   # glob on the program's path (optional)
//   op = "read"                  # read | write | search | all (default all)
//   sandboxed = true             # only callers inside another PID namespace
//   action = "deny"              # allow | deny
//
// The first rule that matches decides. No file means "allow", as before.
// Nothing here is a defence against a program that can already read the
// user's memory; it keeps the unprivileged and the unexpected out.

use kepr_core::policy_glob::glob;
use serde::Deserialize;

use super::caller::Caller;

/// What a call does to the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Search,
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleText {
    exe: Option<String>,
    #[serde(default = "all")]
    op: String,
    sandboxed: Option<bool>,
    action: Action,
}

fn all() -> String {
    "all".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    default: Option<Action>,
    #[serde(default)]
    rule: Vec<RuleText>,
}

#[derive(Debug, Default)]
pub struct Policy {
    default_deny: bool,
    rules: Vec<RuleText>,
}

impl Policy {
    pub fn parse(text: &str) -> Result<Policy, String> {
        let f: File = toml::from_str(text).map_err(|e| e.to_string())?;
        for r in &f.rule {
            if !matches!(r.op.as_str(), "read" | "write" | "search" | "all") {
                return Err(format!(
                    "unknown op {:?} (read, write, search or all)",
                    r.op
                ));
            }
        }
        Ok(Policy {
            default_deny: f.default == Some(Action::Deny),
            rules: f.rule,
        })
    }

    /// The policy file at `path`; a missing file allows everything, a
    /// broken one denies everything (and says why).
    pub fn load(path: &std::path::Path) -> Result<Policy, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => Policy::parse(&t).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Policy::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn deny_all() -> Policy {
        Policy {
            default_deny: true,
            rules: Vec::new(),
        }
    }

    pub fn check(&self, who: &Caller, op: Op) -> Action {
        for r in &self.rules {
            let op_ok = match r.op.as_str() {
                "read" => op == Op::Read,
                "write" => op == Op::Write,
                "search" => op == Op::Search,
                _ => true,
            };
            let exe_ok = r
                .exe
                .as_deref()
                .is_none_or(|g| who.exe.as_deref().is_some_and(|e| glob(g, e)));
            let sandbox_ok = r.sandboxed.is_none_or(|s| s == who.sandboxed);
            if op_ok && exe_ok && sandbox_ok {
                return r.action;
            }
        }
        if self.default_deny {
            Action::Deny
        } else {
            Action::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who(exe: &str, sandboxed: bool) -> Caller {
        Caller {
            name: ":1.5".into(),
            pid: Some(1),
            uid: Some(1000),
            exe: Some(exe.into()),
            sandboxed,
        }
    }

    #[test]
    fn no_policy_allows_everything() {
        let p = Policy::default();
        assert_eq!(
            p.check(&who("/usr/bin/anything", false), Op::Read),
            Action::Allow
        );
        assert_eq!(
            Policy::load(std::path::Path::new("/nonexistent/secret-service.toml"))
                .unwrap()
                .check(&who("/x", true), Op::Write),
            Action::Allow
        );
    }

    #[test]
    fn first_matching_rule_decides_and_the_default_is_the_fallback() {
        let p = Policy::parse(
            r#"
            default = "allow"
            [[rule]]
            exe = "/usr/bin/chromium*"
            op = "read"
            action = "allow"
            [[rule]]
            exe = "/usr/bin/*"
            op = "read"
            action = "deny"
            [[rule]]
            sandboxed = true
            action = "deny"
            "#,
        )
        .unwrap();
        assert_eq!(
            p.check(&who("/usr/bin/chromium-browser", false), Op::Read),
            Action::Allow
        );
        assert_eq!(
            p.check(&who("/usr/bin/curl", false), Op::Read),
            Action::Deny
        );
        assert_eq!(
            p.check(&who("/usr/bin/curl", false), Op::Search),
            Action::Allow,
            "the rule is for reads"
        );
        assert_eq!(
            p.check(&who("/opt/app", true), Op::Search),
            Action::Deny,
            "sandboxed callers"
        );
        assert_eq!(p.check(&who("/opt/app", false), Op::Write), Action::Allow);
    }

    #[test]
    fn a_default_deny_needs_allow_rules_and_an_unknown_program_never_matches_an_exe_rule() {
        let p = Policy::parse(
            "default = \"deny\"\n[[rule]]\nexe = \"/usr/bin/gh\"\naction = \"allow\"\n",
        )
        .unwrap();
        assert_eq!(p.check(&who("/usr/bin/gh", false), Op::Read), Action::Allow);
        assert_eq!(
            p.check(&who("/usr/bin/other", false), Op::Read),
            Action::Deny
        );
        let unknown = Caller {
            name: ":1.6".into(),
            pid: None,
            uid: None,
            exe: None,
            sandboxed: false,
        };
        assert_eq!(
            p.check(&unknown, Op::Read),
            Action::Deny,
            "no exe, no match for an exe rule"
        );
        assert_eq!(
            Policy::deny_all().check(&who("/usr/bin/gh", false), Op::Read),
            Action::Deny
        );
    }

    #[test]
    fn mistakes_in_the_file_are_errors() {
        for bad in [
            "default = \"maybe\"",
            "[[rule]]\naction = \"allow\"\nop = \"delete\"",
            "[[rule]]\naction = \"allow\"\nexe_path = \"x\"",
            "[[rule]]\nexe = \"x\"",
            "oops",
        ] {
            assert!(Policy::parse(bad).is_err(), "{bad}");
        }
    }
}
