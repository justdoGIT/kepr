// cli_session/discover_rules.rs — discovery rules (T11.20) for `kepr
// discover`, read from `~/.config/kepr/discover.toml`:
//
//   [[rule]]
//   match = "aws:*prod*"      # SOURCE:NAME-GLOB, or a bare NAME-GLOB
//   action = "ignore"         # add | ignore | ask
//
// SOURCE is one of `SOURCES` (or `*`); the glob (`*`, `?`, case-
// insensitive) is matched against the kepr name the entry would get.
// The first matching rule decides: `add` imports without `--yes`,
// `ignore` drops the entry without asking, `ask` asks on the terminal
// (no terminal: skipped). Entries no rule matches go through the usual
// plan (`--yes` to import). A broken rules file stops discover.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use kepr_core::protocol::Response;
use serde::Deserialize;

use crate::cli_import::Opts;
use crate::cli_import_parse::Entry;

/// The source keys `kepr discover` reads (see cli_discover.rs).
pub const SOURCES: &[&str] = &["aws", "git", "netrc", "npm", "pypi", "docker", "gh", "kube"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Add,
    Ignore,
    Ask,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    #[serde(rename = "match")]
    pattern: String,
    action: Action,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Rule {
    source: String,
    glob: String,
    pub action: Action,
}

pub fn parse(text: &str) -> Result<Vec<Rule>, String> {
    let file: RulesFile = toml::from_str(text).map_err(|e| e.to_string())?;
    file.rule
        .into_iter()
        .map(|r| {
            let (source, glob) = r.pattern.split_once(':').unwrap_or(("*", &r.pattern));
            let source = source.to_ascii_lowercase();
            if source != "*" && !SOURCES.contains(&source.as_str()) {
                return Err(format!(
                    "rule {:?}: unknown source {source:?} (one of {} or *)",
                    r.pattern,
                    SOURCES.join(", ")
                ));
            }
            if glob.is_empty() {
                return Err(format!("rule {:?}: empty name pattern", r.pattern));
            }
            Ok(Rule {
                source,
                glob: glob.to_ascii_lowercase(),
                action: r.action,
            })
        })
        .collect()
}

/// `*` (any run) and `?` (one character); backtracks only to the last
/// `*`, so it stays linear-ish whatever the pattern.
fn glob(p: &[char], t: &[char]) -> bool {
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// The first rule matching an entry from `source` named `name`.
pub fn decide(rules: &[Rule], source: &str, name: &str) -> Option<Action> {
    let name: Vec<char> = name.to_ascii_lowercase().chars().collect();
    rules
        .iter()
        .find(|r| {
            (r.source == "*" || r.source == source)
                && glob(&r.glob.chars().collect::<Vec<_>>(), &name)
        })
        .map(|r| r.action)
}

/// Entries split by the rules: (import now, usual plan, ignored, not
/// asked or declined). `ask` is called only for `ask` rules.
pub type Sorted = (Vec<Entry>, Vec<Entry>, usize, usize);

pub fn sort(
    rules: &[Rule],
    entries: Vec<(&'static str, Entry)>,
    ask: &mut dyn FnMut(&str, &str) -> bool,
) -> Sorted {
    let (mut now, mut plan, mut ignored, mut declined) = (Vec::new(), Vec::new(), 0, 0);
    for (source, e) in entries {
        match decide(rules, source, &e.name) {
            Some(Action::Add) => now.push(e),
            Some(Action::Ignore) => ignored += 1,
            Some(Action::Ask) if ask(source, &e.name) => now.push(e),
            Some(Action::Ask) => declined += 1,
            None => plan.push(e),
        }
    }
    (now, plan, ignored, declined)
}

pub fn rules_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        })
        .join("kepr/discover.toml")
}

/// The rules in effect: none without a file.
pub fn load() -> Result<Vec<Rule>, String> {
    let path = rules_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn ask_terminal(source: &str, name: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("  Import {name} (from {source})? [y/N]: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok();
    matches!(line.trim(), "y" | "Y" | "yes")
}

/// `kepr discover`'s import step with the rules applied.
pub fn import(entries: Vec<(&'static str, Entry)>, o: &Opts) -> Response {
    let rules = match load() {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    if rules.is_empty() {
        let all = entries.into_iter().map(|(_, e)| e).collect();
        return crate::cli_import::import_entries(all, o, None);
    }
    let (now, plan, ignored, declined) = sort(&rules, entries, &mut ask_terminal);
    crate::cli_ui::info(&format!(
        "discover.toml: {} to add, {ignored} ignored, {declined} not added (ask)",
        now.len()
    ));
    let mut resp = Response::Pong;
    if !now.is_empty() {
        let yes = Opts { yes: true, ..*o };
        resp = crate::cli_import::import_entries(now, &yes, None);
    }
    if !plan.is_empty() {
        let r = crate::cli_import::import_entries(plan, o, None);
        if resp.is_success() {
            resp = r;
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::generate::ZeroString;

    fn e(source: &'static str, name: &str) -> (&'static str, Entry) {
        let value = ZeroString::from_string("v".into());
        let name = name.into();
        (source, Entry { name, value })
    }

    const RULES: &str = r#"
        [[rule]]
        match = "aws:*prod*"
        action = "ignore"
        [[rule]]
        match = "aws:*"
        action = "add"
        [[rule]]
        match = "GIT_?ITHUB_COM"
        action = "ask"
    "#;

    #[test]
    fn the_first_matching_rule_decides() {
        let r = parse(RULES).unwrap();
        assert_eq!(
            decide(&r, "aws", "AWS_PROD_ACCESS_KEY_ID"),
            Some(Action::Ignore)
        );
        assert_eq!(decide(&r, "aws", "AWS_ACCESS_KEY_ID"), Some(Action::Add));
        assert_eq!(decide(&r, "git", "GIT_GITHUB_COM"), Some(Action::Ask));
        assert_eq!(decide(&r, "docker", "GIT_GITHUB_COM"), Some(Action::Ask));
        assert_eq!(decide(&r, "git", "GIT_GITLAB_COM"), None);
        assert_eq!(decide(&r, "npm", "NPM_TOKEN"), None);
    }

    #[test]
    fn ignore_never_prompts_and_ask_only_asks_its_own() {
        let r = parse(RULES).unwrap();
        let entries = vec![
            e("aws", "AWS_PROD_ACCESS_KEY_ID"),
            e("aws", "AWS_ACCESS_KEY_ID"),
            e("git", "GIT_GITHUB_COM"),
            e("npm", "NPM_TOKEN"),
        ];
        let mut asked = Vec::new();
        let mut ask = |_: &str, name: &str| {
            asked.push(name.to_string());
            false
        };
        let (now, plan, ignored, declined) = sort(&r, entries, &mut ask);
        assert_eq!(asked, ["GIT_GITHUB_COM"]);
        let names = |v: &[Entry]| v.iter().map(|e| e.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(&now), ["AWS_ACCESS_KEY_ID"]);
        assert_eq!(names(&plan), ["NPM_TOKEN"]);
        assert_eq!((ignored, declined), (1, 1));
        let (now, ..) = sort(&r, vec![e("git", "GIT_GITHUB_COM")], &mut |_, _| true);
        assert_eq!(names(&now), ["GIT_GITHUB_COM"]);
    }

    #[test]
    fn bad_rules_are_errors() {
        let bad = |t: &str| parse(t).unwrap_err();
        assert!(bad("[[rule]]\nmatch = \"ftp:*\"\naction = \"add\"").contains("unknown source"));
        assert!(bad("[[rule]]\nmatch = \"*\"\naction = \"maybe\"").contains("maybe"));
        assert!(bad("[[rule]]\nmatch = \"aws:\"\naction = \"add\"").contains("empty"));
        assert!(bad("[[rule]]\nmatch = \"*\"\naction = \"add\"\nextra = 1").contains("extra"));
        assert_eq!(parse("").unwrap(), []);
    }

    #[test]
    fn glob_basics() {
        let g = |p: &str, t: &str| {
            glob(
                &p.chars().collect::<Vec<_>>(),
                &t.chars().collect::<Vec<_>>(),
            )
        };
        assert!(g("*", "") && g("a*c", "abbc") && g("a?c", "abc") && g("*prod*", "x_prod_y"));
        assert!(!g("a?c", "ac") && !g("abc", "abcd") && !g("*prod", "prod_x"));
    }
}
