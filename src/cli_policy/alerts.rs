// cli_policy/alerts.rs — alert rules (T7.15): `alerts.toml` maps audit
// ops and results to webhooks, each rule throttled ("once per 10 min").
//
//   [[rule]]
//   name = "policy denials"
//   ops = ["policy-deny", "get"]    # globs; absent = every op
//   names = ["PROD_*"]              # globs over the credential; absent = any
//   result = "fail"                 # ok | fail | any (default)
//   webhook = "kepr:SLACK_HOOK"     # https://… or kepr:NAME
//   format = "slack"                # optional; guessed from the URL
//   throttle = "10m"                # default 10m; "0" = every match
//
// Pure: parsing and evaluation with an injected clock. The message is
// built from the record's op / name / user / uid / result / time only.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use kepr_core::policy::glob;
use kepr_core::protocol_policy::AuditRecord;

use super::notify::{Format, Note};
use super::siem::rfc3339;

const DEFAULT_THROTTLE: u64 = 600;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default, rename = "rule")]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    name: String,
    #[serde(default)]
    ops: Vec<String>,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    result: Option<String>,
    webhook: String,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    throttle: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Fail,
    Any,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub ops: Vec<String>,
    pub names: Vec<String>,
    pub result: Outcome,
    pub webhook: String,
    pub format: Option<Format>,
    pub throttle_secs: u64,
}

impl Rule {
    pub fn matches(&self, r: &AuditRecord) -> bool {
        let any =
            |globs: &[String], text: &str| globs.is_empty() || globs.iter().any(|g| glob(g, text));
        let ok = r.result == "ok";
        any(&self.ops, &r.op)
            && (self.names.is_empty() || r.name.as_deref().is_some_and(|n| any(&self.names, n)))
            && match self.result {
                Outcome::Ok => ok,
                Outcome::Fail => !ok,
                Outcome::Any => true,
            }
    }
}

pub fn parse(text: &str) -> Result<Vec<Rule>, String> {
    let raw: RawFile = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut seen = std::collections::HashSet::new();
    raw.rules
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let at = |e: String| format!("rule {} ({}): {e}", i + 1, r.name);
            if r.name.trim().is_empty() || !seen.insert(r.name.clone()) {
                return Err(format!("rule {}: needs a unique name", i + 1));
            }
            let result = match r.result.as_deref().unwrap_or("any") {
                "ok" => Outcome::Ok,
                "fail" => Outcome::Fail,
                "any" => Outcome::Any,
                other => return Err(at(format!("result `{other}` (ok, fail or any)"))),
            };
            if !(r.webhook.starts_with("https://")
                || r.webhook.starts_with("http://")
                || r.webhook.starts_with("kepr:"))
            {
                return Err(at("webhook must be an http(s):// URL or kepr:NAME".into()));
            }
            let format = r
                .format
                .as_deref()
                .map(Format::parse)
                .transpose()
                .map_err(at)?;
            let throttle_secs = match r.throttle.as_deref() {
                None => DEFAULT_THROTTLE,
                Some("0") => 0,
                Some(t) => crate::cli_sharing::parse_duration(t).map_err(at)?,
            };
            Ok(Rule {
                name: r.name.clone(),
                ops: r.ops,
                names: r.names,
                result,
                webhook: r.webhook,
                format,
                throttle_secs,
            })
        })
        .collect()
}

/// Per-rule throttle state, kept with the feed cursor across restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Throttle {
    /// Rule name → when it last sent.
    #[serde(default)]
    pub sent: HashMap<String, u64>,
    /// Rule name → matches held back since then.
    #[serde(default)]
    pub held: HashMap<String, u64>,
}

/// One message to send: the rule (index into the rules) and its note.
pub struct Hit {
    pub rule: usize,
    pub note: Note,
}

fn describe(r: &AuditRecord) -> String {
    format!(
        "{} {} by {} (uid {}): {}",
        r.op,
        r.name.as_deref().unwrap_or("-"),
        r.user,
        r.uid,
        r.result
    )
}

/// Match `records` at time `now`; updates `t` as if every hit is sent
/// (callers apply it to a copy and keep the copy only once sent).
pub fn evaluate(rules: &[Rule], t: &mut Throttle, records: &[AuditRecord], now: u64) -> Vec<Hit> {
    let mut hits = Vec::new();
    for r in records {
        for (i, rule) in rules.iter().enumerate().filter(|(_, x)| x.matches(r)) {
            let last = t.sent.get(&rule.name).copied();
            if last.is_some_and(|l| now < l.saturating_add(rule.throttle_secs)) {
                *t.held.entry(rule.name.clone()).or_default() += 1;
                continue;
            }
            let mut lines = vec![describe(r), format!("at {}", rfc3339(r.time))];
            if let Some(n) = t.held.remove(&rule.name).filter(|n| *n > 0) {
                lines.push(format!(
                    "{n} more match(es) held back by the throttle since the last alert"
                ));
            }
            t.sent.insert(rule.name.clone(), now);
            hits.push(Hit {
                rule: i,
                note: Note {
                    title: format!("kepr alert: {}", rule.name),
                    lines,
                },
            });
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_policy::notify::render;
    use crate::cli_policy::siem::record;

    const FILE: &str = r#"
[[rule]]
name = "denials"
ops = ["policy-*", "get"]
names = ["PROD_*"]
result = "fail"
webhook = "https://hooks.slack.com/services/x"

[[rule]]
name = "any delete"
ops = ["delete"]
webhook = "kepr:NTFY_URL"
format = "ntfy"
throttle = "0"
"#;

    #[test]
    fn parses_and_rejects_bad_rules() {
        let rules = parse(FILE).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].throttle_secs, 600);
        assert_eq!(rules[0].result, Outcome::Fail);
        assert_eq!(rules[1].format, Some(Format::Ntfy));
        assert_eq!(rules[1].throttle_secs, 0);
        for bad in [
            "[[rule]]\nname = \"a\"\nwebhook = \"ftp://x\"",
            "[[rule]]\nname = \"a\"\nwebhook = \"https://x\"\nresult = \"maybe\"",
            "[[rule]]\nname = \"a\"\nwebhook = \"https://x\"\nthrottle = \"soon\"",
            "[[rule]]\nname = \"a\"\nwebhook = \"https://x\"\nformat = \"pager\"",
            "[[rule]]\nname = \"a\"\nwebhook = \"https://x\"\nopz = []",
            "[[rule]]\nname = \"a\"\nwebhook = \"https://x\"\n[[rule]]\nname = \"a\"\nwebhook = \"https://y\"",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn matching() {
        let rules = parse(FILE).unwrap();
        let deny = &rules[0];
        assert!(deny.matches(&record(1, "policy-deny", Some("PROD_DB"), "fail: denied")));
        assert!(deny.matches(&record(1, "get", Some("PROD_DB"), "fail: expired")));
        assert!(!deny.matches(&record(1, "get", Some("PROD_DB"), "ok")));
        assert!(!deny.matches(&record(1, "get", Some("DEV_DB"), "fail: x")));
        assert!(!deny.matches(&record(1, "get", None, "fail: x")));
        assert!(!deny.matches(&record(1, "set", Some("PROD_DB"), "fail: x")));
        assert!(rules[1].matches(&record(1, "delete", None, "ok")));
    }

    #[test]
    fn throttling_with_an_injected_clock() {
        let rules = parse(FILE).unwrap();
        let mut t = Throttle::default();
        let fail = |s| record(s, "get", Some("PROD_DB"), "fail: x");
        let hits = evaluate(&rules, &mut t, &[fail(1), fail(2), fail(3)], 1000);
        assert_eq!(hits.len(), 1);
        assert_eq!(t.held["denials"], 2);
        assert!(evaluate(&rules, &mut t, &[fail(4)], 1599).is_empty());
        let hits = evaluate(&rules, &mut t, &[fail(5)], 1600);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].note.lines[2].starts_with("3 more match(es) held back"));
        assert!(!t.held.contains_key("denials"));
        // throttle = "0": every match sends.
        let del = |s| record(s, "delete", Some("K"), "ok");
        assert_eq!(evaluate(&rules, &mut t, &[del(6), del(7)], 1600).len(), 2);
    }

    #[test]
    fn body_per_format() {
        let rules = parse(FILE).unwrap();
        let mut t = Throttle::default();
        let hit = evaluate(
            &rules,
            &mut t,
            &[record(
                9,
                "policy-deny",
                Some("PROD_DB"),
                "fail: denied by rule 2",
            )],
            5,
        )
        .pop()
        .unwrap();
        assert_eq!(hit.note.title, "kepr alert: denials");
        assert_eq!(
            hit.note.lines[0],
            "policy-deny PROD_DB by alice (uid 1000): fail: denied by rule 2"
        );
        for f in [
            Format::Slack,
            Format::Teams,
            Format::Discord,
            Format::Ntfy,
            Format::Json,
        ] {
            let b = render(f, &hit.note);
            assert!(b.body.contains("policy-deny PROD_DB"), "{f:?}");
            assert!(!b.body.contains("h9"), "chain hash in {f:?}");
        }
    }
}
