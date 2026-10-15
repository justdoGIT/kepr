// health_policy.rs — T11.11 `kepr health --policy FILE`: hygiene rules
// for every credential, stricter ones per tag (T5.01 tags). The CLI reads
// the file and sends the rules with `Health`; the daemon checks values
// against them and reports only which rule a credential breaks.
// T11.23: the kind of each finding, the unit `kepr health --ignore` uses.
//
//   min_length = 16                    # every credential
//   classes = ["lower", "upper", "digit"]
//   max_age_days = 365
//   [tag.prod]                         # credentials tagged prod, on top
//   min_length = 24
//   max_age_days = 90

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::generate_profile::CLASSES;

const MAX_TAGS: usize = 64;

/// T11.23: what `kepr health --ignore NAME:KIND` can name.
pub const FINDING_KINDS: &[&str] = &[
    "weak",
    "common",
    "short",
    "reused",
    "old",
    "expired",
    "breached",
    "policy",
    "unreadable",
    "cert",
];

/// The kind of a `kepr health` finding (one of FINDING_KINDS).
pub fn finding_kind(issue: &str) -> &'static str {
    const PREFIXES: &[(&str, &str)] = &[
        ("common password", "common"),
        ("weak", "weak"),
        ("short", "short"),
        ("same value as", "reused"),
        ("not changed in", "old"),
        ("expired", "expired"),
        ("found in a data breach", "breached"),
        ("policy:", "policy"),
        ("certificate ", "cert"), // T10.10: kepr pki expiry
    ];
    PREFIXES
        .iter()
        .find(|(p, _)| issue.starts_with(p))
        .map_or("unreadable", |(_, k)| k)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRules {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    /// Classes the value must use: lower, upper, digit, symbol.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_days: Option<u32>,
}

fn has_class(value: &str, class: &str) -> bool {
    match class {
        "lower" => value.chars().any(|c| c.is_ascii_lowercase()),
        "upper" => value.chars().any(|c| c.is_ascii_uppercase()),
        "digit" => value.chars().any(|c| c.is_ascii_digit()),
        _ => value.chars().any(|c| !c.is_ascii_alphanumeric()),
    }
}

impl HealthRules {
    pub fn validate(&self) -> Result<(), String> {
        if self.min_length.is_some_and(|n| !(1..=4096).contains(&n)) {
            return Err("min_length: 1-4096".into());
        }
        if self
            .max_age_days
            .is_some_and(|n| !(1..=36_500).contains(&n))
        {
            return Err("max_age_days: 1-36500".into());
        }
        for (i, c) in self.classes.iter().enumerate() {
            if !CLASSES.contains(&c.as_str()) || self.classes[..i].contains(c) {
                return Err(format!(
                    "classes: each of {} at most once",
                    CLASSES.join(", ")
                ));
            }
        }
        Ok(())
    }

    /// The stricter of each rule in `self` and `other`.
    fn tighten(&mut self, other: &HealthRules) {
        self.min_length = self.min_length.max(other.min_length);
        self.max_age_days = match (self.max_age_days, other.max_age_days) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        for c in &other.classes {
            if !self.classes.contains(c) {
                self.classes.push(c.clone());
            }
        }
    }

    /// Rules a value breaks (never the value itself).
    pub fn value_violations(&self, value: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(n) = self.min_length {
            if value.chars().count() < n as usize {
                out.push(format!("policy: shorter than {n} characters"));
            }
        }
        let missing: Vec<&str> = CLASSES
            .iter()
            .copied()
            .filter(|c| self.classes.iter().any(|x| x == c) && !has_class(value, c))
            .collect();
        if !missing.is_empty() {
            out.push(format!("policy: no {} character", missing.join(" / ")));
        }
        out
    }

    /// The age rule, for a value unchanged for `age_days`.
    pub fn age_violation(&self, age_days: u64) -> Option<String> {
        self.max_age_days
            .filter(|max| age_days > u64::from(*max))
            .map(|max| format!("policy: older than {max} days"))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthPolicy {
    /// For every credential.
    #[serde(default)]
    pub all: HealthRules,
    /// On top, for credentials with that tag.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, HealthRules>,
}

impl HealthPolicy {
    pub fn validate(&self) -> Result<(), String> {
        self.all.validate()?;
        if self.tags.len() > MAX_TAGS {
            return Err(format!("at most {MAX_TAGS} [tag.*] tables"));
        }
        for (t, r) in &self.tags {
            let ok = (1..=32).contains(&t.len())
                && t.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
                });
            if !ok {
                return Err(format!("[tag.{t:?}]: tags are 1-32 of a-z, 0-9, _ and -"));
            }
            r.validate().map_err(|e| format!("[tag.{t}] {e}"))?;
        }
        Ok(())
    }

    /// The rules for a credential with `tags`: the strictest of each.
    pub fn rules_for(&self, tags: &[String]) -> HealthRules {
        let mut r = self.all.clone();
        for t in tags {
            if let Some(extra) = self.tags.get(t) {
                r.tighten(extra);
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(min: Option<u32>, classes: &[&str], age: Option<u32>) -> HealthRules {
        HealthRules {
            min_length: min,
            classes: classes.iter().map(|c| c.to_string()).collect(),
            max_age_days: age,
        }
    }

    #[test]
    fn each_rule_reports_what_it_checks() {
        let r = rules(Some(12), &["upper", "digit", "symbol"], Some(90));
        assert_eq!(
            r.value_violations("short"),
            [
                "policy: shorter than 12 characters",
                "policy: no upper / digit / symbol character"
            ]
        );
        assert_eq!(
            r.value_violations("Long-enough-value-7"),
            Vec::<String>::new()
        );
        assert_eq!(
            r.value_violations("long enough value 7"),
            ["policy: no upper character"]
        );
        assert_eq!(
            r.age_violation(91).as_deref(),
            Some("policy: older than 90 days")
        );
        assert_eq!(r.age_violation(90), None);
        assert!(HealthRules::default().value_violations("").is_empty());
    }

    #[test]
    fn tag_rules_tighten_the_base() {
        let p = HealthPolicy {
            all: rules(Some(12), &["lower"], Some(365)),
            tags: BTreeMap::from([
                ("prod".into(), rules(Some(24), &["digit"], Some(90))),
                ("legacy".into(), rules(Some(8), &[], None)),
            ]),
        };
        p.validate().unwrap();
        assert_eq!(p.rules_for(&[]), p.all);
        assert_eq!(
            p.rules_for(&["prod".into(), "legacy".into(), "other".into()]),
            rules(Some(24), &["lower", "digit"], Some(90))
        );
        assert_eq!(
            p.rules_for(&["legacy".into()]),
            rules(Some(12), &["lower"], Some(365))
        );
    }

    #[test]
    fn every_finding_has_a_kind() {
        for (issue, kind) in [
            ("common password", "common"),
            ("weak (easy to guess)", "weak"),
            ("short (under 12 characters)", "short"),
            ("same value as A, B", "reused"),
            ("not changed in 400 days", "old"),
            ("expired", "expired"),
            ("found in a data breach", "breached"),
            ("policy: older than 90 days", "policy"),
            ("unreadable", "unreadable"),
            (
                "certificate app.test (serial 0a) expires in 3 day(s)",
                "cert",
            ),
        ] {
            assert_eq!(finding_kind(issue), kind, "{issue}");
            assert!(FINDING_KINDS.contains(&kind));
        }
    }

    #[test]
    fn bad_policies_are_refused() {
        for (p, what) in [
            (rules(Some(0), &[], None), "min_length"),
            (rules(None, &["emoji"], None), "classes"),
            (rules(None, &["digit", "digit"], None), "classes"),
            (rules(None, &[], Some(0)), "max_age_days"),
        ] {
            let e = HealthPolicy {
                all: p,
                tags: BTreeMap::new(),
            }
            .validate()
            .unwrap_err();
            assert!(e.contains(what), "{e}");
        }
        let bad_tag = HealthPolicy {
            tags: BTreeMap::from([("Prod".into(), HealthRules::default())]),
            ..Default::default()
        };
        assert!(bad_tag.validate().unwrap_err().contains("[tag.\"Prod\"]"));
    }
}
