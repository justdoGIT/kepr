// cli_recordsx/health.rs — T11.11 reports for `kepr health`
// (cli_health.rs parses the flags and calls these):
//
//   --period N[d|w|m|y]   "old" = unchanged for longer than that (default
//                         days); prints an aging report, oldest first
//   --policy FILE         hygiene rules sent with the request, checked by
//                         the daemon (kepr_core::health_policy):
//                           min_length = 16
//                           classes = ["lower", "upper", "digit", "symbol"]
//                           max_age_days = 365
//                           require_totp = true   # login records need a totp field
//                           [tag.prod]          # stricter, for tag prod
//                           min_length = 24
//
// (The access policy of `kepr policy`, policy.toml, says who may read
// what; it has no hygiene rules, so this file is separate.)
//
// T11.23: `--ignore NAME:KIND[,KIND]` / `--unignore NAME[:KIND,...]`
// (kinds: kepr_core::health_policy::FINDING_KINDS), kept in the
// credential's .meta by the daemon until its value changes.

use kepr_core::health_policy::{HealthPolicy, HealthRules, FINDING_KINDS};
use kepr_core::protocol::{KeyHealth, Response};
use kepr_core::protocol_records::{RecordsRequest, RecordsResponse};

use crate::{cli_mode, cli_ui};

/// `NAME:KIND[,KIND]` (for --unignore the kinds may be left out: all).
pub fn parse_ignore(arg: &str, clear: bool) -> Result<(String, Vec<String>), String> {
    let (name, kinds) = match arg.split_once(':') {
        Some((n, k)) => (n, k.split(',').map(|k| k.trim().to_string()).collect()),
        None if clear => (arg, Vec::new()),
        None => {
            return Err(format!(
                "--ignore {arg}: use NAME:KIND[,KIND] ({})",
                FINDING_KINDS.join(", ")
            ))
        }
    };
    if let Some(k) = kinds
        .iter()
        .find(|k: &&String| !FINDING_KINDS.contains(&k.as_str()))
    {
        return Err(format!(
            "unknown finding {k:?}; use: {}",
            FINDING_KINDS.join(", ")
        ));
    }
    Ok((name.to_uppercase(), kinds))
}

/// Send each ignore; stop at the first refusal.
pub fn cmd_ignore(ignores: &[(String, Vec<String>, bool)]) -> Response {
    let mut last = Response::Pong;
    for (name, kinds, clear) in ignores {
        last = super::send(RecordsRequest::HealthIgnore {
            name: name.clone(),
            kinds: kinds.clone(),
            clear: *clear,
        });
        match &last {
            Response::Records(RecordsResponse::HealthIgnoreOk { name, ignored }) => {
                if !cli_mode::json_mode() {
                    cli_ui::ok(&match ignored.is_empty() {
                        true => format!("{name}: no findings ignored"),
                        false => format!("{name}: ignoring {}", ignored.join(", ")),
                    });
                }
            }
            _ => return last,
        }
    }
    last
}

/// `90`, `90d`, `12w`, `6m` (30 days each) or `1y` → days.
pub fn parse_period(s: &str) -> Result<u32, String> {
    let bad = || format!("--period {s:?}: use days, or a number with d, w, m or y (e.g. 90d, 6m)");
    let (num, unit) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c.to_ascii_lowercase()),
        _ => (s, 'd'),
    };
    let n: u32 = num.parse().map_err(|_| bad())?;
    let per = match unit {
        'd' => 1,
        'w' => 7,
        'm' => 30,
        'y' => 365,
        _ => return Err(bad()),
    };
    match n.checked_mul(per) {
        Some(days) if (1..=36_500).contains(&days) => Ok(days),
        _ => Err(bad()),
    }
}

/// A policy file's text (format in the header).
pub fn parse_policy(text: &str) -> Result<HealthPolicy, String> {
    let mut top: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut policy = HealthPolicy::default();
    if let Some(tags) = top.remove("tag") {
        let toml::Value::Table(tags) = tags else {
            return Err("`tag` must hold [tag.NAME] tables".into());
        };
        for (t, rules) in tags {
            let r: HealthRules = rules.try_into().map_err(|e| format!("[tag.{t}] {e}"))?;
            policy.tags.insert(t, r);
        }
    }
    policy.all = toml::Value::Table(top)
        .try_into()
        .map_err(|e: toml::de::Error| e.to_string())?;
    policy.validate()?;
    Ok(policy)
}

pub fn load_policy(path: &str) -> Result<HealthPolicy, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    parse_policy(&text).map_err(|e| format!("{path}: {e}"))
}

/// The aging report: credentials unchanged for more than `days`, oldest
/// first, as `NAME  N days` lines.
pub fn aging(items: &[KeyHealth], days: u32) -> Vec<String> {
    let mut old: Vec<&KeyHealth> = items
        .iter()
        .filter(|i| i.age_days > u64::from(days))
        .collect();
    old.sort_by(|a, b| b.age_days.cmp(&a.age_days).then(a.name.cmp(&b.name)));
    let width = old.iter().map(|i| i.name.len()).max().unwrap_or(0);
    old.iter()
        .map(|i| format!("{:<width$}  {} days", i.name, i.age_days))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_arguments_name_known_findings() {
        assert_eq!(
            parse_ignore("db:weak, old", false),
            Ok(("DB".into(), vec!["weak".into(), "old".into()]))
        );
        assert_eq!(parse_ignore("db", true), Ok(("DB".into(), vec![])));
        assert!(parse_ignore("db", false).unwrap_err().contains("NAME:KIND"));
        assert!(parse_ignore("db:nope", false)
            .unwrap_err()
            .contains("unknown finding"));
    }

    #[test]
    fn periods_take_units() {
        for (s, days) in [
            ("90", 90),
            ("90d", 90),
            ("2w", 14),
            ("6M", 180),
            ("1y", 365),
        ] {
            assert_eq!(parse_period(s), Ok(days), "{s}");
        }
        for bad in ["", "d", "0", "-5", "3x", "999y", "1.5y"] {
            assert!(parse_period(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn policy_files_parse_base_and_tag_rules() {
        let p = parse_policy(
            "min_length = 16\nclasses = [\"lower\", \"digit\"]\nmax_age_days = 365\n\
             [tag.prod]\nmin_length = 24\nmax_age_days = 90\n",
        )
        .unwrap();
        assert_eq!(p.all.min_length, Some(16));
        assert_eq!(p.all.classes, ["lower", "digit"]);
        assert_eq!(p.tags["prod"].max_age_days, Some(90));
        let t = parse_policy("require_totp = true\n").unwrap();
        assert!(t.all.require_totp);
        assert_eq!(parse_policy("").unwrap(), HealthPolicy::default());
        for (bad, what) in [
            ("min_len = 3\n", "min_len"),
            ("[tag.prod]\nmax_age = 1\n", "[tag.prod]"),
            ("tag = 3\n", "[tag.NAME]"),
            ("classes = [\"emoji\"]\n", "classes"),
            ("[tag.Prod]\nmin_length = 3\n", "tags are"),
        ] {
            let e = parse_policy(bad).unwrap_err();
            assert!(e.contains(what), "{bad}: {e}");
        }
    }

    #[test]
    fn aging_lists_the_old_ones_oldest_first() {
        let item = |name: &str, age_days| KeyHealth {
            name: name.into(),
            issues: vec![],
            age_days,
            hibp_prefix: None,
            ignored: vec![],
            ignore: vec![],
        };
        let items = [item("A", 10), item("BB", 400), item("C", 91), item("D", 90)];
        assert_eq!(aging(&items, 90), ["BB  400 days", "C   91 days"]);
        assert!(aging(&items, 500).is_empty());
    }
}
