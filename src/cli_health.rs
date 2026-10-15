// cli_health.rs — `kepr health [--max-age DAYS | --period N[d|w|m|y]]
// [--policy FILE] [--breach]` (agent vault P6.4; T11.11 period and policy
// reports, cli_recordsx/health.rs), `kepr health --ignore NAME:KIND[,KIND]`
// / `--unignore NAME[:KIND,...]` (T11.23: shown as ignored, not as issues). The daemon reports weak, short,
// common, reused, old and expired credentials without returning values. With --breach, each readable
// value's 5-digit SHA-1 prefix is looked up in the Have I Been Pwned
// password range API (k-anonymity), and the returned suffixes go back
// to the daemon, which says only whether the value is among them.

use std::collections::HashMap;

use kepr_core::health_policy::HealthPolicy;
use kepr_core::protocol::{KeyHealth, Request, Response};

use crate::{cli_mode, cli_ui, client};

const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
/// Suffix digits sent to the daemon: enough to make a false match
/// negligible, small enough to keep a range under the frame limit.
const SUFFIX_DIGITS: usize = 16;

fn send(req: &Request) -> Response {
    client::send_request(req).unwrap_or_else(Response::fail)
}

/// Suffixes from a range response (`SUFFIX:COUNT` lines; padding lines
/// have count 0 and are dropped).
pub fn parse_range(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|l| l.trim().split_once(':'))
        .filter(|(_, n)| n.trim() != "0")
        .map(|(s, _)| s.chars().take(SUFFIX_DIGITS).collect())
        .filter(|s: &String| s.len() == SUFFIX_DIGITS)
        .collect()
}

fn fetch_range(prefix: &str) -> Result<Vec<String>, String> {
    let req = crate::sync_http::agent()
        .get(&format!("{RANGE_URL}{prefix}"))
        .set("Add-Padding", "true")
        .set("User-Agent", "kepr");
    match crate::sync_http::send(req, None) {
        Ok((200, body)) => Ok(parse_range(&body)),
        Ok((code, _)) => Err(format!("breach list lookup failed: HTTP {code}")),
        Err(e) => Err(format!("breach list lookup failed: {e}")),
    }
}

/// Append "found in a data breach" to each item whose value is listed.
fn check_breaches(items: &mut [KeyHealth]) -> Result<(), String> {
    let mut ranges: HashMap<String, Vec<String>> = HashMap::new();
    for item in items.iter_mut() {
        let Some(prefix) = item.hibp_prefix.clone() else {
            continue;
        };
        if !ranges.contains_key(&prefix) {
            ranges.insert(prefix.clone(), fetch_range(&prefix)?);
        }
        let req = Request::BreachCheck {
            name: item.name.clone(),
            suffixes: ranges[&prefix].clone(),
        };
        if let Response::BreachOk { breached: true, .. } = send(&req) {
            let finding = "found in a data breach".to_string();
            match item.ignore.iter().any(|k| k == "breached") {
                true => item.ignored.push(finding), // T11.23
                false => item.issues.push(finding),
            }
        }
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq)]
pub struct Opts {
    pub max_age_days: Option<u32>,
    /// T11.11: `--period`: like --max-age, plus the aging report.
    pub period: bool,
    pub policy: Option<HealthPolicy>,
    pub breach: bool,
    /// T11.23: (name, kinds, clear) for each --ignore / --unignore.
    pub ignores: Vec<(String, Vec<String>, bool)>,
}

const USAGE: &str = "usage: kepr health [--max-age DAYS | --period N[d|w|m|y]] [--policy FILE] \
                     [--breach] | --ignore NAME:KIND[,KIND] | --unignore NAME[:KIND,...]";

pub fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let value = || {
            args.get(i + 1)
                .ok_or_else(|| format!("{} needs a value", args[i]))
        };
        match args[i].as_str() {
            "--breach" => {
                o.breach = true;
                i += 1;
                continue;
            }
            "--max-age" | "--period" if o.max_age_days.is_some() => {
                return Err("use one of --max-age and --period".into())
            }
            "--max-age" => {
                let d = value()?;
                o.max_age_days = Some(d.parse().map_err(|_| "--max-age needs a number of days")?);
            }
            "--period" => {
                o.max_age_days = Some(crate::cli_recordsx::health::parse_period(value()?)?);
                o.period = true;
            }
            "--policy" => o.policy = Some(crate::cli_recordsx::health::load_policy(value()?)?),
            f @ ("--ignore" | "--unignore") => {
                let clear = f == "--unignore";
                let (name, kinds) = crate::cli_recordsx::health::parse_ignore(value()?, clear)?;
                o.ignores.push((name, kinds, clear));
            }
            other => return Err(format!("unexpected argument: {other}\n{USAGE}")),
        }
        i += 2;
    }
    Ok(o)
}

/// `kepr health ARGS`.
pub fn cmd(args: &[String]) -> Response {
    match parse(args) {
        Ok(o) if !o.ignores.is_empty() => crate::cli_recordsx::health::cmd_ignore(&o.ignores),
        Ok(o) => cmd_health(o),
        Err(e) => Response::fail(e),
    }
}

pub fn cmd_health(o: Opts) -> Response {
    let (max_age_days, breach) = (o.max_age_days, o.breach);
    let r = send(&Request::Health {
        max_age_days,
        policy: o.policy,
    });
    let Response::HealthOk { mut items } = r else {
        return r;
    };
    if breach {
        if let Err(e) = check_breaches(&mut items) {
            cli_ui::warn(&format!("{e}; breach check skipped"));
        }
    }
    if let (true, Some(days), false) = (o.period, max_age_days, cli_mode::json_mode()) {
        let old = crate::cli_recordsx::health::aging(&items, days);
        cli_ui::info(&format!(
            "{} of {} credential(s) unchanged for more than {days} days",
            old.len(),
            items.len()
        ));
        old.iter().for_each(|l| println!("  {l}"));
        return Response::HealthOk { items };
    }
    if !cli_mode::json_mode() {
        let bad: Vec<&KeyHealth> = items.iter().filter(|i| !i.issues.is_empty()).collect();
        for i in &bad {
            println!("{}: {}", i.name, i.issues.join("; "));
        }
        for i in items.iter().filter(|i| !i.ignored.is_empty()) {
            cli_ui::dim(&format!("{}: ignored: {}", i.name, i.ignored.join("; ")));
        }
        if bad.is_empty() {
            cli_ui::ok(&format!("{} credential(s), no issues found", items.len()));
        } else {
            cli_ui::info(&format!(
                "{} of {} credential(s) need attention (kepr rotate / kepr set)",
                bad.len(),
                items.len()
            ));
        }
        if !breach {
            cli_ui::dim("add --breach to check values against public breach lists (k-anonymity)");
        }
    }
    Response::HealthOk { items }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_range_and_drops_padding() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n\
                    0000000000000000000000000000000000A:0\r\nbad line\r\n";
        assert_eq!(parse_range(body), vec!["1E4C9B93F3F06822".to_string()]);
    }

    #[test]
    fn parses_period_policy_and_breach_flags() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let o = parse(&a(&["--period", "3m", "--breach"])).unwrap();
        assert_eq!((o.max_age_days, o.period, o.breach), (Some(90), true, true));
        let o = parse(&a(&["--max-age", "30"])).unwrap();
        assert_eq!((o.max_age_days, o.period), (Some(30), false));
        assert!(parse(&a(&["--max-age", "30", "--period", "9"])).is_err());
        assert!(parse(&a(&["--period"]))
            .unwrap_err()
            .contains("needs a value"));
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("p.toml");
        std::fs::write(&f, "min_length = 20\n").unwrap();
        let o = parse(&a(&["--policy", f.to_str().unwrap()])).unwrap();
        assert_eq!(o.policy.unwrap().all.min_length, Some(20));
        assert!(parse(&a(&["--policy", "/nonexistent/p.toml"])).is_err());
        assert!(parse(&a(&["--bogus"])).unwrap_err().contains("unexpected"));
        let o = parse(&a(&["--ignore", "db:weak,old", "--unignore", "x"])).unwrap();
        assert_eq!(
            o.ignores,
            [
                (
                    "DB".to_string(),
                    vec!["weak".to_string(), "old".to_string()],
                    false
                ),
                ("X".to_string(), vec![], true)
            ]
        );
        assert!(parse(&a(&["--ignore", "db"])).is_err());
    }
}
