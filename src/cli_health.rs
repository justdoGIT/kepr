// cli_health.rs — `kepr health [--max-age DAYS] [--breach]` (agent vault
// P6.4). The daemon reports weak, short, common, reused, old and expired
// credentials without returning values. With --breach, each readable
// value's 5-digit SHA-1 prefix is looked up in the Have I Been Pwned
// password range API (k-anonymity), and the returned suffixes go back
// to the daemon, which says only whether the value is among them.

use std::collections::HashMap;

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
            item.issues.push("found in a data breach".to_string());
        }
    }
    Ok(())
}

pub fn cmd_health(max_age_days: Option<u32>, breach: bool) -> Response {
    let r = send(&Request::Health { max_age_days });
    let Response::HealthOk { mut items } = r else {
        return r;
    };
    if breach {
        if let Err(e) = check_breaches(&mut items) {
            cli_ui::warn(&format!("{e}; breach check skipped"));
        }
    }
    if !cli_mode::json_mode() {
        let bad: Vec<&KeyHealth> = items.iter().filter(|i| !i.issues.is_empty()).collect();
        for i in &bad {
            println!("{}: {}", i.name, i.issues.join("; "));
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
}
