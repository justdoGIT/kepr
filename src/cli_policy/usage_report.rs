// cli_policy/usage_report.rs — T9.07 `kepr usage --report [--days N]
// [--unused-days N] [--prices FILE]`: the daemon's per harness ×
// credential × host table of agent-gate traffic, with an estimated cost
// from a price table, and the bound hosts nothing used (over-scoped
// bindings). Also names the harness of a fresh `kepr agent run` session.
//
// Price table (default ~/.config/kepr/prices), one line per host glob,
// first match wins; tokens are what the providers reported:
//
//   # HOST-GLOB            USD per million tokens
//   api.anthropic.com      6.00
//   *.openai.com           4.00

use std::path::PathBuf;

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{PolicyRequest, PolicyResponse, UnusedBinding, UsageRow};

const USAGE: &str =
    "usage: kepr usage --report [--days N] [--unused-days N (default 30)] [--prices FILE]";

/// `kepr agent run`: name the session's harness for the report. Best
/// effort: an older daemon or a failed write only leaves it `unknown`.
pub fn label_session(session: Option<&str>, harness: &str) {
    if let Some(session) = session {
        let _ = crate::client::send_request(&kepr_core::protocol::Request::Policy(
            PolicyRequest::SessionHarness {
                session: session.to_string(),
                harness: harness.to_string(),
            },
        ));
    }
}

/// `HOST-GLOB PRICE` lines; `#` comments and blank lines skipped.
pub fn parse_prices(text: &str) -> Result<Vec<(String, f64)>, String> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(host), Some(price), None) = (it.next(), it.next(), it.next()) else {
            return Err(format!("prices line {}: expected HOST-GLOB PRICE", i + 1));
        };
        match price.trim_start_matches('$').parse::<f64>() {
            Ok(p) if p.is_finite() && p >= 0.0 => out.push((host.to_ascii_lowercase(), p)),
            _ => return Err(format!("prices line {}: {price} is not a price", i + 1)),
        }
    }
    Ok(out)
}

/// USD for `row`'s tokens, if the table prices its host.
pub fn cost(prices: &[(String, f64)], row: &UsageRow) -> Option<f64> {
    let host = row.host.to_ascii_lowercase();
    let host = host.split(':').next().unwrap_or_default();
    let per_million = prices
        .iter()
        .find(|(glob, _)| kepr_core::policy::glob(glob, host))?
        .1;
    Some(row.tokens as f64 * per_million / 1_000_000.0)
}

/// The report as text lines (header first).
pub fn table(rows: &[UsageRow], prices: &[(String, f64)]) -> Vec<String> {
    let w = |f: fn(&UsageRow) -> &str, min: usize| {
        rows.iter().map(|r| f(r).len()).max().unwrap_or(0).max(min)
    };
    let (wh, wc, wo) = (w(|r| &r.harness, 7), w(|r| &r.cred, 4), w(|r| &r.host, 4));
    let mut out = vec![format!(
        "{:wh$}  {:wc$}  {:wo$}  {:>8}  {:>7}  {:>10}  {:>9}",
        "HARNESS", "CRED", "HOST", "REQUESTS", "BLOCKED", "TOKENS", "COST"
    )];
    for r in rows {
        let usd = cost(prices, r).map_or("-".into(), |c| format!("${c:.2}"));
        out.push(format!(
            "{:wh$}  {:wc$}  {:wo$}  {:>8}  {:>7}  {:>10}  {:>9}",
            r.harness, r.cred, r.host, r.requests, r.blocked, r.tokens, usd
        ));
    }
    out
}

fn unused_line(u: &UnusedBinding) -> String {
    let last = u
        .last_used
        .as_deref()
        .map_or("never".into(), |t| format!("last {t} UTC"));
    format!("  {} → {} ({last})", u.cred, u.host)
}

fn number(args: &[String], f: &str) -> Result<Option<u32>, String> {
    match crate::cli_extra::flag(args, f) {
        None if args.iter().any(|a| a == f) => Err(format!("{f} needs a number\n{USAGE}")),
        None => Ok(None),
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| format!("{f} needs a number\n{USAGE}")),
    }
}

pub fn cmd_report(args: &[String]) -> Response {
    let parsed = number(args, "--days").and_then(|d| Ok((d, number(args, "--unused-days")?)));
    let (days, unused_days) = match parsed {
        Ok((d, u)) => (d, u.unwrap_or(30)),
        Err(e) => return Response::fail(e),
    };
    let prices_path = crate::cli_extra::flag(args, "--prices")
        .map(PathBuf::from)
        .unwrap_or_else(|| super::tail::config_dir().join("prices"));
    let prices = match std::fs::read_to_string(&prices_path) {
        Ok(t) => match parse_prices(&t) {
            Ok(p) => p,
            Err(e) => return Response::fail(format!("{}: {e}", prices_path.display())),
        },
        Err(_) => Vec::new(),
    };
    let r = super::send(PolicyRequest::UsageReport { days, unused_days });
    let Response::Policy(PolicyResponse::UsageReportOk {
        since,
        rows,
        unused,
        truncated,
        ..
    }) = &r
    else {
        return r;
    };
    if crate::cli_mode::json_mode() {
        return r;
    }
    let window = since
        .as_deref()
        .map_or("everything kept".into(), |s| format!("since {s} UTC"));
    crate::cli_ui::info(&format!("agent gate traffic, {window}"));
    for line in table(rows, &prices) {
        println!("{line}");
    }
    let total: f64 = rows.iter().filter_map(|r| cost(&prices, r)).sum();
    if prices.is_empty() {
        crate::cli_ui::info(&format!(
            "no prices: list USD per million tokens per host in {} for a cost estimate",
            prices_path.display()
        ));
    } else {
        crate::cli_ui::info(&format!(
            "estimated cost: ${total:.2} (provider-reported tokens × {})",
            prices_path.display()
        ));
    }
    if *truncated {
        crate::cli_ui::warn("more rows than fit one reply; narrow it with --days");
    }
    if !unused.is_empty() {
        crate::cli_ui::warn(&format!(
            "bound but unused for {unused_days} days (over-scoped; see kepr report access NAME):"
        ));
        for u in unused {
            println!("{}", unused_line(u));
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(host: &str, tokens: u64) -> UsageRow {
        UsageRow {
            harness: "claude".into(),
            cred: "ANTHROPIC_API_KEY".into(),
            host: host.into(),
            requests: 3,
            blocked: 1,
            tokens,
        }
    }

    #[test]
    fn prices_parse_and_price_tokens() {
        let p = parse_prices("# table\napi.anthropic.com  6.00\n*.openai.com $4 # blended\n\n")
            .unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(cost(&p, &row("api.anthropic.com", 2_000_000)), Some(12.0));
        assert_eq!(cost(&p, &row("api.openai.com:443", 500_000)), Some(2.0));
        assert_eq!(cost(&p, &row("db.internal:5432", 9)), None);
        assert!(parse_prices("api.x.ai").is_err());
        assert!(parse_prices("api.x.ai -1").is_err());
        assert!(parse_prices("api.x.ai NaN").is_err());
    }

    #[test]
    fn the_table_lines_up_with_costs() {
        let p = parse_prices("api.anthropic.com 6").unwrap();
        let t = table(
            &[row("api.anthropic.com", 2_000), row("example.com:443", 0)],
            &p,
        );
        assert_eq!(t.len(), 3);
        assert!(t[0].starts_with("HARNESS  CRED"), "{}", t[0]);
        assert!(t[1].ends_with("$0.01"), "{}", t[1]);
        assert!(t[2].ends_with(" -"), "{}", t[2]);
        assert!(t.iter().all(|l| l.len() == t[0].len()), "{t:#?}");
        let u = UnusedBinding {
            cred: "GH".into(),
            host: "uploads.github.com".into(),
            last_used: None,
        };
        assert_eq!(unused_line(&u), "  GH → uploads.github.com (never)");
    }

    #[test]
    fn bad_numbers_are_refused() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(number(&v(&["--report", "--days", "x"]), "--days").is_err());
        assert!(number(&v(&["--report", "--days"]), "--days").is_err());
        assert_eq!(number(&v(&["--days", "7"]), "--days"), Ok(Some(7)));
        assert!(matches!(
            cmd_report(&v(&["--report", "--unused-days", "z"])),
            Response::Err { .. }
        ));
    }
}
