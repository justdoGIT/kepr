//! Agent argument parsing, including fail-closed launch options.

use kepr_core::gate_protocol::GateLimits;

use super::{launch, USAGE};

#[derive(Debug, Default, PartialEq)]
pub struct AgentArgs {
    pub verb: String,
    pub target: Option<String>,
    pub fors: Vec<String>,
    pub port: Option<u16>,
    pub stdin: bool,
    pub from_clipboard: bool,
    pub force: bool,
    pub requires_consent: bool,
    pub yes: bool,
    pub remove: bool,
    pub files: Vec<String>,
    pub no_sandbox: bool,
    pub open_window: bool,
    pub strict_sandbox: bool,
    pub isolate_net: bool,
    pub compatibility: bool,
    pub security_preset: Option<String>,
    pub limits: GateLimits,
    /// Gate-batch session flags (`--tunnel`, …), see cli_gatex.
    pub session: crate::cli_gatex::SessionOpts,
    pub argv: Vec<String>,
}

fn number<T: std::str::FromStr>(raw: &[String], i: usize, flag: &str) -> Result<T, String> {
    raw.get(i)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("{flag} needs a positive number"))
}

pub fn parse(raw: &[String]) -> Result<AgentArgs, String> {
    let mut a = AgentArgs {
        verb: raw.first().ok_or(USAGE)?.clone(),
        ..Default::default()
    };
    let mut i = 1;
    while i < raw.len() {
        match raw[i].as_str() {
            "--json" | "--color" | "--no-color" => {}
            "--for" => {
                i += 1;
                a.fors.push(
                    raw.get(i)
                        .ok_or("--for needs a provider or binding")?
                        .clone(),
                );
            }
            "--port" => {
                i += 1;
                let p = raw.get(i).ok_or("--port needs a number")?;
                a.port = Some(
                    p.parse()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or("--port must be 1-65535")?,
                );
            }
            "--max-requests" => {
                i += 1;
                a.limits.max_requests = Some(number(raw, i, "--max-requests")?);
            }
            "--max-tokens" => {
                i += 1;
                a.limits.max_tokens = Some(number(raw, i, "--max-tokens")?);
            }
            "--rate" => {
                i += 1;
                a.limits.per_minute = Some(number(raw, i, "--rate")?);
            }
            "--max-requests-day" => {
                i += 1;
                a.limits.max_requests_day = Some(number(raw, i, "--max-requests-day")?);
            }
            "--max-tokens-day" => {
                i += 1;
                a.limits.max_tokens_day = Some(number(raw, i, "--max-tokens-day")?);
            }
            f if crate::cli_gatex::SessionOpts::FLAGS.contains(&f) => i = a.session.take(raw, i)?,
            "--stdin" => a.stdin = true,
            "--from-clipboard" => a.from_clipboard = true,
            "--force" | "-f" => a.force = true,
            "--requires-consent" => a.requires_consent = true,
            "--yes" | "-y" => a.yes = true,
            "--remove" => a.remove = true,
            f if launch::FLAGS.contains(&f) => i = launch::take(&mut a, raw, i)?,
            "--" => {
                a.argv = raw[i + 1..].to_vec();
                break;
            }
            s if !s.starts_with('-') && a.verb == "adopt" => a.files.push(s.to_string()),
            s if !s.starts_with('-') && a.target.is_none() => a.target = Some(s.to_string()),
            other => return Err(format!("unexpected argument: {other}\n{USAGE}")),
        }
        i += 1;
    }
    if a.stdin && a.from_clipboard {
        return Err("use one of --stdin or --from-clipboard".into());
    }
    launch::defaults(&mut a)?;
    Ok(a)
}
