//! Local privacy setup and preview; no daemon connection or provider call.

pub(crate) mod config;

use kepr_core::privacy::{Policy, Preset, PrivacyResponse, Session, MAX_TEXT_BYTES};
use kepr_core::protocol::Response;
use std::io::IsTerminal;

pub const VERBS: &[&str] = &["privacy"];
pub const HELP: &str = "  privacy init [--preset MODE]         create an owner-only local privacy policy\n  privacy configure --stdin            validate and save a JSON privacy policy\n  privacy status                       show policy and available protection\n  privacy preview                      mask stdin locally and show category counts\n";

fn preset(value: &str) -> Result<Preset, &'static str> {
    match value {
        "private-cloud" => Ok(Preset::PrivateCloud),
        "local-only" => Ok(Preset::LocalOnly),
        _ => Err("privacy preset must be private-cloud or local-only"),
    }
}

fn execute(args: &[&str]) -> Result<PrivacyResponse, &'static str> {
    match args {
        ["init"] | ["init", "--preset", _] => {
            let mut policy = Policy::default();
            if args.len() == 3 {
                policy.preset = preset(args[2])?;
            }
            config::write(&policy, false)?;
            Ok(PrivacyResponse::PrivacyConfiguredOk {
                preset: policy.preset,
                identifier_count: 0,
            })
        }
        ["configure", "--stdin"] => {
            let bytes = config::read_bytes(std::io::stdin().lock(), config::MAX_POLICY_BYTES)?;
            let policy = config::parse(&bytes)?;
            config::write(&policy, true)?;
            Ok(PrivacyResponse::PrivacyConfiguredOk {
                preset: policy.preset,
                identifier_count: policy.identifiers.len(),
            })
        }
        ["status"] => {
            let configured = config::load()?;
            let exists = configured.is_some();
            let policy = configured.unwrap_or_default();
            Ok(PrivacyResponse::PrivacyStatusOk {
                configured: exists,
                preset: policy.preset,
                identifier_count: policy.identifiers.len(),
                device_enforcement_available: false,
                local_inference_available: false,
            })
        }
        ["preview"] => {
            let policy = config::load()?.unwrap_or_default();
            let mut session = Session::new(policy)?;
            let bytes = config::read_bytes(std::io::stdin().lock(), MAX_TEXT_BYTES)?;
            let text =
                std::str::from_utf8(&bytes).map_err(|_| "privacy input must be UTF-8 text")?;
            let report = session.transform_with_counts(text)?;
            Ok(PrivacyResponse::PrivacyPreviewOk {
                preset: session.preset(),
                text: report.text,
                redactions: report.redactions,
                counts: report.counts,
            })
        }
        _ => Err("usage: kepr privacy init [--preset MODE] | configure --stdin | status | preview"),
    }
}

pub fn dispatch(_verb: &str, args: &[String]) -> Response {
    let args: Vec<_> = args
        .iter()
        .map(String::as_str)
        .filter(|s| !matches!(*s, "--json" | "--color" | "--no-color"))
        .collect();
    match execute(&args) {
        Ok(report) => {
            if !crate::cli_ui::json_mode() {
                show(&report);
            }
            Response::Privacy(report)
        }
        Err(message) => Response::fail(message),
    }
}

fn name(preset: Preset) -> &'static str {
    match preset {
        Preset::PrivateCloud => "private-cloud",
        Preset::LocalOnly => "local-only",
    }
}

fn terminal_text(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() && !matches!(c, '\n' | '\t') {
            use std::fmt::Write;
            write!(&mut output, "\\u{{{:x}}}", c as u32).expect("string formatting");
        } else {
            output.push(c);
        }
    }
    output
}

fn show(report: &PrivacyResponse) {
    match report {
        PrivacyResponse::PrivacyStatusOk {
            configured,
            preset,
            identifier_count,
            ..
        } => {
            println!("privacy policy: {}; configured: {configured}; supplied identifiers: {identifier_count}", name(*preset));
            println!("device traffic enforcement: unavailable; local inference: unavailable");
        }
        PrivacyResponse::PrivacyConfiguredOk {
            preset,
            identifier_count,
        } => {
            println!(
                "privacy policy saved: {}; supplied identifiers: {identifier_count}",
                name(*preset)
            );
        }
        PrivacyResponse::PrivacyPreviewOk {
            text,
            redactions,
            counts,
            ..
        } => {
            if std::io::stdout().is_terminal() {
                print!("{}", terminal_text(text));
            } else {
                print!("{text}");
            }
            eprintln!("privacy preview: {redactions} redactions; {counts:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_preview_cannot_execute_escape_sequences() {
        let output = terminal_text("hello\x1b]52;c;data\x07\n");
        assert!(!output.contains('\x1b'));
        assert!(!output.contains('\x07'));
        assert!(output.ends_with('\n'));
    }
}
