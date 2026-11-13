//! Resolve modern Codex profile files without exposing their contents.

use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

pub(super) fn selected_profile(argv: &[String]) -> Result<Option<String>, String> {
    if argv
        .first()
        .is_some_and(|s| Path::new(s).file_name().is_none_or(|n| n != "codex"))
    {
        return Ok(None);
    }
    let mut selected = None;
    let mut args = argv.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        let name = if matches!(arg.as_str(), "--profile" | "-p") {
            Some(args.next().ok_or("Codex profile needs a name")?.as_str())
        } else {
            arg.strip_prefix("--profile=")
                .or_else(|| arg.strip_prefix("-p"))
        };
        if let Some(name) = name {
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                || selected.is_some()
            {
                return Err("unsupported or repeated Codex profile name".into());
            }
            selected = Some(name.to_string());
        }
        let config = if matches!(arg.as_str(), "--config" | "-c") {
            Some(
                args.next()
                    .ok_or("Codex config override needs a value")?
                    .as_str(),
            )
        } else {
            arg.strip_prefix("--config=")
                .or_else(|| arg.strip_prefix("-c"))
        };
        if let Some(config) = config {
            let key = config.split('=').next().unwrap_or_default().trim();
            let top = key
                .split('.')
                .next()
                .unwrap_or_default()
                .trim()
                .trim_matches(['\'', '"']);
            if matches!(
                top,
                "model_provider"
                    | "model_providers"
                    | "openai_base_url"
                    | "cli_auth_credentials_store"
                    | "profile"
                    | "profiles"
            ) {
                return Err(
                    "Kepr controls provider routing and authentication; select a Codex profile"
                        .into(),
                );
            }
        }
    }
    Ok(selected)
}

pub(super) fn read(path: &Path, required: bool) -> Result<Zeroizing<String>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(Zeroizing::new(String::new()));
        }
        Err(_) => return Err("cannot open Codex configuration or selected profile".into()),
    };
    if !file
        .metadata()
        .map_err(|_| "cannot inspect Codex configuration")?
        .is_file()
    {
        return Err("Codex configuration must be a bounded regular file".into());
    }
    let mut text = Zeroizing::new(String::new());
    file.take(1_048_577)
        .read_to_string(&mut text)
        .map_err(|_| "cannot read Codex configuration")?;
    if text.len() > 1_048_576 {
        return Err("Codex configuration must be a bounded regular file".into());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).into()).collect()
    }

    #[test]
    fn codex_profile_argument_selects_separate_file() {
        for args in [
            vec!["codex", "--profile", "selora"],
            vec!["codex", "exec", "-p", "selora"],
            vec!["codex", "--profile=selora"],
            vec!["codex", "-pselora"],
        ] {
            assert_eq!(
                selected_profile(&argv(&args)).unwrap(),
                Some("selora".into())
            );
        }
    }

    #[test]
    fn ambiguous_or_traversing_profiles_are_refused_without_echoing() {
        for args in [
            vec!["codex", "-p", "../outside"],
            vec!["codex", "--profile"],
            vec!["codex", "--profile="],
            vec!["codex", "-p", "one", "-p", "two"],
        ] {
            assert!(selected_profile(&argv(&args)).is_err());
        }
        assert_eq!(
            selected_profile(&argv(&["codex", "--", "--profile", "text"])).unwrap(),
            None
        );
    }

    #[test]
    fn cli_cannot_override_protected_provider_configuration() {
        for config in [
            "model_provider='other'",
            "model_providers.selora.base_url='http://other'",
            "\"model_provider\"='other'",
            "cli_auth_credentials_store='file'",
            "openai_base_url='http://other'",
        ] {
            assert!(selected_profile(&argv(&["codex", "-c", config])).is_err());
        }
        assert!(selected_profile(&argv(&[
            "codex",
            "--profile",
            "selora",
            "-c",
            "model='example'"
        ]))
        .is_ok());
    }
}
