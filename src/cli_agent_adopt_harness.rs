// cli_agent_adopt_harness.rs — keys in agent harness config files (T12.18).
// `kepr agent adopt` also reads these: the agent can read them inside its
// session, and a harness may use a key there instead of the gate's
// placeholder. Files and keys, checked against each harness's docs as of
// 2026-10 (relative to HOME):
//   .codex/auth.json           OPENAI_API_KEY (`codex login --with-api-key`)
//   .grok/user-settings.json   apiKey (grok-cli)
//   .aider.conf.yml            openai-api-key, anthropic-api-key, and
//                              `api-key:` items `- provider=key`
//   .config/omp/agent/models.yml providers.<id>.apiKey (a key or a variable name)
// Read by key, not by line, and never rewritten: `--remove` leaves the
// key for the user to delete by hand. Values are never printed.

use std::path::Path;

use kepr_core::generate::ZeroString;
use serde_json::Value;

use crate::cli_agent_adopt::Found;

pub const HARNESS_FILES: &[&str] = &[
    ".codex/auth.json",
    ".grok/user-settings.json",
    ".aider.conf.yml",
    ".config/omp/agent/models.yml",
];

/// JSON and YAML files are read by key and never rewritten.
pub fn is_structured(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("json" | "yml" | "yaml")
    )
}

/// Could be a key: not a variable name (`KEPR_PH_ANTHROPIC`), a reference
/// (`${VAR}`, `{env:VAR}`), a URL or prose.
fn key_shaped(value: &str) -> bool {
    value.len() >= 8
        && !value.contains(char::is_whitespace)
        && !value.contains("://")
        && !value.starts_with(['$', '{', '%'])
        && !value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The key itself when it reads like a credential NAME (`OPENAI_API_KEY`,
/// `anthropic-api-key`); otherwise the name the adapters use for the
/// provider (`apiKey` for xai → XAI_API_KEY).
fn name_for(key: &str, provider: &str) -> String {
    let k = key.to_ascii_uppercase().replace('-', "_");
    let valid = k.len() <= 128 && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if valid && (k.ends_with("_KEY") || k.ends_with("_TOKEN")) {
        return k;
    }
    crate::cli_agent_adapters::ADAPTERS
        .iter()
        .flat_map(|a| a.creds)
        .find(|(p, _)| *p == provider)
        .map_or_else(
            || format!("{}_API_KEY", provider.to_ascii_uppercase()),
            |(_, n)| n.to_string(),
        )
}

fn found(file: &Path, line: usize, key: &str, value: &str) -> Option<Found> {
    if !key_shaped(value) {
        return None;
    }
    let p = kepr_core::providers::detect(Some(key), value)?;
    // Found by the key's name alone (no known prefix): the key must also
    // say it holds a credential, or `anthropic-model: claude-x` would count.
    let by_prefix = p.prefixes.iter().any(|pre| value.starts_with(pre));
    let upper = key.to_ascii_uppercase();
    if !by_prefix && !["KEY", "TOKEN", "SECRET"].iter().any(|w| upper.contains(w)) {
        return None;
    }
    Some(Found {
        file: file.to_path_buf(),
        line,
        name: name_for(key, p.name),
        provider: p.name,
        value: ZeroString::from_string(value.to_string()),
        key: Some(key.to_string()),
    })
}

fn walk(file: &Path, key: &str, v: &Value, out: &mut Vec<Found>) {
    match v {
        Value::String(s) => out.extend(found(file, 0, key, s)),
        Value::Array(a) => a.iter().for_each(|x| walk(file, key, x, out)),
        Value::Object(o) => o.iter().for_each(|(k, x)| walk(file, k, x, out)),
        _ => {}
    }
}

/// `key: value` (YAML), `key = "value"` (TOML-like) or an aider list item
/// `- provider=value`; comments and other lines give None.
fn key_value(line: &str) -> Option<(&str, &str)> {
    let l = line.trim();
    let l = l.strip_prefix("- ").unwrap_or(l);
    if l.starts_with('#') {
        return None;
    }
    let i = l.find([':', '='])?;
    let key = l[..i].trim().trim_matches(['"', '\'']);
    let ok = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c));
    ok.then(|| (key, crate::cli_agent_adopt::unquote(&l[i + 1..])))
}

/// Provider keys in a harness config file. JSON findings have line 0 and
/// are shown as `file (key)`; YAML ones carry their line.
pub fn scan_structured(file: &Path, text: &str) -> Vec<Found> {
    let mut out = Vec::new();
    if file.extension().is_some_and(|e| e == "json") {
        if let Ok(v) = serde_json::from_str::<Value>(text) {
            walk(file, "", &v, &mut out);
        }
        return out;
    }
    for (i, l) in text.lines().enumerate() {
        if let Some((k, v)) = key_value(l) {
            out.extend(found(file, i + 1, k, v));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn got(f: &[Found]) -> Vec<(usize, &str, &str, Option<&str>)> {
        f.iter()
            .map(|x| (x.line, x.name.as_str(), x.provider, x.key.as_deref()))
            .collect()
    }

    #[test]
    fn json_keys_are_found_by_key() {
        let f = scan_structured(
            Path::new("auth.json"),
            r#"{"OPENAI_API_KEY": "sk-proj-abcdefghijklmnop", "tokens": null}"#,
        );
        assert_eq!(
            got(&f),
            vec![(0, "OPENAI_API_KEY", "openai", Some("OPENAI_API_KEY"))]
        );
        assert_eq!(f[0].value.as_str(), "sk-proj-abcdefghijklmnop");
        let nested = scan_structured(
            Path::new("user-settings.json"),
            r#"{"x": {"apiKey": "xai-abcdefghijklmnop", "baseURL": "https://api.x.ai/v1"}}"#,
        );
        assert_eq!(
            got(&nested),
            vec![(0, "XAI_API_KEY", "xai", Some("apiKey"))]
        );
    }

    #[test]
    fn yaml_lines_are_found_with_their_line() {
        let text = "# aider\nmodel: sonnet\nopenai-api-base: https://proxy.example/v1\n\
                    anthropic-api-key: sk-ant-api03-abcdefghijk\napi-key:\n  - gemini=AIzaSyabcdefghijklmn\n";
        let f = scan_structured(Path::new(".aider.conf.yml"), text);
        assert_eq!(
            got(&f),
            vec![
                (
                    4,
                    "ANTHROPIC_API_KEY",
                    "anthropic",
                    Some("anthropic-api-key")
                ),
                (6, "GEMINI_API_KEY", "google", Some("gemini")),
            ]
        );
        let omp = "providers:\n  kepr-anthropic:\n    apiKey: KEPR_PH_ANTHROPIC\n  mine:\n    apiKey: \"sk-ant-api03-zzzzzzzzzzzz\"\n";
        let f = scan_structured(Path::new("models.yml"), omp);
        assert_eq!(
            got(&f),
            vec![(5, "ANTHROPIC_API_KEY", "anthropic", Some("apiKey"))]
        );
    }

    #[test]
    fn variable_names_prose_and_bad_json_are_not_keys() {
        for text in [
            "apiKey: KEPR_PH_ANTHROPIC\n",
            "anthropic-api-key: KEPR_PH_ANTHROPIC\n",
            "openai-api-key: ${OPENAI_API_KEY}\n",
            "openai-model: gpt-5\n",
            "anthropic-note: this is not a key at all\n",
            "openai-api-base: https://api.openai.com/v1\n",
        ] {
            assert!(
                scan_structured(Path::new("c.yml"), text).is_empty(),
                "{text}"
            );
        }
        for text in [
            "{\"OPENAI_API_KEY\": ",
            "not json at all",
            "{\"apiKey\": \"{env:KEPR_PH_ANTHROPIC}\"}",
            "{\"anthropic\": \"hello world\"}",
            "[1, 2, {\"deep\": [[[]]]}]",
        ] {
            assert!(
                scan_structured(Path::new("c.json"), text).is_empty(),
                "{text}"
            );
        }
    }

    #[test]
    fn structured_means_json_or_yaml() {
        for f in HARNESS_FILES {
            assert!(is_structured(Path::new(f)), "{f}");
        }
        assert!(!is_structured(Path::new(".env")));
        assert!(!is_structured(Path::new(".bashrc")));
        assert!(!is_structured(Path::new("config.toml")));
    }
}
