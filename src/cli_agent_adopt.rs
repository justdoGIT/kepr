// cli_agent_adopt.rs — `kepr agent adopt [FILE...] [--yes] [--remove]`
// (agent vault T1.20). Finds API keys already sitting in .env files and
// shell startup files, imports them as sealed credentials, and
// optionally deletes the plaintext lines.
//
// Only values with a recognised provider prefix are adopted (see
// cli_agent_detect::detect). Values are never printed. `--remove`
// rewrites files without keeping a plaintext backup (a backup would
// leave the key on disk, which is what adoption is meant to end).

use std::path::{Path, PathBuf};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};

use crate::{cli_agent_detect, cli_ui, client};

pub struct Found {
    pub file: PathBuf,
    pub line: usize,
    pub name: String,
    pub provider: &'static str,
    pub value: ZeroString,
}

fn default_files() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [".env", ".env.local", ".envrc"].map(PathBuf::from).into();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for f in [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".zprofile",
            ".config/fish/config.fish",
        ] {
            v.push(home.join(f));
        }
    }
    v
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|s| s.strip_suffix(q)) {
            return inner;
        }
    }
    v.split_whitespace().next().unwrap_or_default()
}

/// `NAME=VALUE`, `export NAME=VALUE`, or fish `set -gx NAME VALUE`.
pub fn parse_line(line: &str) -> Option<(String, String)> {
    let l = line.trim();
    if l.starts_with('#') {
        return None;
    }
    let (name, value) = if let Some(rest) = l.strip_prefix("set ") {
        let mut parts = rest.split_whitespace().filter(|p| !p.starts_with('-'));
        let name = parts.next()?;
        let value_start = rest.find(name)? + name.len();
        (name.to_string(), unquote(&rest[value_start..]).to_string())
    } else {
        let l = l.strip_prefix("export ").unwrap_or(l);
        let (n, v) = l.split_once('=')?;
        (n.trim().to_string(), unquote(v).to_string())
    };
    let valid = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    (valid && !value.is_empty()).then_some((name.to_uppercase(), value))
}

pub fn scan_text(file: &Path, text: &str) -> Vec<Found> {
    text.lines()
        .enumerate()
        .filter_map(|(i, l)| {
            let (name, value) = parse_line(l)?;
            let provider = cli_agent_detect::detect(&value)?;
            Some(Found {
                file: file.to_path_buf(),
                line: i + 1,
                name,
                provider,
                value: ZeroString::from_string(value),
            })
        })
        .collect()
}

/// Delete the given 1-based line numbers from `text`.
pub fn remove_lines(text: &str, lines: &[usize]) -> String {
    let mut out: String = text
        .lines()
        .enumerate()
        .filter(|(i, _)| !lines.contains(&(i + 1)))
        .map(|(_, l)| format!("{l}\n"))
        .collect();
    if !text.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

fn store(f: &Found) -> Result<(), String> {
    let binding = cli_agent_detect::binding_for(f.provider)?;
    let req = Request::Set {
        name: f.name.clone(),
        value: Some(ZeroString::from_string(f.value.as_str().to_string())),
        generate: None,
        ttl_secs: None,
        requires_consent: None,
        requires_fido2: None,
        sealed: Some(true),
        bindings: Some(vec![binding]),
    };
    match client::send_request(&req)? {
        Response::SetOk { .. } => Ok(()),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

pub fn cmd_adopt(files: &[String], yes: bool, remove: bool) -> Response {
    let paths: Vec<PathBuf> = if files.is_empty() {
        default_files()
    } else {
        files.iter().map(PathBuf::from).collect()
    };
    let mut found: Vec<Found> = Vec::new();
    for p in &paths {
        if let Ok(text) = std::fs::read_to_string(p) {
            found.extend(scan_text(p, &text));
        }
    }
    if found.is_empty() {
        cli_ui::info("no provider API keys found in the scanned files");
        return Response::Pong;
    }
    for f in &found {
        println!(
            "{}:{}  {}  ({})",
            f.file.display(),
            f.line,
            f.name,
            f.provider
        );
    }
    if !yes {
        cli_ui::info("re-run with --yes to import these as sealed keys (add --remove to delete the plaintext lines)");
        return Response::Pong;
    }
    let mut adopted: Vec<&Found> = Vec::new();
    for f in &found {
        match store(f) {
            Ok(()) => adopted.push(f),
            Err(e) => cli_ui::err(&format!("{}: {e}", f.name)),
        }
    }
    cli_ui::ok(&format!(
        "adopted {} key(s) as sealed credentials",
        adopted.len()
    ));
    if remove {
        let mut files: Vec<&PathBuf> = adopted.iter().map(|f| &f.file).collect();
        files.dedup();
        for file in files {
            let lines: Vec<usize> = adopted
                .iter()
                .filter(|f| &f.file == file)
                .map(|f| f.line)
                .collect();
            let result = std::fs::read_to_string(file)
                .and_then(|t| std::fs::write(file, remove_lines(&t, &lines)));
            match result {
                Ok(()) => cli_ui::ok(&format!(
                    "removed {} line(s) from {}",
                    lines.len(),
                    file.display()
                )),
                Err(e) => cli_ui::err(&format!("{}: {e}", file.display())),
            }
        }
    } else {
        cli_ui::warn("the plaintext lines are still in place; delete them or re-run with --remove");
    }
    Response::Pong
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_forms() {
        assert_eq!(
            parse_line("OPENAI_API_KEY=sk-abc"),
            Some(("OPENAI_API_KEY".into(), "sk-abc".into()))
        );
        assert_eq!(
            parse_line("export ANTHROPIC_API_KEY=\"sk-ant-x\""),
            Some(("ANTHROPIC_API_KEY".into(), "sk-ant-x".into()))
        );
        assert_eq!(
            parse_line("  export K='v v'"),
            Some(("K".into(), "v v".into()))
        );
        assert_eq!(
            parse_line("set -gx XAI_API_KEY xai-123"),
            Some(("XAI_API_KEY".into(), "xai-123".into()))
        );
        assert_eq!(parse_line("# OPENAI_API_KEY=sk-abc"), None);
        assert_eq!(parse_line("echo hi"), None);
        assert_eq!(parse_line("BAD-NAME=sk-x"), None);
        assert_eq!(
            parse_line("K=sk-x # comment"),
            Some(("K".into(), "sk-x".into()))
        );
    }

    #[test]
    fn scan_finds_only_known_prefixes() {
        let text = "A=1\nexport ANTHROPIC_API_KEY=sk-ant-api03-zzz\nDB=postgres://x\nXAI=xai-abc\n";
        let f = scan_text(Path::new(".env"), text);
        let got: Vec<(usize, &str, &str)> = f
            .iter()
            .map(|x| (x.line, x.name.as_str(), x.provider))
            .collect();
        assert_eq!(
            got,
            vec![(2, "ANTHROPIC_API_KEY", "anthropic"), (4, "XAI", "xai")]
        );
    }

    #[test]
    fn remove_lines_keeps_the_rest() {
        assert_eq!(remove_lines("a\nb\nc\n", &[2]), "a\nc\n");
        assert_eq!(remove_lines("a\nb", &[2]), "a");
        assert_eq!(remove_lines("a\nb\nc", &[1, 3]), "b");
    }
}
