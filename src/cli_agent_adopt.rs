// cli_agent_adopt.rs — `kepr agent adopt [FILE...] [--yes] [--remove]`
// (agent vault T1.20). Finds API keys already sitting in .env files and
// shell startup files, imports them as sealed credentials, and
// optionally deletes the plaintext lines.
//
// Only values with a recognised provider prefix are adopted (see
// kepr_core::providers::detect). Values are never printed. `--remove`
// rewrites files without keeping a plaintext backup (a backup would
// leave the key on disk, which is what adoption is meant to end).
// Agent harness config files (JSON / YAML) are read by key through
// cli_agent_adopt_harness.rs (T12.18) and never rewritten; shell history
// through cli_agent_adopt_history.rs (T12.19). `--remove` is in
// cli_agent_adopt_remove.rs.

use std::path::{Path, PathBuf};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use zeroize::Zeroizing;

use crate::cli_agent_adopt_history::{is_history_file, scan_history};
use crate::cli_agent_adopt_remove::remove_adopted;
use crate::{cli_agent_detect, cli_ui, client};

pub struct Found {
    pub file: PathBuf,
    pub line: usize,
    pub name: String,
    pub provider: &'static str,
    pub value: ZeroString,
    /// The key in a structured file (T12.18); None for line-based files.
    pub key: Option<String>,
}

/// `file:line`, or `file (key)` for a key in a JSON file (line 0).
pub fn place(f: &Found) -> String {
    match (&f.key, f.line) {
        (Some(k), 0) => format!("{} ({k})", f.file.display()),
        _ => format!("{}:{}", f.file.display(), f.line),
    }
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
        v.extend(
            crate::cli_agent_adopt_harness::HARNESS_FILES
                .iter()
                .map(|f| home.join(f)),
        );
        let env = |k: &str| std::env::var(k).ok();
        v.extend(crate::cli_agent_adopt_history::history_files(&home, &env));
    }
    v
}

/// A value written out in full: not `$VAR`, `$(…)`, `` `…` ``, a
/// half-quoted word or several words.
pub fn literal(v: &str) -> bool {
    !v.chars()
        .any(|c| c.is_whitespace() || "$`'\"(){}<>;|&\\".contains(c))
}

pub fn unquote(v: &str) -> &str {
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
            let mut value = Zeroizing::new(value);
            if !literal(&value) {
                return None;
            }
            let provider = kepr_core::providers::detect(Some(&name), &value)?.name;
            Some(Found {
                file: file.to_path_buf(),
                line: i + 1,
                name,
                provider,
                value: ZeroString::from_string(std::mem::take(&mut *value)),
                key: None,
            })
        })
        .collect()
}

/// Read one file the way its kind needs: a history file even when it is
/// not UTF-8 (zsh), any other file only when it is.
pub fn scan_file(p: &Path, history: bool) -> Vec<Found> {
    let Ok(bytes) = std::fs::read(p).map(Zeroizing::new) else {
        return Vec::new();
    };
    if history {
        let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
        return scan_history(p, &text);
    }
    match std::str::from_utf8(&bytes) {
        Ok(t) if crate::cli_agent_adopt_harness::is_structured(p) => {
            crate::cli_agent_adopt_harness::scan_structured(p, t)
        }
        Ok(t) => scan_text(p, t),
        Err(_) => Vec::new(),
    }
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

/// What adoption will do: one representative per NAME to store, every
/// source line to delete, and NAMEs skipped with the reason.
pub struct Plan<'a> {
    pub store: Vec<&'a Found>,
    pub remove: Vec<(PathBuf, usize)>,
    pub skipped: Vec<(String, String)>,
}

/// Group findings by NAME. A NAME found with different values in
/// different places, or already stored in kepr, is skipped rather than
/// silently overwritten.
pub fn plan<'a>(
    found: &'a [Found],
    existing: &std::collections::HashSet<String>,
    canaries: &crate::cli_policy::Canaries,
) -> Plan<'a> {
    let mut p = Plan {
        store: Vec::new(),
        remove: Vec::new(),
        skipped: Vec::new(),
    };
    let mut names: Vec<&str> = found.iter().map(|f| f.name.as_str()).collect();
    names.sort();
    names.dedup();
    for name in names {
        let group: Vec<&Found> = found.iter().filter(|f| f.name == name).collect();
        if group.iter().any(|f| canaries.contains(f.value.as_str())) {
            p.skipped
                .push((name.into(), crate::cli_policy::CANARY_SKIP.into()));
        } else if existing.contains(name) {
            p.skipped.push((
                name.into(),
                "already in kepr (use `kepr agent add` to replace it)".into(),
            ));
        } else if group
            .iter()
            .any(|f| f.value.as_str() != group[0].value.as_str())
        {
            let places: Vec<String> = group.iter().map(|f| place(f)).collect();
            p.skipped.push((
                name.into(),
                format!(
                    "different values at {}; adopt one with `kepr agent add`",
                    places.join(", ")
                ),
            ));
        } else {
            p.store.push(group[0]);
            p.remove
                .extend(group.iter().map(|f| (f.file.clone(), f.line)));
        }
    }
    p
}

fn existing_names() -> std::collections::HashSet<String> {
    match client::send_request(&Request::List) {
        Ok(Response::ListOk { credentials, .. }) => {
            credentials.into_iter().map(|c| c.name).collect()
        }
        _ => Default::default(),
    }
}

pub fn cmd_adopt(files: &[String], yes: bool, remove: bool) -> Response {
    let requested: Vec<PathBuf> = if files.is_empty() {
        default_files()
    } else {
        files.iter().map(PathBuf::from).collect()
    };
    // Canonical, de-duplicated: the same file under two spellings must be
    // scanned (and rewritten) once, or line numbers would go stale.
    let mut paths: Vec<PathBuf> = requested
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();
    paths.sort();
    paths.dedup();
    let known = crate::cli_agent_adopt_history::known_files();
    let is_history = |p: &Path| is_history_file(p, &known);
    let found: Vec<Found> = paths
        .iter()
        .flat_map(|p| scan_file(p, is_history(p)))
        .collect();
    if found.is_empty() {
        cli_ui::info("no provider API keys found in the scanned files");
        return Response::Pong;
    }
    for f in &found {
        println!("{}  {}  ({})", place(f), f.name, f.provider);
    }
    let plan = plan(
        &found,
        &existing_names(),
        &crate::cli_policy::Canaries::planted(),
    );
    for (name, why) in &plan.skipped {
        cli_ui::warn(&format!("skipping {name}: {why}"));
    }
    if !yes {
        cli_ui::info("re-run with --yes to import these as sealed keys (add --remove to delete the plaintext lines)");
        return Response::Pong;
    }
    let mut stored: Vec<&str> = Vec::new();
    for f in &plan.store {
        match store(f) {
            Ok(()) => stored.push(&f.name),
            Err(e) => cli_ui::err(&format!("{}: {e}", f.name)),
        }
    }
    cli_ui::ok(&format!(
        "adopted {} key(s) as sealed credentials",
        stored.len()
    ));
    if !remove {
        cli_ui::warn("the plaintext lines are still in place; delete them or re-run with --remove");
        return Response::Pong;
    }
    let rewritten = remove_adopted(&paths, &plan, &found, &stored);
    if rewritten.iter().any(|p| is_history(p)) {
        cli_ui::warn(crate::cli_agent_adopt_history::REMOVE_WARNING);
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
    fn plan_skips_conflicts_and_existing() {
        let a = scan_text(
            Path::new("a"),
            "ANTHROPIC_API_KEY=sk-ant-AAA\nXAI_API_KEY=xai-1\nOPENAI_API_KEY=sk-proj-1\n",
        );
        let b = scan_text(
            Path::new("b"),
            "ANTHROPIC_API_KEY=sk-ant-BBB\nXAI_API_KEY=xai-1\n",
        );
        let found: Vec<Found> = a.into_iter().chain(b).collect();
        let existing: std::collections::HashSet<String> = ["OPENAI_API_KEY".to_string()].into();
        let p = plan(&found, &existing, &Default::default());
        let stored: Vec<&str> = p.store.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(stored, vec!["XAI_API_KEY"]);
        assert_eq!(p.remove.len(), 2, "same value in two files: both lines go");
        let skipped: Vec<&str> = p.skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(skipped, vec!["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]);
        // A planted canary is neither stored nor removed from its file.
        let decoy = crate::cli_policy::Canaries::of(&["xai-1"]);
        let p = plan(&found, &existing, &decoy);
        assert!(p.store.is_empty() && p.remove.is_empty());
        assert!(p
            .skipped
            .iter()
            .any(|(n, why)| n == "XAI_API_KEY" && why.contains("canary")));
    }

    #[test]
    fn plan_skips_stored_and_canary_keys_from_harness_files() {
        use crate::cli_agent_adopt_harness::scan_structured;
        let found = scan_structured(
            Path::new("auth.json"),
            r#"{"OPENAI_API_KEY": "sk-proj-abcdefghijkl", "x": {"apiKey": "xai-abcdefghijkl"}}"#,
        );
        assert_eq!(found.len(), 2);
        assert_eq!(place(&found[0]), "auth.json (OPENAI_API_KEY)");
        let existing: std::collections::HashSet<String> = ["OPENAI_API_KEY".to_string()].into();
        let decoy = crate::cli_policy::Canaries::of(&["xai-abcdefghijkl"]);
        let p = plan(&found, &existing, &decoy);
        assert!(p.store.is_empty() && p.remove.is_empty());
        let why: Vec<&str> = p.skipped.iter().map(|(_, w)| w.as_str()).collect();
        assert!(
            why.iter().any(|w| w.contains("canary")) && why.iter().any(|w| w.contains("already"))
        );
    }

    #[test]
    fn values_that_are_not_written_out_are_left_alone() {
        let text = "export OPENAI_API_KEY=$(pass show openai)\nXAI_API_KEY=\"$XAI\"\n\
                    ANTHROPIC_API_KEY=`cat k`\n";
        assert!(scan_text(Path::new(".bashrc"), text).is_empty());
        assert!(literal("sk-proj-abc_DEF.1/2+3="));
        assert!(!literal("${X}") && !literal("'half") && !literal("a b"));
    }
}
