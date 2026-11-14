// cli_repo_policy.rs — repository privacy policy loader and restricted-repo
// detector across all coding agents.

use std::path::{Path, PathBuf};

pub const DEFAULT_POLICY_YAML: &str = include_str!("../plugins/privacy-policy.yaml");

const STRICT_MARKERS: &[&str] = &[
    ".kepr-strict",
    ".privacy-strict",
    ".agent-strict",
    ".omp-strict",
    ".git/kepr-strict",
    ".git/privacy-strict",
    ".git/agent-strict",
    ".git/omp-strict",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyPolicy {
    pub strict: bool,
    pub allowed_providers: Vec<String>,
    pub restricted_repos: Vec<String>,
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        parse_policy(DEFAULT_POLICY_YAML)
    }
}

pub(crate) fn clean_yaml_scalar(raw: &str) -> String {
    let s = raw.trim();
    let s = match s.find('#') {
        Some(i) if !s.starts_with(['"', '\'']) => &s[..i],
        _ => s,
    };
    s.trim()
        .trim_matches(['"', '\''])
        .trim()
        .to_ascii_lowercase()
}

pub fn parse_policy(yaml: &str) -> PrivacyPolicy {
    let (mut strict, mut allowed, mut repos, mut sec) = (true, Vec::new(), Vec::new(), "");
    for line in yaml
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if let Some(rest) = line.strip_prefix("strict:") {
            strict = !matches!(clean_yaml_scalar(rest).as_str(), "false" | "0" | "no");
            sec = "";
        } else if line.starts_with("allowed_providers:") {
            sec = "allowed";
        } else if line.starts_with("restricted_repos:") {
            sec = "repos";
        } else if let Some(item) = line.strip_prefix('-') {
            let val = clean_yaml_scalar(item);
            if !val.is_empty() {
                match sec {
                    "allowed" if !allowed.contains(&val) => allowed.push(val),
                    "repos" if !repos.contains(&val) => repos.push(val),
                    _ => {}
                }
            }
        } else if line.contains(':') {
            sec = "";
        }
    }
    if (allowed.is_empty() || repos.is_empty()) && yaml != DEFAULT_POLICY_YAML {
        let fb = parse_policy(DEFAULT_POLICY_YAML);
        if allowed.is_empty() {
            allowed = fb.allowed_providers;
        }
        if repos.is_empty() {
            repos = fb.restricted_repos;
        }
    }
    PrivacyPolicy {
        strict,
        allowed_providers: allowed,
        restricted_repos: repos,
    }
}

pub fn policy_search_paths(
    home: Option<&Path>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(p) = env("KEPR_PRIVACY_POLICY").filter(|s| !s.is_empty()) {
        paths.push(PathBuf::from(p));
    }
    if let Some(xdg) = env("XDG_CONFIG_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
    {
        paths.push(xdg.join("kepr/privacy-policy.yaml"));
        paths.push(xdg.join("omp/agent/privacy-policy.yaml"));
    }
    for var in ["PI_CODING_AGENT_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME"] {
        if let Some(d) = env(var).filter(|s| !s.is_empty()) {
            paths.push(PathBuf::from(d).join("privacy-policy.yaml"));
        }
    }
    if let Some(h) = home {
        for rel in [
            ".config/kepr/privacy-policy.yaml",
            ".config/omp/agent/privacy-policy.yaml",
            ".config/pi/agent/privacy-policy.yaml",
            ".pi/agent/privacy-policy.yaml",
            ".claude/privacy-policy.yaml",
            ".codex/privacy-policy.yaml",
        ] {
            paths.push(h.join(rel));
        }
    }
    paths
}

pub fn load_policy() -> PrivacyPolicy {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    policy_search_paths(home.as_deref(), &|k| std::env::var(k).ok())
        .into_iter()
        .find_map(|p| std::fs::read_to_string(p).ok().map(|s| parse_policy(&s)))
        .unwrap_or_default()
}

fn git_config_path(repo_root: &Path) -> PathBuf {
    let dot_git = repo_root.join(".git");
    if let Ok(text) = std::fs::read_to_string(&dot_git) {
        if let Some(dir) = text.trim().strip_prefix("gitdir:") {
            let p = Path::new(dir.trim());
            let base = if p.is_absolute() {
                p.to_path_buf()
            } else {
                repo_root.join(p)
            };
            return base.join("config");
        }
    }
    dot_git.join("config")
}

fn repo_label(dir: &Path) -> String {
    dir.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| dir.display().to_string())
}

fn inspect_git_config(repo_root: &Path, policy: &PrivacyPolicy) -> Option<String> {
    let text = std::fs::read_to_string(git_config_path(repo_root)).ok()?;
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (key, val) = (k.trim().to_ascii_lowercase(), clean_yaml_scalar(v));
        if matches!(section.as_str(), "kepr" | "privacy" | "agent" | "omp")
            && matches!(key.as_str(), "privacy" | "strict")
            && matches!(val.as_str(), "strict" | "true" | "1" | "yes")
        {
            return Some(repo_label(repo_root));
        }
        if section.starts_with("remote ") && key == "url" {
            let trimmed = val.trim_end_matches('/');
            let slug = trimmed
                .strip_suffix(".git")
                .unwrap_or(trimmed)
                .rsplit(['/', ':'])
                .next()?;
            if policy.restricted_repos.iter().any(|r| r == slug) {
                return Some(slug.to_string());
            }
        }
    }
    None
}

pub fn is_restricted_repo(cwd: &Path, policy: &PrivacyPolicy) -> Option<String> {
    if !policy.strict {
        return None;
    }
    for dir in cwd.ancestors() {
        if STRICT_MARKERS.iter().any(|m| dir.join(m).exists()) {
            return Some(repo_label(dir));
        }
        let folder = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let full = dir.to_string_lossy().to_ascii_lowercase();
        if policy.restricted_repos.iter().any(|r| {
            let r = r.trim_end_matches('/');
            !r.is_empty() && (folder == r || full == r || full.ends_with(&format!("/{r}")))
        }) {
            return Some(repo_label(dir));
        }
        if dir.join(".git").exists() {
            return inspect_git_config(dir, policy);
        }
    }
    None
}
