// cli_agent_plugin.rs — the omp extension and the Grok Build plugin
// (plugins/omp/kepr, plugins/grok/kepr), embedded in the binary so
// `kepr agent install omp|grok` writes the copy that matches this kepr.
// Both call `kepr hook` (cli_hook.rs) for their policy.
//
// Install locations follow each harness's rules (checked against omp
// 18.6 and grok 1.0.46):
//   omp:  ~/.omp/agent/extensions/kepr/, auto-discovered
//         (package.json `omp.extensions`)
//   grok: source in ~/.local/share/kepr/plugins/grok/kepr/, registered
//         with `grok plugin install DIR --trust` (grok keeps its own
//         copy, so a changed source needs `grok plugin update kepr`)

use std::path::{Path, PathBuf};

type Files = &'static [(&'static str, &'static str)];

const OMP: Files = &[
    (
        "package.json",
        include_str!("../plugins/omp/kepr/package.json"),
    ),
    ("index.ts", include_str!("../plugins/omp/kepr/index.ts")),
];

const GROK: Files = &[
    (
        ".grok-plugin/plugin.json",
        include_str!("../plugins/grok/kepr/.grok-plugin/plugin.json"),
    ),
    (
        "hooks/hooks.json",
        include_str!("../plugins/grok/kepr/hooks/hooks.json"),
    ),
    (".mcp.json", include_str!("../plugins/grok/kepr/.mcp.json")),
    ("skills/kepr/SKILL.md", SKILL),
];

/// kepr's guidance for the model, harness-neutral: Grok Build's skill,
/// Claude Code's skill and Codex's AGENTS.md block all come from it (T12.15).
pub const SKILL: &str = include_str!("../plugins/grok/kepr/skills/kepr/SKILL.md");

const BEGIN: &str = "<!-- kepr:begin -->";
const END: &str = "<!-- kepr:end -->";

/// Where `kepr agent install claude|codex` puts the guidance.
pub fn guidance_path(
    harness: &str,
    home: &Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    let base = |var: &str, default: &str| {
        env(var)
            .filter(|v| !v.is_empty())
            .map_or_else(|| home.join(default), PathBuf::from)
    };
    match harness {
        "claude" => Some(base("CLAUDE_CONFIG_DIR", ".claude").join("skills/kepr/SKILL.md")),
        "codex" => Some(base("CODEX_HOME", ".codex").join("AGENTS.md")),
        _ => None,
    }
}

/// Byte range of the first line at or after `from` that is `marker`.
fn marker_line(text: &str, marker: &str, from: usize) -> Option<(usize, usize)> {
    let mut at = from;
    for line in text[from..].split_inclusive('\n') {
        if line.trim_end() == marker {
            return Some((at, at + line.len()));
        }
        at += line.len();
    }
    None
}

/// `text` with kepr's block (between the begin and end markers) set to
/// `body`: replaced in place, or appended. Text outside it is untouched.
pub fn upsert_block(text: &str, body: &str) -> String {
    let block = format!("{BEGIN}\n{}\n{END}\n", body.trim_end());
    let span = marker_line(text, BEGIN, 0)
        .and_then(|(b, e)| marker_line(text, END, e).map(|(_, end)| (b, end)));
    if let Some((b, e)) = span {
        return format!("{}{block}{}", &text[..b], &text[e..]);
    }
    let sep = match text {
        "" => "",
        t if t.ends_with("\n\n") => "",
        t if t.ends_with('\n') => "\n",
        _ => "\n\n",
    };
    format!("{text}{sep}{block}")
}

/// SKILL without its `---` front matter (for AGENTS.md).
fn skill_body() -> &'static str {
    SKILL
        .strip_prefix("---\n")
        .and_then(|s| s.split_once("\n---\n"))
        .map_or(SKILL, |(_, body)| body.trim_start())
}

/// Write the guidance for `harness` through `cli_agent_install::apply`
/// (timestamped 0600 backup, idempotent). None: no guidance for it.
pub fn install_guidance(
    harness: &str,
    home: &Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<(PathBuf, bool)>, String> {
    let Some(path) = guidance_path(harness, home, env) else {
        return Ok(None);
    };
    let changed = match harness {
        "codex" => crate::cli_agent_install::apply(&path, |t| upsert_block(t, skill_body())),
        _ => crate::cli_agent_install::apply(&path, |_| SKILL.to_string()),
    }?;
    Ok(Some((path, changed)))
}

/// (directory under HOME, files) for a harness with a plugin.
pub fn plugin_for(harness: &str) -> Option<(&'static str, Files)> {
    match harness {
        "omp" => Some((".omp/agent/extensions/kepr", OMP)),
        "grok" => Some((".local/share/kepr/plugins/grok/kepr", GROK)),
        _ => None,
    }
}

/// Write the plugin into `dir`; true when any file changed. The
/// directory is kepr's own, so files are replaced, not merged.
pub fn write_plugin(dir: &Path, files: Files) -> Result<bool, String> {
    let mut changed = false;
    for (rel, body) in files {
        let path = dir.join(rel);
        if std::fs::read_to_string(&path).ok().as_deref() == Some(*body) {
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
        changed = true;
    }
    Ok(changed)
}

pub fn install(harness: &str, home: &Path) -> Result<Option<(PathBuf, bool)>, String> {
    let Some((rel, files)) = plugin_for(harness) else {
        return Ok(None);
    };
    let dir = home.join(rel);
    let changed = write_plugin(&dir, files)?;
    if harness == "grok" {
        register_with_grok(&dir, changed)?;
    }
    Ok(Some((dir, changed)))
}

fn grok(args: &[&str]) -> Result<std::process::Output, String> {
    std::process::Command::new("grok")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| e.to_string())
}

/// `grok plugin install DIR --trust` the first time, `grok plugin update
/// kepr` after a change. Without grok on PATH, say what to run.
fn register_with_grok(dir: &Path, changed: bool) -> Result<(), String> {
    let installed = match grok(&["plugin", "list", "--json"]) {
        Ok(o) => serde_json::from_slice::<Vec<serde_json::Value>>(&o.stdout)
            .unwrap_or_default()
            .iter()
            .any(|p| p["name"] == "kepr"),
        Err(_) => {
            crate::cli_ui::info(&format!(
                "grok not found on PATH; afterwards run: grok plugin install {} --trust",
                dir.display()
            ));
            return Ok(());
        }
    };
    let out = match (installed, changed) {
        (true, false) => return Ok(()),
        (true, true) => grok(&["plugin", "update", "kepr"])?,
        (false, _) => grok(&["plugin", "install", &dir.to_string_lossy(), "--trust"])?,
    };
    if out.status.success() && !String::from_utf8_lossy(&out.stdout).contains("Error") {
        return Ok(());
    }
    Err(format!(
        "grok plugin install failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_are_valid_json_and_hooks_call_kepr() {
        for (_, files) in [plugin_for("omp").unwrap(), plugin_for("grok").unwrap()] {
            for (rel, body) in files {
                if rel.ends_with(".json") {
                    serde_json::from_str::<serde_json::Value>(body)
                        .unwrap_or_else(|e| panic!("{rel}: {e}"));
                }
            }
        }
        let pkg: serde_json::Value = serde_json::from_str(OMP[0].1).unwrap();
        assert_eq!(pkg["omp"]["extensions"][0], "./index.ts");
        let hooks: serde_json::Value = serde_json::from_str(GROK[1].1).unwrap();
        for (event, verb) in [("UserPromptSubmit", "prompt"), ("PreToolUse", "pre-tool")] {
            let cmd = hooks["hooks"][event][0]["hooks"][0]["command"]
                .as_str()
                .unwrap();
            assert_eq!(cmd, format!("kepr hook {verb}"));
        }
        assert!(GROK[3].1.starts_with("---\nname: kepr\ndescription: "));
        assert!(plugin_for("claude").is_none());
    }

    const B: &str = "<!-- kepr:begin -->";
    const E: &str = "<!-- kepr:end -->";

    #[test]
    fn upsert_block_appends_replaces_and_is_idempotent() {
        let fresh = upsert_block("", "rules\n");
        assert_eq!(fresh, format!("{B}\nrules\n{E}\n"));
        assert_eq!(upsert_block(&fresh, "rules"), fresh);
        let user = "# Mine\n\nbe terse\n";
        let added = upsert_block(user, "rules");
        assert_eq!(added, format!("{user}\n{B}\nrules\n{E}\n"));
        assert_eq!(upsert_block(&added, "rules"), added);
        assert_eq!(
            upsert_block("no newline", "r"),
            format!("no newline\n\n{B}\nr\n{E}\n")
        );
        let around = format!("top\n{B}\nold rules\nmore old\n{E}\nbottom\n");
        let replaced = upsert_block(&around, "new rules");
        assert_eq!(replaced, format!("top\n{B}\nnew rules\n{E}\nbottom\n"));
        assert_eq!(upsert_block(&replaced, "new rules"), replaced);
    }

    #[test]
    fn guidance_paths_honour_the_harness_variables() {
        let home = Path::new("/h");
        let none = |_: &str| None;
        assert_eq!(
            guidance_path("claude", home, &none).unwrap(),
            Path::new("/h/.claude/skills/kepr/SKILL.md")
        );
        assert_eq!(
            guidance_path("codex", home, &none).unwrap(),
            Path::new("/h/.codex/AGENTS.md")
        );
        let env = |k: &str| match k {
            "CLAUDE_CONFIG_DIR" => Some("/c".to_string()),
            "CODEX_HOME" => Some("/x".to_string()),
            _ => None,
        };
        assert_eq!(
            guidance_path("claude", home, &env).unwrap(),
            Path::new("/c/skills/kepr/SKILL.md")
        );
        assert_eq!(
            guidance_path("codex", home, &env).unwrap(),
            Path::new("/x/AGENTS.md")
        );
        assert!(guidance_path("omp", home, &env).is_none());
    }

    #[test]
    fn installs_guidance_for_claude_and_codex() {
        let home = std::env::temp_dir().join(format!("kepr-guide-{}", std::process::id()));
        let none = |_: &str| None;
        let (path, changed) = install_guidance("claude", &home, &none).unwrap().unwrap();
        assert!(changed);
        assert_eq!(path, home.join(".claude/skills/kepr/SKILL.md"));
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, SKILL);
        assert!(written.starts_with("---\nname: kepr\n"));
        assert!(!install_guidance("claude", &home, &none).unwrap().unwrap().1);
        let agents = home.join(".codex/AGENTS.md");
        std::fs::create_dir_all(agents.parent().unwrap()).unwrap();
        std::fs::write(&agents, "# my rules\n").unwrap();
        install_guidance("codex", &home, &none).unwrap();
        let text = std::fs::read_to_string(&agents).unwrap();
        assert!(text.starts_with("# my rules\n\n<!-- kepr:begin -->\n# Working with secrets"));
        assert!(!text.contains("name: kepr") && text.contains("kepr leaked NAME"));
        assert!(!install_guidance("codex", &home, &none).unwrap().unwrap().1);
        assert!(install_guidance("aider", &home, &none).unwrap().is_none());
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn skill_is_one_source_and_harness_neutral() {
        assert_eq!(GROK[3], ("skills/kepr/SKILL.md", SKILL));
        assert!(SKILL.contains("kepr agent run <harness>"));
        assert!(!SKILL.contains("kepr agent run grok"));
    }

    #[test]
    fn writes_once_then_reports_unchanged() {
        let dir = std::env::temp_dir().join(format!("kepr-plugin-test-{}", std::process::id()));
        assert!(write_plugin(&dir, GROK).unwrap());
        assert!(!write_plugin(&dir, GROK).unwrap());
        assert!(dir.join(".grok-plugin/plugin.json").is_file());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
