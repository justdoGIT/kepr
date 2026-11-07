// cli_agent_plugin.rs — the omp extension and the Grok Build plugin
// (plugins/omp/kepr, plugins/grok/kepr), embedded in the binary so
// `kepr agent install omp|grok` writes the copy that matches this kepr.
// Both call `kepr hook` (cli_hook.rs) for their policy.
//
// Install locations follow each harness's rules (checked against omp
// 18.6 and grok 1.0.46):
//   omp:  ~/.config/omp/agent/extensions/kepr/, auto-discovered
//         (package.json `omp.extensions`)
//   grok: source in ~/.local/share/kepr/plugins/grok/kepr/, registered
//         with `grok plugin install DIR --trust` (grok keeps its own
//         copy, so a changed source needs `grok plugin update kepr`)

use std::path::{Path, PathBuf};

pub type Files = &'static [(&'static str, &'static str)];

const OMP: Files = &[
    (
        "package.json",
        include_str!("../plugins/omp/kepr/package.json"),
    ),
    ("index.ts", include_str!("../plugins/omp/kepr/index.ts")),
    (
        "providers.ts",
        include_str!("../plugins/omp/kepr/providers.ts"),
    ),
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
        // T13.07: both tools read project files, so for these two `home` is
        // the project directory (the current one).
        "cursor" => Some(home.join(".cursor/rules/kepr.mdc")),
        "copilot" => Some(home.join(".github/copilot-instructions.md")),
        _ => None,
    }
}

/// Byte range of kepr's block: the first end marker line and the last
/// begin marker line above it, so a stray begin marker stays user text.
fn block_span(text: &str) -> Option<(usize, usize)> {
    let (mut at, mut begin) = (0, None);
    for line in text.split_inclusive('\n') {
        match line.trim_end() {
            BEGIN => begin = Some(at),
            END if begin.is_some() => return begin.map(|b| (b, at + line.len())),
            _ => {}
        }
        at += line.len();
    }
    None
}

/// `text` with kepr's block (between the begin and end markers) set to
/// `body`: replaced in place, or appended. Text outside it is untouched.
pub fn upsert_block(text: &str, body: &str) -> String {
    let block = format!("{BEGIN}\n{}\n{END}\n", body.trim_end());
    if let Some((b, e)) = block_span(text) {
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

/// Cursor's project rule: always applied, kepr's guidance as the body.
fn cursor_rule() -> String {
    format!(
        "---\ndescription: Secrets are already wired in by kepr; never ask for or print them\nalwaysApply: true\n---\n{}",
        skill_body()
    )
}

/// Fail if `path`, or any directory between `root` and it, is a symlink: a
/// repository can plant `.github/copilot-instructions.md -> ~/.bashrc`, and
/// writing guidance through it would overwrite a file outside the project.
pub fn refuse_links(root: &Path, path: &Path) -> Result<(), String> {
    let below = path.strip_prefix(root).unwrap_or(path);
    let mut at = root.to_path_buf();
    for part in below.components() {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!(
                    "{} is a symbolic link; kepr will not write project files through one",
                    at.display()
                ))
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(format!("{}: {e}", at.display())),
        }
    }
    Ok(())
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
    // Project files come from a checkout that may not be ours; the other
    // harnesses' files are the user's own (dotfile managers link those).
    if matches!(harness, "cursor" | "copilot") {
        refuse_links(home, &path)?;
    }
    let changed = match harness {
        "codex" | "copilot" => {
            crate::cli_agent_install::apply(&path, |t| upsert_block(t, skill_body()))
        }
        "cursor" => crate::cli_agent_install::apply(&path, |_| cursor_rule()),
        _ => crate::cli_agent_install::apply(&path, |_| SKILL.to_string()),
    }?;
    Ok(Some((path, changed)))
}

/// (directory under HOME, files) for a harness with a plugin.
pub fn plugin_for(harness: &str) -> Option<(&'static str, Files)> {
    match harness {
        "omp" => Some((".config/omp/agent/extensions/kepr", OMP)),
        "grok" => Some((".local/share/kepr/plugins/grok/kepr", GROK)),
        _ => None,
    }
}
pub fn plugin_path(
    harness: &str,
    home: &Path,
    agent_dir: Option<std::ffi::OsString>,
    xdg: Option<std::ffi::OsString>,
) -> Option<(PathBuf, Files)> {
    let (rel, files) = plugin_for(harness)?;
    let path = if harness == "omp" {
        crate::cli_agent_install::omp_agent_dir(home, agent_dir, xdg).join("extensions/kepr")
    } else {
        home.join(rel)
    };
    Some((path, files))
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
    let Some((dir, files)) = plugin_path(
        harness,
        home,
        std::env::var_os("PI_CODING_AGENT_DIR"),
        std::env::var_os("XDG_CONFIG_HOME"),
    ) else {
        return Ok(None);
    };
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    Missing,
    Stale,
    Current,
}

/// How the plugin in `dir` compares with the embedded files, byte for
/// byte (T12.16): none there, some differ or are missing, or all equal.
pub fn plugin_state(dir: &Path, files: Files) -> PluginState {
    let same: Vec<Option<bool>> = files
        .iter()
        .map(|(rel, body)| {
            std::fs::read(dir.join(rel))
                .ok()
                .map(|b| b == body.as_bytes())
        })
        .collect();
    if same.iter().all(|s| *s == Some(true)) {
        PluginState::Current
    } else if same.iter().all(Option::is_none) {
        PluginState::Missing
    } else {
        PluginState::Stale
    }
}

/// Whether `grok plugin list --json` lists kepr; None when grok can't run.
pub fn grok_lists_kepr() -> Option<bool> {
    let o = grok(&["plugin", "list", "--json"]).ok()?;
    let list = serde_json::from_slice::<Vec<serde_json::Value>>(&o.stdout).unwrap_or_default();
    Some(list.iter().any(|p| p["name"] == "kepr"))
}

/// `grok plugin install DIR --trust` the first time, `grok plugin update
/// kepr` after a change. Without grok on PATH, say what to run.
fn register_with_grok(dir: &Path, changed: bool) -> Result<(), String> {
    let installed = match grok_lists_kepr() {
        Some(listed) => listed,
        None => {
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
        // A stray begin marker (no end) stays user text, on every run.
        let stray = format!("top\n{B}\nmine\n");
        let once = upsert_block(&stray, "r");
        assert_eq!(once, format!("{stray}\n{B}\nr\n{E}\n"));
        assert_eq!(upsert_block(&once, "r"), once);
        assert_eq!(
            upsert_block(&once, "r2"),
            format!("{stray}\n{B}\nr2\n{E}\n")
        );
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
    fn plugin_state_compares_bytes_with_the_embedded_files() {
        let dir = std::env::temp_dir().join(format!("kepr-pstate-{}", std::process::id()));
        assert_eq!(plugin_state(&dir, OMP), PluginState::Missing);
        write_plugin(&dir, OMP).unwrap();
        assert_eq!(plugin_state(&dir, OMP), PluginState::Current);
        std::fs::write(dir.join("index.ts"), "// older\n").unwrap();
        assert_eq!(plugin_state(&dir, OMP), PluginState::Stale);
        std::fs::remove_file(dir.join("index.ts")).unwrap();
        assert_eq!(plugin_state(&dir, OMP), PluginState::Stale);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn writes_once_then_reports_unchanged() {
        let dir = std::env::temp_dir().join(format!("kepr-plugin-test-{}", std::process::id()));
        assert!(write_plugin(&dir, GROK).unwrap());
        assert!(!write_plugin(&dir, GROK).unwrap());
        assert!(dir.join(".grok-plugin/plugin.json").is_file());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn project_guidance_is_never_written_through_a_symlink() {
        use std::os::unix::fs::symlink;
        let none = |_: &str| None;
        let proj = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        let target = victim.path().join("bashrc");
        std::fs::write(&target, "export A=1\n").unwrap();
        // The file itself is a link out of the project.
        std::fs::create_dir_all(proj.path().join(".github")).unwrap();
        symlink(&target, proj.path().join(".github/copilot-instructions.md")).unwrap();
        let e = install_guidance("copilot", proj.path(), &none).unwrap_err();
        assert!(e.contains("symbolic link"), "{e}");
        // A directory on the way is a link out of the project.
        symlink(victim.path(), proj.path().join(".cursor")).unwrap();
        let e = install_guidance("cursor", proj.path(), &none).unwrap_err();
        assert!(e.contains("symbolic link"), "{e}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "export A=1\n");
        assert_eq!(std::fs::read_dir(victim.path()).unwrap().count(), 1);
        // The user's own files may be links (dotfile managers do that).
        let home = tempfile::tempdir().unwrap();
        let real = victim.path().join("AGENTS.md");
        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        symlink(&real, home.path().join(".codex/AGENTS.md")).unwrap();
        assert!(install_guidance("codex", home.path(), &none).is_ok());
    }

    #[test]
    fn cursor_and_copilot_guidance_goes_in_the_project() {
        let none = |_: &str| None;
        let proj = Path::new("/p");
        assert_eq!(
            guidance_path("cursor", proj, &none).unwrap(),
            Path::new("/p/.cursor/rules/kepr.mdc")
        );
        assert_eq!(
            guidance_path("copilot", proj, &none).unwrap(),
            Path::new("/p/.github/copilot-instructions.md")
        );
        let dir = tempfile::tempdir().unwrap();
        let (path, changed) = install_guidance("cursor", dir.path(), &none)
            .unwrap()
            .unwrap();
        assert!(changed);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("---\ndescription:") && text.contains("alwaysApply: true\n---\n"));
        assert!(text.contains(skill_body().lines().next().unwrap()));
        // Again: nothing changes.
        assert!(
            !install_guidance("cursor", dir.path(), &none)
                .unwrap()
                .unwrap()
                .1
        );
        // Copilot: the user's own instructions are kept around kepr's block.
        let c = dir.path().join(".github/copilot-instructions.md");
        std::fs::create_dir_all(c.parent().unwrap()).unwrap();
        std::fs::write(&c, "Use tabs.\n").unwrap();
        install_guidance("copilot", dir.path(), &none)
            .unwrap()
            .unwrap();
        let t = std::fs::read_to_string(&c).unwrap();
        assert!(t.starts_with("Use tabs.\n") && t.contains(BEGIN) && t.contains(END));
        assert!(
            !install_guidance("copilot", dir.path(), &none)
                .unwrap()
                .unwrap()
                .1
        );
    }
}
