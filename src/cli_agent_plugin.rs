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
    (
        "skills/kepr/SKILL.md",
        include_str!("../plugins/grok/kepr/skills/kepr/SKILL.md"),
    ),
];

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

    #[test]
    fn writes_once_then_reports_unchanged() {
        let dir = std::env::temp_dir().join(format!("kepr-plugin-test-{}", std::process::id()));
        assert!(write_plugin(&dir, GROK).unwrap());
        assert!(!write_plugin(&dir, GROK).unwrap());
        assert!(dir.join(".grok-plugin/plugin.json").is_file());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
