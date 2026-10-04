// cli_agent_install.rs — `kepr agent install omp|grok [--port N]`
// (T1.15). Points a harness's own config file at the gate once, so the
// user just runs `kepr agent run omp` / `kepr agent run grok`
// afterwards. Plain line editing (no YAML/TOML crates); always writes a
// timestamped backup first; idempotent; never removes user entries.
//
// Config shapes follow the harnesses' docs as of 2026-10:
//   omp:  ~/.omp/agent/models.yml  providers.<id>.{baseUrl,api,apiKey}
//   grok: ~/.grok/config.toml      [model.<key>] {model,base_url,env_key}
// Re-verify when a harness changes its configuration format.

use std::path::PathBuf;

use kepr_core::protocol::Response;

use crate::cli_agent_adapters::INSTALL_PORT;
use crate::cli_ui;

const OMP_ID: &str = "  kepr-anthropic:";
const GROK_HEADER: &str = "[model.kepr-grok]";

fn omp_block(port: u16) -> String {
    format!(
        "{OMP_ID}\n    baseUrl: http://127.0.0.1:{port}/anthropic\n    api: anthropic-messages\n    apiKey: KEPR_PH_ANTHROPIC\n"
    )
}

fn grok_block(port: u16) -> String {
    format!(
        "{GROK_HEADER}\nmodel = \"grok-4\"\nbase_url = \"http://127.0.0.1:{port}/xai/v1\"\nenv_key = \"KEPR_PH_XAI\"\n"
    )
}

fn lines_of(text: &str) -> Vec<String> {
    text.lines().map(str::to_string).collect()
}

fn join(lines: &[String]) -> String {
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

/// Insert or replace the `kepr-anthropic` provider under `providers:`.
pub fn upsert_omp(text: &str, port: u16) -> String {
    let mut lines = lines_of(text);
    let block = lines_of(&omp_block(port));
    let Some(prov) = lines.iter().position(|l| l.trim_end() == "providers:") else {
        if !lines.is_empty() && !lines.last().is_some_and(|l| l.is_empty()) {
            lines.push(String::new());
        }
        lines.push("providers:".into());
        lines.extend(block);
        return join(&lines);
    };
    match lines
        .iter()
        .skip(prov + 1)
        .position(|l| l.trim_end() == OMP_ID)
    {
        Some(off) => {
            let start = prov + 1 + off;
            let mut end = start + 1;
            while end < lines.len()
                && (lines[end].starts_with("    ") || lines[end].trim().is_empty())
            {
                end += 1;
            }
            lines.splice(start..end, block);
        }
        None => {
            lines.splice(prov + 1..prov + 1, block);
        }
    }
    join(&lines)
}

/// Insert or replace the `[model.kepr-grok]` table.
pub fn upsert_grok(text: &str, port: u16) -> String {
    let mut lines = lines_of(text);
    let block = lines_of(&grok_block(port));
    match lines.iter().position(|l| l.trim() == GROK_HEADER) {
        Some(start) => {
            let mut end = start + 1;
            while end < lines.len() && !lines[end].trim_start().starts_with('[') {
                end += 1;
            }
            lines.splice(start..end, block);
        }
        None => {
            if !lines.is_empty() && !lines.last().is_some_and(|l| l.is_empty()) {
                lines.push(String::new());
            }
            lines.extend(block);
        }
    }
    join(&lines)
}

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())
}

/// Apply `edit` to `path`, backing up the old file. Returns whether the
/// file changed.
pub fn apply(path: &std::path::Path, edit: impl Fn(&str) -> String) -> Result<bool, String> {
    let old = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let new = edit(old.as_deref().unwrap_or_default());
    if old.as_deref() == Some(new.as_str()) {
        return Ok(false);
    }
    if let Some(old) = &old {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = path.with_extension(format!("kepr-backup-{ts}"));
        std::fs::write(&backup, old).map_err(|e| format!("{}: {e}", backup.display()))?;
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::write(path, new).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(true)
}

pub fn cmd_install(harness: &str, port: Option<u16>) -> Response {
    let port = port.unwrap_or(INSTALL_PORT);
    let home = match home() {
        Ok(h) => h,
        Err(e) => return Response::fail(e),
    };
    let (path, result) = match harness {
        "omp" => {
            let p = home.join(".omp/agent/models.yml");
            let r = apply(&p, |t| upsert_omp(t, port));
            (p, r)
        }
        "grok" => {
            let p = home.join(".grok/config.toml");
            let r = apply(&p, |t| upsert_grok(t, port));
            (p, r)
        }
        "claude" | "codex" | "grok-cli" | "aider" => {
            return Response::fail(format!(
                "{harness} needs no install step: run `kepr agent run {harness}`"
            ))
        }
        other => {
            return Response::fail(format!("no installer for '{other}' (supported: omp, grok)"))
        }
    };
    match result {
        Ok(changed) => {
            let what = if changed {
                "configured"
            } else {
                "already configured"
            };
            cli_ui::ok(&format!(
                "{harness} {what}: {} → kepr gate on port {port}",
                path.display()
            ));
            cli_ui::info(&format!("start it with: kepr agent run {harness}"));
            Response::Pong
        }
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omp_insert_replace_idempotent() {
        let fresh = upsert_omp("", 7878);
        assert!(fresh.starts_with("providers:\n  kepr-anthropic:\n"));
        assert_eq!(upsert_omp(&fresh, 7878), fresh);
        let user = "providers:\n  mine:\n    baseUrl: https://x\n    apiKey: MINE\n";
        let added = upsert_omp(user, 7878);
        assert!(added.contains("  mine:\n    baseUrl: https://x"));
        assert!(added.contains("apiKey: KEPR_PH_ANTHROPIC"));
        let moved = upsert_omp(&added, 9000);
        assert!(moved.contains("127.0.0.1:9000/anthropic") && !moved.contains(":7878/"));
        assert!(moved.contains("  mine:"));
        assert_eq!(moved.matches(OMP_ID).count(), 1);
    }

    #[test]
    fn grok_insert_replace_idempotent() {
        let user = "[models]\ndefault = \"grok-4\"\n\n[model.other]\nbase_url = \"x\"\n";
        let added = upsert_grok(user, 7878);
        assert!(added.contains("[model.other]\nbase_url = \"x\""));
        assert!(added.contains("env_key = \"KEPR_PH_XAI\""));
        assert_eq!(upsert_grok(&added, 7878), added);
        let moved = upsert_grok(&added, 9000);
        assert!(moved.contains(":9000/xai/v1") && !moved.contains(":7878/"));
        assert_eq!(moved.matches(GROK_HEADER).count(), 1);
    }

    #[test]
    fn apply_writes_backup_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("kepr-install-{}", std::process::id()));
        let path = dir.join("cfg.toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "[a]\n").unwrap();
        assert!(apply(&path, |t| upsert_grok(t, 7878)).unwrap());
        assert!(!apply(&path, |t| upsert_grok(t, 7878)).unwrap());
        let backups = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("kepr-backup")
            })
            .count();
        assert_eq!(backups, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
