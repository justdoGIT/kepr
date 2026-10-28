// cli_agent_install.rs — `kepr agent install omp|grok|opencode [--port N]`
// (T1.15). Points a harness's own config file at the gate once, so the
// user just runs `kepr agent run omp` / `kepr agent run grok`
// afterwards. Plain line editing (no YAML/TOML crates); always writes a
// timestamped backup first; idempotent; never removes user entries.
// `install claude|codex` writes only kepr's guidance for the model
// (cli_agent_plugin::install_guidance, T12.15).
//
// Config shapes follow the harnesses' docs as of 2026-10:
//   omp:  ~/.omp/agent/models.yml  providers.<id>.{baseUrl,api,apiKey}
//   grok: ~/.grok/config.toml      [model.<key>] {model,base_url,env_key}
//   opencode: ${XDG_CONFIG_HOME:-~/.config}/opencode/opencode.json
//         provider.anthropic.options.{baseURL,apiKey} (serde_json, T12.13)
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

/// Point opencode's `anthropic` provider at the gate (T12.13). Plain JSON
/// only: a root that isn't an object, a non-object on the way, or JSONC
/// comments are refused rather than rewritten. Every other key is kept.
pub fn upsert_opencode(text: &str, port: u16) -> Result<String, String> {
    use serde_json::{Map, Value};
    let bad = |what: &str| format!("opencode.json: {what} is not a JSON object; edit it by hand");
    let mut root: Value = match text.trim() {
        "" => Value::Object(Map::new()),
        t => serde_json::from_str(t).map_err(|_| bad("the file"))?,
    };
    let obj = root.as_object_mut().ok_or_else(|| bad("the file"))?;
    obj.entry("$schema")
        .or_insert_with(|| "https://opencode.ai/config.json".into());
    let mut at = obj;
    for key in ["provider", "anthropic", "options"] {
        at = at
            .entry(key)
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| bad(key))?;
    }
    let base = format!("http://127.0.0.1:{port}/anthropic/v1");
    at.insert("baseURL".into(), base.into());
    at.insert("apiKey".into(), "{env:KEPR_PH_ANTHROPIC}".into());
    let mut out = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    out.push('\n');
    Ok(out)
}

/// `${XDG_CONFIG_HOME:-~/.config}/opencode/opencode.json`; a relative
/// XDG_CONFIG_HOME is ignored, as the XDG spec says.
fn opencode_config(home: &std::path::Path, xdg: Option<std::ffi::OsString>) -> PathBuf {
    xdg.map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"))
        .join("opencode/opencode.json")
}

/// Check first, then write through `apply`: a file opencode can read but
/// kepr can't is left as it is, with no backup.
fn install_opencode(path: &std::path::Path, port: u16) -> Result<bool, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => {
            upsert_opencode(&t, port)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    apply(path, |t| {
        upsert_opencode(t, port).unwrap_or_else(|_| t.to_string())
    })
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
        // 0600: harness configs often hold API keys, and a plain write
        // would make the copy readable by every local user.
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backup)
            .and_then(|mut f| f.write_all(old.as_bytes()))
            .map_err(|e| format!("{}: {e}", backup.display()))?;
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::write(path, new).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(true)
}

/// claude / codex: no config to edit (the environment points them at the
/// gate), only kepr's guidance for the model (T12.15).
fn guidance(harness: &str, home: &std::path::Path) -> Response {
    let env = |k: &str| std::env::var(k).ok();
    match crate::cli_agent_plugin::install_guidance(harness, home, &env) {
        Ok(Some((path, changed))) => {
            let what = if changed { "installed" } else { "up to date" };
            cli_ui::ok(&format!("kepr guidance {what}: {}", path.display()));
            cli_ui::info(&format!("start it with: kepr agent run {harness}"));
            Response::Pong
        }
        Ok(None) => Response::fail(format!("no guidance for '{harness}'")),
        Err(e) => Response::fail(e),
    }
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
        "opencode" => {
            let p = opencode_config(&home, std::env::var_os("XDG_CONFIG_HOME"));
            let r = install_opencode(&p, port);
            (p, r)
        }
        "claude" | "codex" => return guidance(harness, &home),
        "grok-cli" | "aider" | "gemini" => {
            return Response::fail(format!(
                "{harness} needs no install step: run `kepr agent run {harness}`"
            ))
        }
        other => {
            return Response::fail(format!(
                "no installer for '{other}' (supported: omp, grok, opencode, claude, codex)"
            ))
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
            match crate::cli_agent_plugin::install(harness, &home) {
                Ok(Some((dir, changed))) => cli_ui::ok(&format!(
                    "kepr plugin {}: {}",
                    if changed { "installed" } else { "up to date" },
                    dir.display()
                )),
                Ok(None) => {}
                Err(e) => return Response::fail(format!("plugin: {e}")),
            }
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
    fn opencode_config_path_ignores_a_relative_xdg_dir() {
        let home = std::path::Path::new("/h");
        let want = |p: &str| PathBuf::from(p).join("opencode/opencode.json");
        assert_eq!(opencode_config(home, None), want("/h/.config"));
        assert_eq!(opencode_config(home, Some("/x".into())), want("/x"));
        assert_eq!(
            opencode_config(home, Some("rel".into())),
            want("/h/.config")
        );
        assert_eq!(opencode_config(home, Some("".into())), want("/h/.config"));
    }

    #[test]
    fn opencode_fresh_config() {
        let want = r#"{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "{env:KEPR_PH_ANTHROPIC}",
        "baseURL": "http://127.0.0.1:7878/anthropic/v1"
      }
    }
  }
}
"#;
        let fresh = upsert_opencode("", 7878).unwrap();
        assert_eq!(fresh, want);
        assert_eq!(upsert_opencode(" \n", 7878).unwrap(), want);
        assert_eq!(upsert_opencode(&fresh, 7878).unwrap(), fresh);
        assert!(!fresh.contains("sk-"));
    }

    #[test]
    fn opencode_keeps_user_keys() {
        let user = r#"{"$schema": "https://example.test/mine.json", "model": "anthropic/claude-sonnet-4-5",
          "provider": {"openai": {"options": {"baseURL": "https://proxy.example/v1"}},
                       "anthropic": {"models": {"x": {}}, "options": {"apiKey": "sk-ant-api03-old", "timeout": 5}}}}"#;
        let out = upsert_opencode(user, 9000).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["$schema"], "https://example.test/mine.json");
        assert_eq!(v["model"], "anthropic/claude-sonnet-4-5");
        assert_eq!(
            v["provider"]["openai"]["options"]["baseURL"],
            "https://proxy.example/v1"
        );
        let a = &v["provider"]["anthropic"];
        assert_eq!(a["models"]["x"], serde_json::json!({}));
        assert_eq!(a["options"]["timeout"], 5);
        assert_eq!(
            a["options"]["baseURL"],
            "http://127.0.0.1:9000/anthropic/v1"
        );
        assert_eq!(a["options"]["apiKey"], "{env:KEPR_PH_ANTHROPIC}");
        assert!(!out.contains("sk-"));
        assert_eq!(upsert_opencode(&out, 9000).unwrap(), out);
    }

    #[test]
    fn opencode_refuses_a_non_object_and_leaves_the_file() {
        for bad in ["[1, 2]", "{\"provider\": 3}", "{\"a\": 1, // note\n}"] {
            assert!(upsert_opencode(bad, 7878).is_err(), "{bad}");
        }
        let dir = std::env::temp_dir().join(format!("kepr-oc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("opencode.json");
        std::fs::write(&path, "[1, 2]\n").unwrap();
        assert!(install_opencode(&path, 7878).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[1, 2]\n");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no backup");
        std::fs::remove_file(&path).unwrap();
        assert!(install_opencode(&path, 7878).unwrap());
        assert!(!install_opencode(&path, 7878).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
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
