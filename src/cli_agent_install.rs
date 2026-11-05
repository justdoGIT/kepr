// cli_agent_install.rs — `kepr agent install omp|grok|opencode [--port N]`
// (T1.15). Points a harness's own config file at the gate once, so the
// user just runs `kepr agent run omp` / `kepr agent run grok`
// afterwards. Plain line editing (no YAML/TOML crates); always writes a
// timestamped backup first; idempotent; never removes user entries.
// `install claude|codex` writes only kepr's guidance for the model
// (cli_agent_plugin::install_guidance, T12.15).
//
// Config shapes follow the harnesses' docs as of 2026-10:
//   omp:  ~/.config/omp/agent/models.yml (or PI_CODING_AGENT_DIR)
//   grok: ~/.grok/config.toml      [model.<key>] {model,base_url,env_key}
//   opencode: ${XDG_CONFIG_HOME:-~/.config}/opencode/opencode.json
//         provider.anthropic.options.{baseURL,apiKey} (serde_json, T12.13)
// Re-verify when a harness changes its configuration format.

use std::path::PathBuf;

use kepr_core::protocol::Response;

use crate::cli_ui;

const OMP_ID: &str = "  kepr-anthropic:";
const GROK_HEADER: &str = "[model.kepr-grok]";

fn omp_block(port: u16) -> String {
    format!(
        "{OMP_ID}\n    baseUrl: http://127.0.0.1:{port}/anthropic\n    api: anthropic-messages\n    apiKey: KEPR_PH_ANTHROPIC\n"
    )
}

fn grok_block(port: Option<u16>) -> String {
    let base_url = port.map_or_else(String::new, |p| {
        format!("base_url = \"http://127.0.0.1:{p}/xai/v1\"\n")
    });
    format!("{GROK_HEADER}\nmodel = \"grok-4\"\n{base_url}env_key = \"KEPR_PH_XAI\"\n")
}

fn lines_of(text: &str) -> Vec<String> {
    text.lines().map(str::to_string).collect()
}

fn join(lines: &[String]) -> String {
    let mut s = lines.join("\n");
    s.push('\n');
    s
}

pub fn upsert_omp(text: &str, port: Option<u16>) -> String {
    let mut lines = lines_of(text);
    let block = port.map(|port| lines_of(&omp_block(port)));
    let Some(prov) = lines
        .iter()
        .position(|line| matches!(line.trim_end(), "providers:" | "providers: {}"))
    else {
        let Some(block) = block else {
            return if text.trim().is_empty() {
                "providers: {}\n".into()
            } else {
                text.to_string()
            };
        };
        if !lines.is_empty() && !lines.last().is_some_and(|line| line.is_empty()) {
            lines.push(String::new());
        }
        lines.push("providers:".into());
        lines.extend(block);
        return join(&lines);
    };
    let own = lines
        .iter()
        .skip(prov + 1)
        .position(|line| line.trim_end() == OMP_ID);
    if let Some(offset) = own {
        let start = prov + 1 + offset;
        let mut end = start + 1;
        while end < lines.len() && (lines[end].starts_with("    ") || lines[end].trim().is_empty())
        {
            end += 1;
        }
        lines.splice(start..end, block.unwrap_or_default());
    } else if let Some(block) = block {
        lines.splice(prov + 1..prov + 1, block);
    } else {
        return text.to_string();
    }
    let has_entries = lines
        .iter()
        .skip(prov + 1)
        .take_while(|line| line.starts_with(' ') || line.trim().is_empty())
        .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'));
    lines[prov] = if has_entries {
        "providers:"
    } else {
        "providers: {}"
    }
    .into();
    join(&lines)
}

pub fn upsert_grok(text: &str, port: Option<u16>) -> String {
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
pub fn upsert_opencode(text: &str, port: Option<u16>) -> Result<String, String> {
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
    let base = port.map_or_else(
        || "{env:KEPR_GATE_URL}/anthropic/v1".to_string(),
        |p| format!("http://127.0.0.1:{p}/anthropic/v1"),
    );
    at.insert("baseURL".into(), base.into());
    at.insert("apiKey".into(), "{env:KEPR_PH_ANTHROPIC}".into());
    let mut out = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    out.push('\n');
    Ok(out)
}

/// `${XDG_CONFIG_HOME:-~/.config}/opencode/opencode.json`; a relative
/// XDG_CONFIG_HOME is ignored, as the XDG spec says.
/// OMP prefers an explicit agent directory; otherwise use the XDG
/// `omp/agent` location (its default is ~/.config/omp/agent).
pub(crate) fn omp_agent_dir(
    home: &std::path::Path,
    agent_dir: Option<std::ffi::OsString>,
    xdg: Option<std::ffi::OsString>,
) -> PathBuf {
    agent_dir
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            xdg.map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(".config"))
                .join("omp/agent")
        })
}

pub(crate) fn omp_config(
    home: &std::path::Path,
    agent_dir: Option<std::ffi::OsString>,
    xdg: Option<std::ffi::OsString>,
) -> PathBuf {
    omp_agent_dir(home, agent_dir, xdg).join("models.yml")
}
fn opencode_config(home: &std::path::Path, xdg: Option<std::ffi::OsString>) -> PathBuf {
    xdg.map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"))
        .join("opencode/opencode.json")
}

/// Check first, then write through `apply`: a file opencode can read but
/// kepr can't is left as it is, with no backup.
fn install_opencode(path: &std::path::Path, port: Option<u16>) -> Result<bool, String> {
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
    let port_text = port.map_or_else(|| "dynamic session".to_string(), |p| format!("port {p}"));
    let home = match home() {
        Ok(h) => h,
        Err(e) => return Response::fail(e),
    };
    let (path, result) = match harness {
        "omp" => {
            let p = omp_config(
                &home,
                std::env::var_os("PI_CODING_AGENT_DIR"),
                std::env::var_os("XDG_CONFIG_HOME"),
            );
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
        // T13.07: project files; neither tool can be pointed at the gate by
        // an environment variable, and the message says so.
        "cursor" | "copilot" => {
            let Ok(project) = std::env::current_dir() else {
                return Response::fail("cannot read the current directory");
            };
            let r = guidance(harness, &project);
            if matches!(r, Response::Pong) {
                cli_ui::info(&format!(
                    "{harness} has no setting kepr can set for it: its model traffic does not go \
                     through the gate, so keep provider keys out of its files and settings"
                ));
            }
            return r;
        }
        "grok-cli" | "aider" | "gemini" => {
            return Response::fail(format!(
                "{harness} needs no install step: run `kepr agent run {harness}`"
            ))
        }
        other => {
            return Response::fail(format!(
                "no installer for '{other}' (supported: omp, grok, opencode, claude, codex, cursor, copilot)"
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
                "{harness} {what}: {} → kepr gate ({port_text})",
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
#[path = "cli_agent_install_tests.rs"]
mod tests;
