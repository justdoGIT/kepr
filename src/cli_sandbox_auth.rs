//! Mask supported harness credentials without reading or migrating their contents.
//! Sources: Claude authentication docs; Gemini core config/storage.ts and
//! utils/paths.ts; pi coding-agent core/auth-storage.ts and config.ts;
//! oh-my-pi utils/dirs.ts and ai/auth/sqlite-credential-store.ts;
//! OpenCode core credential.ts, legacy credential migration, cli/database-path.ts.
use std::ffi::CString;
use std::path::{Path, PathBuf};

#[path = "cli_sandbox_auth_paths.rs"]
mod paths;

const PATH_ENV: &[&str] = &[
    "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR",
    "GEMINI_CLI_HOME", "GOOGLE_APPLICATION_CREDENTIALS", "PI_CODING_AGENT_DIR",
    "PI_CONFIG_DIR", "OMP_PROFILE", "PI_PROFILE", "OPENCODE_DB",
];

/// Capture path controls before the selected harness environment is allowlisted.
pub fn environment() -> Result<Vec<(String, String)>, String> {
    let env: Vec<_> = PATH_ENV.iter().filter_map(|key| std::env::var_os(key).map(|value| {
        value.into_string().map(|value| ((*key).to_string(), value))
            .map_err(|_| String::from("credential path control is not valid UTF-8"))
    })).collect::<Result<_, _>>()?;
    if get(&env, "HOME").is_none() {
        return Err("HOME is required to locate host harness credential caches".into());
    }
    Ok(env)
}

pub fn hidden_cstrings(
    env: &[(String, String)],
    hidden_dirs: &[PathBuf],
) -> Result<Vec<CString>, String> {
    let mut out = crate::cli_sandbox_bus::hidden_cstrings();
    for path in files(env)? {
        if !hidden_dirs.iter().any(|dir| path.starts_with(dir)) {
            out.push(CString::new(path.as_os_str().as_encoded_bytes())
                .map_err(|_| "bad credential cache path")?);
        }
    }
    Ok(out)
}

fn get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str())
}

fn agent_files(base: &Path, mixed: &mut Vec<(PathBuf, &'static str)>, out: &mut Vec<(PathBuf, bool)>) {
    out.push((base.join("auth.json"), false));
    mixed.push((base.join("agent.db"), "omp"));
}

fn candidates(env: &[(String, String)]) -> Result<Vec<(PathBuf, bool, Option<&'static str>)>, String> {
    // PI_CONFIG_DIR and OPENCODE_DB are documented relative-name controls;
    // profiles are names, not filesystem roots. Validate them after joining.
    for key in PATH_ENV.iter().filter(|key| !matches!(**key,
        "PI_CONFIG_DIR" | "OMP_PROFILE" | "PI_PROFILE" | "OPENCODE_DB")) {
        if let Some(value) = get(env, key) { paths::validate(Path::new(value))?; }
    }
    let home = get(env, "HOME").map(PathBuf::from);
    let config = get(env, "XDG_CONFIG_HOME").map(PathBuf::from)
        .or_else(|| home.as_ref().map(|p| p.join(".config")));
    let data = get(env, "XDG_DATA_HOME").map(PathBuf::from)
        .or_else(|| home.as_ref().map(|p| p.join(".local/share")));
    let mut out = Vec::new();
    let mut mixed = Vec::new();
    if let Some(home) = &home {
        out.push((home.join(".codex/auth.json"), false));
        out.push((home.join(".claude/.credentials.json"), false));
        gemini(&home.join(".gemini"), &mut out);
        out.push((home.join(".pi/agent/auth.json"), false));
        // Legacy Pi/OMP layout confirmed by operator metadata inventory.
        out.push((home.join(".config/pi/auth.json"), false));
        agent_files(&home.join(".config/pi/agent"), &mut mixed, &mut out);
        agent_files(&home.join(".config/omp/agent"), &mut mixed, &mut out);
        out.push((home.join(".local/share/opencode/auth.json"), false));
        mixed.push((home.join(".local/share/opencode/opencode.db"), "opencode"));
        agent_files(&home.join(".omp/agent"), &mut mixed, &mut out);
        let root = home.join(get(env, "PI_CONFIG_DIR").unwrap_or(".omp"));
        paths::validate(&root)?;
        if Path::new(get(env, "PI_CONFIG_DIR").unwrap_or(".omp")).is_absolute() {
            return Err("PI_CONFIG_DIR must be a home-relative config directory name".into());
        }
        agent_files(&root.join("agent"), &mut mixed, &mut out);
        if let Some(profile) = get(env, "OMP_PROFILE").or_else(|| get(env, "PI_PROFILE")) {
            let profile = profile.trim();
            if !profile.is_empty() && profile != "default" {
                if profile.len() > 64 || profile.ends_with('.')
                    || !profile.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
                    || !profile.as_bytes()[0].is_ascii_alphanumeric() {
                    return Err("unsafe OMP credential profile name".into());
                }
                agent_files(&root.join("profiles").join(profile).join("agent"), &mut mixed, &mut out);
                if let Some(data) = &data {
                    mixed.push((data.join("omp/profiles").join(profile).join("agent.db"), "omp"));
                }
            }
        }
    }
    if let Some(config) = &config {
        out.push((config.join("codex/auth.json"), false));
        agent_files(&config.join("omp/agent"), &mut mixed, &mut out);
        out.push((config.join("pi/auth.json"), false));
        agent_files(&config.join("pi/agent"), &mut mixed, &mut out);
    }
    for (key, name) in [("CODEX_HOME", "auth.json"), ("CLAUDE_CONFIG_DIR", ".credentials.json")] {
        if let Some(base) = get(env, key) { out.push((Path::new(base).join(name), false)); }
    }
    if let Some(base) = get(env, "PI_CODING_AGENT_DIR") {
        agent_files(Path::new(base), &mut mixed, &mut out);
    }
    if let Some(base) = get(env, "GEMINI_CLI_HOME") { gemini(&Path::new(base).join(".gemini"), &mut out); }
    if let Some(file) = get(env, "GOOGLE_APPLICATION_CREDENTIALS") { out.push((PathBuf::from(file), false)); }
    if let Some(data) = &data {
        mixed.push((data.join("omp/agent.db"), "omp"));
        out.push((data.join("opencode/auth.json"), false));
        let db = get(env, "OPENCODE_DB").unwrap_or("opencode.db");
        if db != ":memory:" { mixed.push((data.join("opencode").join(db), "opencode")); }
        // The default remains discoverable even when OPENCODE_DB redirects it.
        mixed.push((data.join("opencode/opencode.db"), "opencode"));
    } else if let Some(db) = get(env, "OPENCODE_DB").filter(|db| *db != ":memory:") {
        paths::validate(Path::new(db))?;
        mixed.push((PathBuf::from(db), "opencode"));
    }
    let mut result: Vec<_> = out.into_iter().map(|(path, sqlite)| (path, sqlite, None)).collect();
    result.extend(mixed.into_iter().map(|(path, owner)| (path, true, Some(owner))));
    Ok(result)
}

fn gemini(base: &Path, out: &mut Vec<(PathBuf, bool)>) {
    for name in ["oauth_creds.json", "gemini-credentials.json", "mcp-oauth-tokens.json", "a2a-oauth-tokens.json"] {
        out.push((base.join(name), false));
    }
}

pub fn files(env: &[(String, String)]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for (path, sqlite, _) in candidates(env)? { paths::append(&path, sqlite, &mut out)?; }
    out.sort();
    out.dedup();
    Ok(out)
}

/// A shared settings/auth database cannot be blanked for its own consumer.
/// Refuse instead of silently breaking account login or exposing its tokens.
pub fn validate_selected(harness: &str, env: &[(String, String)]) -> Result<(), String> {
    for (path, sqlite, owner) in candidates(env)? {
        if owner != Some(harness) { continue; }
        let mut found = Vec::new();
        paths::append(&path, sqlite, &mut found)?;
        if !found.is_empty() {
            return Err(format!("{harness} shared settings/auth database {} requires an unsupported credential broker; use a protected private-home workspace with a Kepr API grant (external account logins are preserved)", path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "cli_sandbox_auth_tests.rs"]
mod tests;
