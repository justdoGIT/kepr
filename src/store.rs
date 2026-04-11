// store.rs — credstore path conventions and naming
//
// Credentials are namespaced per-user by UID:
//   ENV_VAR_NAME (uid=1000) → credman-1000-env-var-name
//
// This allows multiple users to store credentials in the same
// /etc/credstore.encrypted/ directory without collisions,
// using systemd's standard location without any permission changes.

use std::path::{Path, PathBuf};
use std::fs;
use std::os::unix::fs::MetadataExt;

pub const CREDSTORE:    &str = "/etc/credstore.encrypted";
pub const CRED_PREFIX:  &str = "credman";

// ── Naming ────────────────────────────────────────────────────────────────────

/// Build systemd credential name for a given uid + env var name.
/// ENV_VAR_NAME → credman-<uid>-env-var-name
pub fn to_cred_name(uid: u32, env_var: &str) -> String {
    format!("{}-{}-{}", CRED_PREFIX, uid,
        env_var.to_lowercase().replace('_', "-"))
}

/// credman-<uid>-env-var-name → ENV_VAR_NAME
pub fn from_cred_name(cred_name: &str) -> Option<(u32, String)> {
    // Strip "credman-" prefix
    let rest = cred_name.strip_prefix(&format!("{}-", CRED_PREFIX))?;
    // Parse uid
    let dash = rest.find('-')?;
    let uid: u32 = rest[..dash].parse().ok()?;
    let env_var = rest[dash+1..].to_uppercase().replace('-', "_");
    Some((uid, env_var))
}

/// Validate credential name — only A-Z, 0-9, underscore allowed.
/// Rejects path traversal, shell injection, etc.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name cannot be empty".to_string());
    }
    if name.len() > 128 {
        return Err("name too long (max 128 chars)".to_string());
    }
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return Err(format!(
                "invalid character '{}' — only A-Z, 0-9, underscore allowed", c
            ));
        }
    }
    Ok(())
}

// ── Paths ─────────────────────────────────────────────────────────────────────

pub fn cred_path(uid: u32, name: &str) -> PathBuf {
    Path::new(CREDSTORE).join(to_cred_name(uid, name))
}

pub fn store_path() -> &'static Path {
    Path::new(CREDSTORE)
}

// ── List creds for a specific uid ─────────────────────────────────────────────

pub fn list_for_uid(uid: u32) -> Vec<(String, PathBuf)> {
    let prefix = format!("{}-{}-", CRED_PREFIX, uid);
    let mut results = vec![];

    if let Ok(entries) = fs::read_dir(CREDSTORE) {
        let mut files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
            .collect();
        files.sort_by_key(|e| e.file_name());

        for entry in files {
            let fname = entry.file_name().to_string_lossy().to_string();
            if let Some((_, env_var)) = from_cred_name(&fname) {
                results.push((env_var, entry.path()));
            }
        }
    }

    results
}

// ── Timestamp helper ──────────────────────────────────────────────────────────

pub fn file_mtime_str(path: &Path) -> String {
    fs::metadata(path)
        .map(|m| format_timestamp(m.mtime()))
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn format_timestamp(secs: i64) -> String {
    let secs = secs as u64;
    let m    = (secs / 60) % 60;
    let h    = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02}", y, mo, d, h, m)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z   = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    let y   = yoe + era * 400;
    let doy = doe - (365*yoe + yoe/4 - yoe/100);
    let mp  = (5*doy + 2)/153;
    let d   = doy - (153*mp+2)/5 + 1;
    let m   = if mp < 10 { mp+3 } else { mp-9 };
    let y   = if m <= 2  { y+1  } else { y   };
    (y, m, d)
}
