// store.rs — credstore path conventions and naming
//
// Credentials are namespaced per-user by UID:
//   ENV_VAR_NAME (uid=1000) → kepr-1000-env-var-name
//
// This allows multiple users to store credentials in the same
// /etc/credstore.encrypted/ directory without collisions,
// using systemd's standard location without any permission changes.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const CREDSTORE: &str = "/etc/credstore.encrypted";
pub const CRED_PREFIX: &str = "kepr";

// ── Naming ────────────────────────────────────────────────────────────────────

/// Build systemd credential name for a given uid + env var name.
/// ENV_VAR_NAME → kepr-<uid>-env-var-name
pub fn to_cred_name(uid: u32, env_var: &str) -> String {
    format!(
        "{}-{}-{}",
        CRED_PREFIX,
        uid,
        env_var.to_lowercase().replace('_', "-")
    )
}

/// kepr-<uid>-env-var-name → ENV_VAR_NAME
pub fn from_cred_name(cred_name: &str) -> Option<(u32, String)> {
    // Strip "kepr-" prefix
    let rest = cred_name.strip_prefix(&format!("{}-", CRED_PREFIX))?;
    // Parse uid
    let dash = rest.find('-')?;
    let uid: u32 = rest[..dash].parse().ok()?;
    let env_var = rest[dash + 1..].to_uppercase().replace('-', "_");
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
                "invalid character '{}' — only A-Z, 0-9, underscore allowed",
                c
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
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02}", y, mo, d, h, m)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cred_name_format() {
        assert_eq!(to_cred_name(1000, "FOO_BAR"), "kepr-1000-foo-bar");
        assert_eq!(to_cred_name(0, "A"), "kepr-0-a");
        assert_eq!(to_cred_name(65535, "A_B_C_1"), "kepr-65535-a-b-c-1");
    }

    #[test]
    fn cred_name_roundtrip() {
        for (uid, name) in [
            (1000u32, "OPENAI_API_KEY"),
            (0, "A"),
            (42, "A_B_C_1"),
            (99999, "X"),
        ] {
            let encoded = to_cred_name(uid, name);
            let (decoded_uid, decoded_name) =
                from_cred_name(&encoded).expect("valid cred name must parse");
            assert_eq!(decoded_uid, uid, "uid roundtrip failed");
            assert_eq!(decoded_name, name, "name roundtrip failed");
        }
    }

    #[test]
    fn from_cred_name_rejects_malformed() {
        assert!(from_cred_name("notkepr-1000-foo").is_none());
        assert!(from_cred_name("kepr-abc-foo").is_none()); // non-numeric uid
        assert!(from_cred_name("kepr-").is_none()); // no uid/name
    }

    #[test]
    fn from_cred_name_reverses_dash_mapping() {
        // Pins the `-` → `_` inverse mapping that `to_cred_name`'s
        // `replace('_', "-")` depends on. A regression here would
        // desync what `list_for_uid` shows from what `get` can retrieve.
        assert_eq!(
            from_cred_name("kepr-1000-foo-bar"),
            Some((1000, "FOO_BAR".to_string())),
        );
        assert_eq!(
            from_cred_name("kepr-0-a-b-c-1"),
            Some((0, "A_B_C_1".to_string())),
        );
    }

    #[test]
    fn validate_name_accepts_valid() {
        for ok in &[
            "A",
            "X",
            "1",
            "_",
            "ABC",
            "A1",
            "1A",
            "A_B",
            "FOO_BAR_123",
            "foo",
            "Foo_Bar",
        ] {
            validate_name(ok).unwrap_or_else(|e| panic!("expected {ok:?} to be accepted: {e}"));
        }
        // Boundary: exactly 128 chars is allowed.
        let max_len: String = "A".repeat(128);
        validate_name(&max_len).expect("128 chars must be accepted");
    }

    #[test]
    fn validate_name_rejects_invalid() {
        // path-traversal and separators
        for bad in &[
            "",
            "..",
            "/",
            "foo/bar",
            "../etc/passwd",
            "foo bar",
            "foo-bar",
            "foo.bar",
            "foo\nbar",
            "foo\tbar",
            "naïve", // non-ASCII
            "foo\0bar",
        ] {
            // NUL
            assert!(
                validate_name(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
        // 129 chars exceeds the cap
        let too_long: String = "A".repeat(129);
        assert!(validate_name(&too_long).is_err());
    }

    #[test]
    fn format_timestamp_known_values() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00");
        // 2023-11-14 22:13:20 UTC — catches calendar-math regressions
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14 22:13");
    }
}
