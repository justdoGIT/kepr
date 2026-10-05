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

pub const CRED_PREFIX: &str = "kepr";

pub fn store_dir() -> PathBuf {
    if std::env::var_os("KEPR_SYSTEM_MODE").is_some() {
        PathBuf::from("/etc/credstore.encrypted")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
            })
            .join("kepr/credentials")
    }
}

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
    // Strip "kepr-" prefix and parse the uid.
    let rest = cred_name.strip_prefix(&format!("{}-", CRED_PREFIX))?;
    let dash = rest.find('-')?;
    let uid: u32 = rest[..dash].parse().ok()?;
    let env_var = rest[dash + 1..].to_uppercase().replace('-', "_");
    validate_name(&env_var).ok()?;
    (to_cred_name(uid, &env_var) == cred_name).then_some((uid, env_var))
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
    store_dir().join(to_cred_name(uid, name))
}

/// Does `name` (history slots `NAME~N` included) hold a value? Asks the
/// vault image when it is the active store (T4.06), else the file.
pub fn cred_exists(uid: u32, name: &str) -> bool {
    match crate::daemon_vault::active() {
        Some(image) => image.exists(uid, name),
        None => cred_path(uid, name).exists(),
    }
}

// ── List creds for a specific uid ─────────────────────────────────────────────

pub fn list_for_uid(uid: u32) -> Vec<(String, PathBuf)> {
    if let Some(image) = crate::daemon_vault::active() {
        return image.list(uid);
    }
    let store = store_dir();
    let prefix = format!("{}-{}-", CRED_PREFIX, uid);
    let mut results = vec![];

    if let Ok(entries) = fs::read_dir(&store) {
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
    if let Some((_, updated)) = crate::daemon_vault::stat(path) {
        return format_timestamp(updated as i64);
    }
    fs::metadata(path)
        .map(|m| format_timestamp(m.mtime()))
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn file_size(path: &Path) -> u64 {
    if let Some((size, _)) = crate::daemon_vault::stat(path) {
        return size;
    }
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
    fn from_cred_name_rejects_sidecars() {
        assert!(from_cred_name("kepr-1000-foo.meta").is_none());
        assert!(from_cred_name("kepr-1000-foo.tmp.123").is_none());
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

// ── Property tests ────────────────────────────────────────────────────────────
// validate_name is the only path-traversal defence between the daemon and the
// filesystem. Example-based tests above catch the obvious cases; these
// property tests random-walk the input space to lock in the contract:
//   1. Any [A-Za-z0-9_]{1..=128} input is accepted.
//   2. Any input containing a single non-allowed Unicode scalar is rejected.
//   3. Any input longer than 128 chars is rejected, regardless of charset.
//   4. validate_name is total — no input causes a panic.
//
// Default proptest config runs 256 cases per property; failures are minimised
// (shrunk) and the failing seed is recorded under proptest-regressions/ for
// deterministic replay. Keep that directory out of git unless a regression
// proves valuable for the test corpus.

#[cfg(test)]
mod proptests {
    use super::validate_name;
    use proptest::prelude::*;

    proptest! {
        /// Positive contract: any non-empty [A-Za-z0-9_] string up to the
        /// 128-char cap must be accepted.
        #[test]
        fn valid_chars_within_length_accepted(s in "[A-Za-z0-9_]{1,128}") {
            prop_assert!(validate_name(&s).is_ok(), "rejected valid name: {s:?}");
        }

        /// Negative contract: any string containing at least one Unicode
        /// scalar outside [A-Za-z0-9_] must be rejected. The complement class
        /// covers ASCII punctuation, whitespace, control chars, and the
        /// entire non-ASCII Unicode plane.
        #[test]
        fn invalid_char_rejected(
            prefix in "[A-Za-z0-9_]{0,30}",
            bad    in "[^A-Za-z0-9_]",
            suffix in "[A-Za-z0-9_]{0,30}",
        ) {
            let s = format!("{prefix}{bad}{suffix}");
            prop_assert!(
                validate_name(&s).is_err(),
                "accepted name with invalid char: {s:?}"
            );
        }

        /// Length cap: 129..=200 chars of otherwise-valid charset must still
        /// reject. Catches off-by-one regressions on the 128 boundary.
        #[test]
        fn over_length_rejected(s in "[A-Za-z0-9_]{129,200}") {
            prop_assert!(
                validate_name(&s).is_err(),
                "accepted over-length name: {} chars",
                s.len()
            );
        }

        /// Totality: any UTF-8 input must terminate with Ok or Err. No
        /// panics, no infinite loops. Acts as a fuzz harness for the
        /// function's edge cases (empty, all-control, mixed-script, etc.).
        #[test]
        fn never_panics(s in ".*") {
            let _ = validate_name(&s);
        }
    }
}
