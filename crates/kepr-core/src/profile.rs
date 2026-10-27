// profile.rs — profiles (T11.16): `KEPR_PROFILE=work` (or `kepr --profile
// work …`) gives a separate store, state directory and socket, served by
// its own user-mode daemon.
//
// A profile's directories nest under the default ones
// (`$XDG_RUNTIME_DIR/kepr/profiles/work/`, `…/share/kepr/profiles/work/`,
// `…/state/kepr/profiles/work/`), so whatever hides `…/kepr` (the agent
// sandbox) hides every profile too, including one started later.
//
// Profiles are a user-mode feature: with KEPR_SYSTEM_MODE set, a profile
// is an error rather than silently meaning the shared system store.

use std::path::PathBuf;

/// The environment variable naming the active profile.
pub const ENV: &str = "KEPR_PROFILE";

/// `[a-z0-9_-]{1,32}`: safe as one path component, never `.` or `..`.
pub fn validate(name: &str) -> Result<(), String> {
    let ok = (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid profile name {name:?}: use 1-32 of a-z, 0-9, _ and -"
        ))
    }
}

/// Parse a profile value: `None` for the default (empty or `default`).
pub fn parse(value: &str, system_mode: bool) -> Result<Option<String>, String> {
    if value.is_empty() || value == "default" {
        return Ok(None);
    }
    validate(value)?;
    if system_mode {
        return Err("profiles are a user-mode feature; unset KEPR_PROFILE".into());
    }
    Ok(Some(value.to_string()))
}

/// The active profile from the environment.
pub fn current() -> Result<Option<String>, String> {
    match std::env::var_os(ENV) {
        None => Ok(None),
        Some(v) => parse(
            v.to_str().ok_or("invalid profile name (not UTF-8)")?,
            std::env::var_os("KEPR_SYSTEM_MODE").is_some(),
        ),
    }
}

/// The active profile's name for display: `default` when none is set.
pub fn display_name() -> String {
    current().ok().flatten().unwrap_or_else(|| "default".into())
}

/// `base` (a `…/kepr` directory) for the default profile and
/// `base/profiles/NAME` for another. An invalid profile maps to
/// `base/profiles/.invalid`, which no daemon serves (both binaries refuse
/// to start with one): a misconfigured client fails instead of quietly
/// using the default store.
pub fn nest_for(base: PathBuf, profile: &Result<Option<String>, String>) -> PathBuf {
    match profile {
        Ok(None) => base,
        Ok(Some(name)) => base.join("profiles").join(name),
        Err(_) => base.join("profiles").join(".invalid"),
    }
}

/// `nest_for` with the active profile.
pub fn nest(base: PathBuf) -> PathBuf {
    nest_for(base, &current())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lowercase_digits_dash_underscore_up_to_32() {
        for ok in ["work", "a", "dev-2", "client_x", &"z".repeat(32)] {
            assert!(validate(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "Work",
            "a/b",
            "..",
            ".",
            "a.b",
            "é",
            "a b",
            &"z".repeat(33),
        ] {
            assert!(validate(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn default_and_empty_mean_no_profile_and_system_mode_refuses_one() {
        assert_eq!(parse("", false), Ok(None));
        assert_eq!(parse("default", true), Ok(None));
        assert_eq!(parse("work", false), Ok(Some("work".into())));
        assert!(parse("work", true).unwrap_err().contains("user-mode"));
        assert!(parse("../x", false).is_err());
    }

    #[test]
    fn paths_per_profile() {
        let base = PathBuf::from("/run/user/1000/kepr");
        assert_eq!(nest_for(base.clone(), &Ok(None)), base);
        assert_eq!(
            nest_for(base.clone(), &Ok(Some("work".into()))),
            PathBuf::from("/run/user/1000/kepr/profiles/work")
        );
        let invalid = nest_for(base.clone(), &Err("bad".into()));
        assert!(invalid.starts_with(&base) && invalid.ends_with(".invalid"));
        // Every profile stays inside the default directory.
        for p in ["a", "work", "--", "_"] {
            assert!(nest_for(base.clone(), &Ok(Some(p.into()))).starts_with(&base));
        }
    }
}
