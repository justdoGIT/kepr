// cli_mode.rs — single process-wide CliMode value read by every early-exit
// path in the CLI.
//
// Replaces two independent AtomicBools (FORCE_NO_COLOR and FORCE_JSON) with
// one struct behind a OnceLock. Benefits:
//
//   - One source of truth. Every consumer (`use_color`, `json_mode`,
//     future additions) goes through `mode()`.
//   - Set once at the top of parse_args — never mutated afterwards.
//   - Adding a new mode flag is a one-line field on CliMode, not a new
//     static atomic.
//
// init_from_argv() pre-scans argv for mode flags before the main parse
// loop runs, so error paths that fire before Args is built (unknown verb,
// missing value after --value, etc.) already see the correct mode.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, Default)]
pub struct CliMode {
    pub json: bool,
    pub color: bool,
}

static CLI_MODE: OnceLock<CliMode> = OnceLock::new();

fn option_name(token: &str) -> &str {
    if token == "--" {
        token
    } else {
        token.strip_prefix("--").unwrap_or(token)
    }
}

fn command_needs_name(command: &str) -> bool {
    matches!(
        command,
        "set"
            | "get"
            | "delete"
            | "rotate"
            | "sync-push"
            | "sync-pull"
            | "fido2-register"
            | "protect-agent"
    )
}

fn mode_flags(argv: &[String]) -> (bool, bool, bool) {
    let mut json = argv.iter().any(|arg| arg == "--json");
    let mut color = argv.iter().any(|arg| arg == "--color");
    let mut no_color = argv.iter().any(|arg| arg == "--no-color");
    let mut i = 1;
    while i < argv.len() {
        match option_name(&argv[i]) {
            "json" => json = true,
            "color" => color = true,
            "no-color" => no_color = true,
            "version" => {}
            _ => break,
        }
        i += 1;
    }

    let Some(command) = argv.get(i).map(String::as_str) else {
        return (json, color, no_color);
    };
    i += 1;
    if command_needs_name(command) && i < argv.len() && !argv[i].starts_with('-') {
        i += 1;
    }
    while i < argv.len() {
        let token = argv[i].as_str();
        if token == "--" {
            break;
        }
        match option_name(token) {
            "json" => json = true,
            "color" => color = true,
            "no-color" => no_color = true,
            "value" | "gen-kind" | "ttl" | "env" | "memfd" | "manifest" | "url" | "hook" | "-v" => {
                i = (i + 2).min(argv.len());
                continue;
            }
            "generate" | "quiet" | "export" | "force" | "stdin" | "requires-consent"
            | "requires-fido2" | "version" | "help" | "-g" | "-q" | "-e" | "-f" => {}
            _ if token.starts_with('-') => {}
            _ if matches!(command, "exec" | "protect-agent") => break,
            _ => {}
        }
        i += 1;
    }
    (json, color, no_color)
}
/// Compute the mode from argv + environment and install it.
/// Idempotent: the OnceLock ignores repeat set() calls.
///
/// Color precedence (highest first):
///   1. NO_COLOR env var set      → off
///   2. --no-color flag           → off
///   3. CLICOLOR_FORCE=1 env      → on
///   4. --color flag              → on
///   5. default                   → off
pub fn init_from_argv(argv: &[String]) {
    let (json, color_flag, no_color_flag) = mode_flags(argv);

    let no_color_env = std::env::var_os("NO_COLOR").is_some();
    let force_env = std::env::var_os("CLICOLOR_FORCE")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false);

    let color = !(no_color_env || no_color_flag) && (force_env || color_flag);

    let _ = CLI_MODE.set(CliMode { json, color });
}

/// Current mode. Before init_from_argv runs, returns the default (all false).
pub fn mode() -> CliMode {
    CLI_MODE.get().copied().unwrap_or_default()
}

pub fn json_mode() -> bool {
    mode().json
}
pub fn use_color() -> bool {
    mode().color
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper that computes a CliMode without touching the global OnceLock,
    // so tests remain order-independent.
    fn compute(argv: &[&str], no_color_env: bool, force_env: Option<&str>) -> CliMode {
        let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let (json, c_flag, nc_flag) = mode_flags(&owned);
        let force = force_env
            .map(|v| v != "0" && !v.is_empty())
            .unwrap_or(false);
        let color = !(no_color_env || nc_flag) && (force || c_flag);
        CliMode { json, color }
    }

    #[test]
    fn default_is_no_color_no_json() {
        let m = compute(&["kepr", "list"], false, None);
        assert!(!m.json);
        assert!(!m.color);
    }

    #[test]
    fn color_flag_enables_color() {
        let m = compute(&["kepr", "--color", "list"], false, None);
        assert!(m.color);
    }

    #[test]
    fn no_color_env_overrides_color_flag() {
        let m = compute(&["kepr", "--color", "list"], true, None);
        assert!(!m.color, "NO_COLOR env must win over --color");
    }

    #[test]
    fn no_color_flag_overrides_force_env() {
        let m = compute(&["kepr", "--no-color", "list"], false, Some("1"));
        assert!(!m.color, "--no-color must win over CLICOLOR_FORCE");
    }

    #[test]
    fn clicolor_force_enables_color() {
        let m = compute(&["kepr", "list"], false, Some("1"));
        assert!(m.color);
    }

    #[test]
    fn json_is_independent_of_color() {
        let m = compute(&["kepr", "--json", "list"], false, None);
        assert!(m.json);
        assert!(!m.color);
    }

    #[test]
    fn bare_global_flags_match_double_hyphen_flags() {
        let bare = compute(&["kepr", "json", "color", "list"], false, None);
        let dashed = compute(&["kepr", "--json", "--color", "list"], false, None);
        assert_eq!(bare.json, dashed.json);
        assert_eq!(bare.color, dashed.color);

        let no_color = compute(&["kepr", "color", "no-color", "list"], false, Some("1"));
        assert!(!no_color.color);
    }

    #[test]
    fn bare_json_does_not_capture_a_key_or_value() {
        assert!(!compute(&["kepr", "get", "json"], false, None).json);
        assert!(!compute(&["kepr", "set", "KEY", "value", "json"], false, None).json);
        assert!(compute(&["kepr", "get", "KEY", "json"], false, None).json);
    }
}
