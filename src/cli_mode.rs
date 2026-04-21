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
    let json = argv.iter().any(|a| a == "--json");

    let no_color_env = std::env::var_os("NO_COLOR").is_some();
    let no_color_flag = argv.iter().any(|a| a == "--no-color");
    let force_env = std::env::var_os("CLICOLOR_FORCE")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false);
    let color_flag = argv.iter().any(|a| a == "--color");

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
        let json = owned.iter().any(|a| a == "--json");
        let nc_flag = owned.iter().any(|a| a == "--no-color");
        let c_flag = owned.iter().any(|a| a == "--color");
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
}
