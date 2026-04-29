// cli_ui.rs — CLI presentation: ANSI colour, status prefixes, JSON output.
//
// The two boolean mode flags (colour, JSON) live in cli_mode behind a single
// OnceLock. This module only pulls them when rendering.

use crate::cli_mode;
use kepr_core::protocol::Response;

// Re-exported for call sites that used to import `cli_ui::json_mode`.
pub use crate::cli_mode::json_mode;

pub fn use_color() -> bool {
    cli_mode::use_color()
}

pub fn color(code: &str, text: &str) -> String {
    if use_color() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn ok(m: &str) {
    println!("  {}  {}", color("0;32", "✓"), m);
}
pub fn err(m: &str) {
    eprintln!("  {}  {}", color("0;31", "✗"), m);
}
pub fn warn(m: &str) {
    println!("  {}  {}", color("1;33", "⚠"), m);
}
pub fn info(m: &str) {
    println!("  {}  {}", color("0;36", "·"), m);
}
pub fn einfo(m: &str) {
    eprintln!("  {}  {}", color("0;36", "·"), m);
}
pub fn bold(m: &str) {
    println!("{}", color("1", m));
}
pub fn dim(m: &str) {
    println!("{}", color("2", m));
}

pub fn print_json(resp: &Response) {
    println!("{}", serde_json::to_string_pretty(resp).unwrap_or_default());
}
