// cli_ui.rs — CLI presentation: ANSI colour, status prefixes, JSON output.
//
// Converted from the original `color!` macro to a plain function so it can be
// imported across module boundaries without macro export headaches.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::protocol::Response;

pub static FORCE_NO_COLOR: AtomicBool = AtomicBool::new(false);

/// Set when `--json` is seen on argv. Lets error paths that fire before
/// Args is built (e.g. CliActivity::parse rejecting an unknown verb) honour
/// JSON mode — no stderr noise, Response::Err on stdout.
pub static FORCE_JSON: AtomicBool = AtomicBool::new(false);

pub fn json_mode() -> bool { FORCE_JSON.load(Ordering::Relaxed) }

extern "C" { fn isatty(fd: i32) -> i32; }

pub fn use_color() -> bool {
    if FORCE_NO_COLOR.load(Ordering::Relaxed) { return false; }
    if std::env::var_os("NO_COLOR").is_some()  { return false; }
    unsafe { isatty(1) != 0 }
}

pub fn color(code: &str, text: &str) -> String {
    if use_color() { format!("\x1b[{code}m{text}\x1b[0m") }
    else           { text.to_string() }
}

pub fn ok(m: &str)    { println!("  {}  {}", color("0;32", "✓"), m); }
pub fn err(m: &str)   { eprintln!("  {}  {}", color("0;31", "✗"), m); }
pub fn warn(m: &str)  { println!("  {}  {}", color("1;33", "⚠"), m); }
pub fn info(m: &str)  { println!("  {}  {}", color("0;36", "·"), m); }
pub fn einfo(m: &str) { eprintln!("  {}  {}", color("0;36", "·"), m); }
pub fn bold(m: &str)  { println!("{}", color("1", m)); }
pub fn dim(m: &str)   { println!("{}", color("2", m)); }

pub fn print_json(resp: &Response) {
    println!("{}", serde_json::to_string_pretty(resp).unwrap_or_default());
}
