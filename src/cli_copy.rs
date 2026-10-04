// cli_copy.rs — `kepr copy NAME [--clear SECS]` (agent vault P10.9).
// Puts a stored value on the clipboard (wl-copy on Wayland, else xclip
// or xsel on X11) and clears it after SECS seconds (default 20) from a
// detached background process. The value is written to the tool's
// stdin, never to argv.

use std::io::Write;
use std::process::{Command, Stdio};

use kepr_core::protocol::Response;

use crate::cli_exec::{CredFetcher, DaemonFetcher};

pub const DEFAULT_CLEAR_SECS: u64 = 20;

/// (copy command, clear command) for the current session.
pub fn tool(
    wayland: bool,
    x11: bool,
    has: &dyn Fn(&str) -> bool,
) -> Option<(Vec<&'static str>, &'static str)> {
    if wayland && has("wl-copy") {
        return Some((vec!["wl-copy"], "wl-copy --clear"));
    }
    if x11 && has("xclip") {
        return Some((
            vec!["xclip", "-selection", "clipboard"],
            "printf '' | xclip -selection clipboard",
        ));
    }
    if x11 && has("xsel") {
        return Some((
            vec!["xsel", "--clipboard", "--input"],
            "xsel --clipboard --clear",
        ));
    }
    None
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

pub fn cmd_copy(name: &str, clear_secs: u64) -> Response {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let x11 = std::env::var_os("DISPLAY").is_some();
    let Some((copy, clear)) = tool(wayland, x11, &on_path) else {
        return Response::fail("no clipboard tool found (install wl-clipboard, xclip or xsel)");
    };
    let value = match DaemonFetcher.fetch(&name.to_uppercase()) {
        Ok(v) => v,
        Err(e) => return Response::fail(e),
    };
    let child = Command::new(copy[0])
        .args(&copy[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn();
    let ok = child.and_then(|mut c| {
        c.stdin.take().expect("piped").write_all(value.as_bytes())?;
        c.wait()
    });
    if !matches!(ok, Ok(s) if s.success()) {
        return Response::fail(format!("{} failed", copy[0]));
    }
    // Detached clearer: survives this process, holds no secret.
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("sleep {clear_secs}; {clear}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    crate::cli_ui::ok(&format!(
        "{} copied; clipboard clears in {clear_secs}s",
        name.to_uppercase()
    ));
    Response::Pong
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_tool_by_session() {
        let all = |_: &str| true;
        assert_eq!(tool(true, true, &all).unwrap().0, vec!["wl-copy"]);
        assert_eq!(tool(false, true, &all).unwrap().0[0], "xclip");
        assert_eq!(tool(false, true, &|b| b == "xsel").unwrap().0[0], "xsel");
        assert!(tool(false, false, &all).is_none());
        assert!(tool(true, false, &|_| false).is_none());
    }
}
