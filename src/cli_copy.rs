// cli_copy.rs — `kepr copy NAME [--clear SECS]` (agent vault P10.9).
// Puts a stored value on the clipboard (wl-copy on Wayland, else xclip
// or xsel on X11) and clears it after SECS seconds (default 20), but
// only if the clipboard still holds that value: whatever the user copied
// in the meantime is left alone. The value goes to the tool's stdin,
// never to argv; the detached clearer (`kepr __clipboard-clear`) gets
// only a SHA-256 of it, on stdin.

use std::io::{BufRead, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use kepr_core::protocol::Response;
use sha2::{Digest, Sha256};

use crate::cli_exec::{CredFetcher, DaemonFetcher};

pub const DEFAULT_CLEAR_SECS: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    WlCopy,
    Xclip,
    Xsel,
}

impl Tool {
    fn id(self) -> &'static str {
        match self {
            Tool::WlCopy => "wl",
            Tool::Xclip => "xclip",
            Tool::Xsel => "xsel",
        }
    }
    fn from_id(s: &str) -> Option<Self> {
        [Tool::WlCopy, Tool::Xclip, Tool::Xsel]
            .into_iter()
            .find(|t| t.id() == s)
    }
    fn copy_cmd(self) -> &'static [&'static str] {
        match self {
            Tool::WlCopy => &["wl-copy"],
            Tool::Xclip => &["xclip", "-selection", "clipboard"],
            Tool::Xsel => &["xsel", "--clipboard", "--input"],
        }
    }
    fn paste_cmd(self) -> &'static [&'static str] {
        match self {
            Tool::WlCopy => &["wl-paste", "--no-newline"],
            Tool::Xclip => &["xclip", "-selection", "clipboard", "-o"],
            Tool::Xsel => &["xsel", "--clipboard", "--output"],
        }
    }
    fn clear_cmd(self) -> &'static [&'static str] {
        match self {
            Tool::WlCopy => &["wl-copy", "--clear"],
            Tool::Xclip => &["xclip", "-selection", "clipboard", "-i", "/dev/null"],
            Tool::Xsel => &["xsel", "--clipboard", "--clear"],
        }
    }
}

/// The clipboard tool for the current session.
pub fn tool(wayland: bool, x11: bool, has: &dyn Fn(&str) -> bool) -> Option<Tool> {
    if wayland && has("wl-copy") {
        return Some(Tool::WlCopy);
    }
    if x11 && has("xclip") {
        return Some(Tool::Xclip);
    }
    (x11 && has("xsel")).then_some(Tool::Xsel)
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn run(cmd: &[&str], input: Option<&[u8]>) -> Option<Vec<u8>> {
    let mut child = Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(data) = input {
        child.stdin.take()?.write_all(data).ok()?;
    }
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

pub fn cmd_copy(name: &str, clear_secs: u64) -> Response {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let x11 = std::env::var_os("DISPLAY").is_some();
    let Some(t) = tool(wayland, x11, &on_path) else {
        return Response::fail("no clipboard tool found (install wl-clipboard, xclip or xsel)");
    };
    let value = match DaemonFetcher.fetch(&name.to_uppercase()) {
        Ok(v) => v,
        Err(e) => return Response::fail(e),
    };
    if run(t.copy_cmd(), Some(value.as_bytes())).is_none() {
        return Response::fail(format!("{} failed", t.copy_cmd()[0]));
    }
    let job = format!("{}\n{clear_secs}\n{}\n", t.id(), digest(value.as_bytes()));
    drop(value);
    let clearer = std::env::current_exe().map(|exe| {
        let mut c = Command::new(exe);
        c.arg("__clipboard-clear")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: setsid is async-signal-safe; detaches the clearer from
        // the terminal so closing it doesn't cancel the clear.
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        c.spawn()
    });
    match clearer {
        Ok(Ok(mut child)) => {
            let _ = child.stdin.take().map(|mut s| s.write_all(job.as_bytes()));
        }
        _ => crate::cli_ui::warn("could not start the clipboard clearer; clear it yourself"),
    }
    crate::cli_ui::ok(&format!(
        "{} copied; clipboard clears in {clear_secs}s",
        name.to_uppercase()
    ));
    Response::Pong
}

/// `kepr __clipboard-clear` (internal): read `tool\nsecs\nsha256\n` from
/// stdin, wait, and clear the clipboard if it still holds that value.
pub fn cmd_clipboard_clear() -> Response {
    let lines: Vec<String> = std::io::stdin()
        .lock()
        .lines()
        .take(3)
        .map_while(Result::ok)
        .collect();
    let (Some(t), Some(secs), Some(want)) = (
        lines.first().and_then(|s| Tool::from_id(s)),
        lines.get(1).and_then(|s| s.parse::<u64>().ok()),
        lines.get(2),
    ) else {
        return Response::fail("bad clipboard-clear job");
    };
    std::thread::sleep(std::time::Duration::from_secs(secs));
    if run(t.paste_cmd(), None).is_some_and(|now| &digest(&zeroize::Zeroizing::new(now)) == want) {
        run(t.clear_cmd(), None);
    }
    Response::Pong
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_tool_by_session() {
        let all = |_: &str| true;
        assert_eq!(tool(true, true, &all), Some(Tool::WlCopy));
        assert_eq!(tool(false, true, &all), Some(Tool::Xclip));
        assert_eq!(tool(false, true, &|b| b == "xsel"), Some(Tool::Xsel));
        assert_eq!(tool(false, false, &all), None);
        assert_eq!(tool(true, false, &|_| false), None);
    }

    #[test]
    fn tool_ids_round_trip() {
        for t in [Tool::WlCopy, Tool::Xclip, Tool::Xsel] {
            assert_eq!(Tool::from_id(t.id()), Some(t));
        }
        assert_eq!(digest(b"abc").len(), 64);
    }
}
