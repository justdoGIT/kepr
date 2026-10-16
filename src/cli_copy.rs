// cli_copy.rs — `kepr copy NAME [--clear SECS]` (agent vault P10.9).
// Puts a stored value on the clipboard (wl-copy on Wayland, else xclip
// or xsel on X11) and clears it after SECS seconds (default 20), but
// only if the clipboard still holds that value: whatever the user copied
// in the meantime is left alone. The value goes to the tool's stdin,
// never to argv; the detached clearer (`kepr __clipboard-clear`) gets
// only a SHA-256 of it, on stdin. `take_clipboard` goes the other way,
// for `kepr agent add --from-clipboard` (T12.12): read once, then clear.
// wl-copy keeps what it serves in a file under /tmp: on a disk-backed
// /tmp it runs under `kepr __private-tmp`, which gives it a tmpfs /tmp of
// its own (T12.46). On Wayland, kepr first serves the selection itself
// with the password-manager hint (T12.47, cli_clip/), as it does on X11
// (T12.48); wl-copy, xclip and xsel are the fallbacks where that is not
// possible.

use std::ffi::{OsStr, OsString};
use std::io::{BufRead, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cli_exec::{CredFetcher, DaemonFetcher};

pub const DEFAULT_CLEAR_SECS: u64 = 20;
const NO_TOOL: &str = "no clipboard tool found (install wl-clipboard, xclip or xsel)";
/// Largest clipboard value `take_clipboard` accepts; keys are far smaller.
const MAX_PASTE: usize = 64 * 1024;

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
            // An explicit type: wl-copy never sniffs the value (xdg-mime).
            Tool::WlCopy => &["wl-copy", "--type", "text/plain;charset=utf-8"],
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

/// Run `cmd` with `input` on its stdin (or read its stdout): its exit
/// status and output, None when it could not start.
fn run<S: AsRef<OsStr>>(cmd: &[S], input: Option<&[u8]>) -> Option<(ExitStatus, Vec<u8>)> {
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        // Writing: no stdout pipe. xclip forks a child that keeps serving
        // the selection and inherits stdout, so waiting for EOF on a pipe
        // would block until another app took the clipboard.
        .stdout(if input.is_some() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(data) = input {
        // A child that exits before reading (`__private-tmp` exit 3) breaks
        // the pipe: its exit status, not the write error, is the answer.
        let _ = child.stdin.take()?.write_all(data); // stdin closes on drop
        return Some((child.wait().ok()?, Vec::new()));
    }
    let out = child.wait_with_output().ok()?;
    Some((out.status, out.stdout))
}

fn run_ok<S: AsRef<OsStr>>(cmd: &[S], input: Option<&[u8]>) -> Option<Vec<u8>> {
    run(cmd, input).and_then(|(st, out)| st.success().then_some(out))
}

/// wl-copy, under `kepr __private-tmp` unless /tmp is already in memory.
fn wl_copy_argv(tmp_on_memory: bool, kepr: &Path) -> Vec<OsString> {
    let plain = Tool::WlCopy.copy_cmd().iter().map(OsString::from);
    if tmp_on_memory {
        return plain.collect();
    }
    let wrap = [
        kepr.as_os_str().to_owned(),
        "__private-tmp".into(),
        "--".into(),
    ];
    wrap.into_iter().chain(plain).collect()
}

/// A human-mode note (stdout carries the JSON reply in `--json` mode).
fn note(say: &dyn Fn()) {
    if !crate::cli_ui::json_mode() {
        say();
    }
}

/// Hand `value` to the clipboard tool on stdin.
fn copy_value(t: Tool, value: &[u8]) -> Result<(), String> {
    let failed = || Err(format!("{} failed", t.copy_cmd()[0]));
    let tmp_on_memory = crate::cli_memfs::path_on_memory_fs(Path::new("/tmp"));
    if t == Tool::WlCopy && !tmp_on_memory {
        let wrapped = std::env::current_exe()
            .ok()
            .and_then(|kepr| run(&wl_copy_argv(false, &kepr), Some(value)));
        match wrapped.map(|(st, _)| (st.success(), st.code())) {
            Some((true, _)) => return Ok(()),
            Some((false, Some(crate::cli_memfs::PRIVATE_TMP_UNAVAILABLE))) | None => note(&|| {
                crate::cli_ui::warn(
                    "the value passes through a file in /tmp while it is on the clipboard \
                     (user namespaces unavailable)",
                )
            }),
            Some((false, _)) => return failed(),
        }
    }
    match run_ok(t.copy_cmd(), Some(value)) {
        Some(_) => Ok(()),
        None => failed(),
    }
}

/// `kepr VERB` (internal) as a detached child: its own session, so closing
/// the terminal doesn't end it; stdin piped, output dropped.
pub fn detached_kepr(verb: &str) -> std::io::Result<Command> {
    let mut c = Command::new(std::env::current_exe()?);
    c.arg(verb)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe; detaches the child from the
    // terminal so closing it doesn't cancel the clear.
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    Ok(c)
}

pub fn cmd_copy(name: &str, clear_secs: u64) -> Response {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let x11 = std::env::var_os("DISPLAY").is_some();
    let t = tool(wayland, x11, &on_path);
    if !wayland && !x11 {
        return Response::fail(NO_TOOL);
    }
    let name = name.to_uppercase();
    let value = match DaemonFetcher.fetch(&name) {
        Ok(v) => v,
        Err(e) => return Response::fail(e),
    };
    let copied = format!("{name} copied; clipboard clears in {clear_secs}s");
    // T12.47 / T12.48: kepr serves the selection itself, with the
    // password-manager hint, and drops it after SECS; no clearer needed.
    // An X11 session is one without WAYLAND_DISPLAY (XWayland goes the
    // Wayland way).
    use crate::cli_clip::Backend;
    let backend = if wayland {
        Backend::Wayland
    } else {
        Backend::X11
    };
    if crate::cli_clip::handed_off(backend, clear_secs, &value) {
        crate::cli_ui::ok(&copied);
        return Response::Pong;
    }
    let Some(t) = t else {
        return Response::fail(NO_TOOL);
    };
    if let Err(e) = copy_value(t, value.as_bytes()) {
        return Response::fail(e);
    }
    note(&|| {
        crate::cli_ui::info(&format!(
            "this desktop gives clipboard managers no hint; the value is cleared after {clear_secs} s"
        ))
    });
    let job = format!("{}\n{clear_secs}\n{}\n", t.id(), digest(value.as_bytes()));
    drop(value);
    match detached_kepr("__clipboard-clear").and_then(|mut c| c.spawn()) {
        Ok(mut child) => {
            let _ = child.stdin.take().map(|mut s| s.write_all(job.as_bytes()));
        }
        _ => crate::cli_ui::warn("could not start the clipboard clearer; clear it yourself"),
    }
    crate::cli_ui::ok(&copied);
    Response::Pong
}

/// The clipboard's bytes as a value: one trailing LF or CRLF trimmed.
/// Errors never carry the bytes.
pub fn clipboard_text(raw: Zeroizing<Vec<u8>>) -> Result<ZeroString, String> {
    let nl = [&b"\r\n"[..], b"\n"]
        .into_iter()
        .find(|nl| raw.ends_with(nl));
    let end = raw.len() - nl.map_or(0, <[u8]>::len);
    let text = std::str::from_utf8(&raw[..end]).map_err(|_| "clipboard does not hold text")?;
    if text.is_empty() {
        return Err("empty value — nothing stored".into());
    }
    Ok(ZeroString::from_string(text.to_string()))
}

/// Run `cmd` and read its stdout into a buffer allocated once (growing
/// would leave copies behind), at most `MAX_PASTE` bytes.
fn paste(cmd: &[&str]) -> Result<Zeroizing<Vec<u8>>, String> {
    let failed = || format!("{} could not read the clipboard", cmd[0]);
    let mut child = Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| failed())?;
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_PASTE + 1));
    let out = child.stdout.take().ok_or_else(failed)?;
    let read = out.take(MAX_PASTE as u64 + 1).read_to_end(&mut buf);
    if buf.len() > MAX_PASTE {
        let _ = child.kill();
        let _ = child.wait();
        return Err("the clipboard holds more than 64 KiB; nothing stored".into());
    }
    match (read, child.wait()) {
        (Ok(_), Ok(s)) if s.success() => Ok(buf),
        _ => Err(failed()),
    }
}

/// Read the clipboard once, then clear it. The clear runs whatever the
/// read gave, so a refused value doesn't stay on the clipboard either.
pub fn take_clipboard() -> Result<ZeroString, String> {
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let x11 = std::env::var_os("DISPLAY").is_some();
    // Empty stdin and no stdout pipe: xclip's forked selection server
    // must not hold a pipe this process would wait on.
    let mut clear = |cmd: &[&str]| run_ok(cmd, Some(&[])).is_some();
    take_with(tool(wayland, x11, &on_path), &mut paste, &mut clear)
}

type Paste<'a> = &'a mut dyn FnMut(&[&str]) -> Result<Zeroizing<Vec<u8>>, String>;

fn take_with(
    t: Option<Tool>,
    paste: Paste,
    clear: &mut dyn FnMut(&[&str]) -> bool,
) -> Result<ZeroString, String> {
    let t = t.ok_or(NO_TOOL)?;
    let raw = paste(t.paste_cmd());
    let cleared = clear(t.clear_cmd());
    let value = clipboard_text(raw?)?;
    if !cleared {
        return Err(format!(
            "could not clear the clipboard ({} failed); clear it yourself — nothing stored",
            t.clear_cmd()[0]
        ));
    }
    Ok(value)
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
    if run_ok(t.paste_cmd(), None).is_some_and(|now| &digest(&zeroize::Zeroizing::new(now)) == want)
    {
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

    fn raw(b: &[u8]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(b.to_vec())
    }

    #[test]
    fn clipboard_text_trims_one_newline_and_refuses_junk() {
        assert_eq!(
            clipboard_text(raw(b"sk-ant-x\n")).unwrap().as_str(),
            "sk-ant-x"
        );
        assert_eq!(clipboard_text(raw(b"a\r\n")).unwrap().as_str(), "a");
        assert_eq!(clipboard_text(raw(b"a\n\n")).unwrap().as_str(), "a\n");
        let e = clipboard_text(raw(b"sk-\xff\xfeQZ")).unwrap_err();
        assert_eq!(e, "clipboard does not hold text");
        assert!(!e.contains("sk-") && !e.contains("QZ"));
        for empty in [&b""[..], b"\n", b"\r\n"] {
            assert_eq!(
                clipboard_text(raw(empty)).unwrap_err(),
                "empty value — nothing stored"
            );
        }
    }

    #[test]
    fn take_clipboard_reads_once_and_always_clears() {
        let mut cleared = Vec::new();
        let v = take_with(
            Some(Tool::Xclip),
            &mut |c| {
                assert_eq!(c, Tool::Xclip.paste_cmd());
                Ok(raw(b"xai-123\n"))
            },
            &mut |c| {
                cleared.push(c.join(" "));
                true
            },
        )
        .unwrap();
        assert_eq!(v.as_str(), "xai-123");
        assert_eq!(cleared, vec!["xclip -selection clipboard -i /dev/null"]);
        // A failed read, an empty value or a failed clear: the clear still runs.
        for (paste, clear_ok, want) in [
            (Err("wl-paste failed".to_string()), true, "wl-paste failed"),
            (Ok(raw(b"")), true, "empty value — nothing stored"),
            (Ok(raw(b"k")), false, "could not clear the clipboard"),
        ] {
            let mut ran = 0;
            let mut paste = Some(paste);
            let e = take_with(
                Some(Tool::WlCopy),
                &mut |_| paste.take().unwrap(),
                &mut |c| {
                    assert_eq!(c, ["wl-copy", "--clear"]);
                    ran += 1;
                    clear_ok
                },
            )
            .unwrap_err();
            assert!(e.contains(want), "{e}");
            assert_eq!(ran, 1);
        }
    }

    #[test]
    fn paste_reads_stdout_bounded() {
        assert_eq!(
            &paste(&["sh", "-c", "printf 'ab\\n'"]).unwrap()[..],
            b"ab\n"
        );
        let e = paste(&["sh", "-c", "head -c 70000 /dev/zero"]).unwrap_err();
        assert!(e.contains("64 KiB"), "{e}");
        assert!(paste(&["false"]).is_err());
        assert!(paste(&["kepr-no-such-clipboard-tool"]).is_err());
    }

    #[test]
    fn take_clipboard_without_a_tool_names_the_packages() {
        let e = take_with(None, &mut |_| unreachable!(), &mut |_| unreachable!()).unwrap_err();
        for pkg in ["wl-clipboard", "xclip", "xsel"] {
            assert!(e.contains(pkg), "{e}");
        }
    }

    #[test]
    fn wl_copy_offers_text_plain() {
        assert_eq!(
            Tool::WlCopy.copy_cmd(),
            ["wl-copy", "--type", "text/plain;charset=utf-8"]
        );
    }

    #[test]
    fn xclip_and_xsel_argv_unchanged() {
        assert_eq!(Tool::Xclip.copy_cmd(), ["xclip", "-selection", "clipboard"]);
        assert_eq!(Tool::Xsel.copy_cmd(), ["xsel", "--clipboard", "--input"]);
    }

    #[test]
    fn wl_copy_runs_plain_when_tmp_is_in_memory() {
        let argv = wl_copy_argv(true, Path::new("/usr/bin/kepr"));
        assert_eq!(argv, ["wl-copy", "--type", "text/plain;charset=utf-8"]);
    }

    #[test]
    fn wl_copy_gets_a_private_tmp_when_tmp_is_on_disk() {
        let argv = wl_copy_argv(false, Path::new("/usr/bin/kepr"));
        assert_eq!(
            argv,
            [
                "/usr/bin/kepr",
                "__private-tmp",
                "--",
                "wl-copy",
                "--type",
                "text/plain;charset=utf-8"
            ]
        );
    }

    #[test]
    fn tool_ids_round_trip() {
        for t in [Tool::WlCopy, Tool::Xclip, Tool::Xsel] {
            assert_eq!(Tool::from_id(t.id()), Some(t));
        }
        assert_eq!(digest(b"abc").len(), 64);
    }
}
