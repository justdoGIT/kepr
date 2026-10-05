// tui_term.rs — the terminal side of `kepr ui` (T8.02): raw mode through
// libc termios, the alternate screen, key decoding and the event loop.
// Credentials come from `List` (metadata only); copy runs `kepr copy` so
// the value goes straight to the clipboard tool; delete asks first.
// batch: eco

use std::io::{IsTerminal, Read, Write};
use std::process::{Command, Stdio};

use kepr_core::protocol::{Request, Response};

use super::tui::{render, Action, Key, Row, State};

/// Raw mode + alternate screen for as long as it lives; restored on drop
/// (also when unwinding from a panic).
struct RawTerm {
    orig: libc::termios,
}

impl RawTerm {
    fn enter() -> Result<Self, String> {
        // SAFETY: termios is plain data; tcgetattr fills it for fd 0.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
            return Err("cannot read terminal settings".into());
        }
        let orig = t;
        t.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
        t.c_iflag &= !(libc::IXON | libc::ICRNL);
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &t) } != 0 {
            return Err("cannot switch the terminal to raw mode".into());
        }
        print!("\x1b[?1049h\x1b[?25l");
        let _ = std::io::stdout().flush();
        Ok(RawTerm { orig })
    }
}

impl Drop for RawTerm {
    fn drop(&mut self) {
        print!("\x1b[?25h\x1b[?1049l");
        let _ = std::io::stdout().flush();
        // SAFETY: restores the settings read in `enter`.
        unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &self.orig) };
    }
}

fn term_size() -> (usize, usize) {
    // SAFETY: TIOCGWINSZ fills a winsize struct.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
        (ws.ws_col as usize, ws.ws_row as usize)
    } else {
        (80, 24)
    }
}

/// Decode one read's worth of bytes into keys.
pub fn parse_keys(b: &[u8]) -> Vec<Key> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let k = match b[i] {
            0x1b if b.get(i + 1) == Some(&b'[') || b.get(i + 1) == Some(&b'O') => {
                i += 2;
                let k = match b.get(i) {
                    Some(b'A') => Some(Key::Up),
                    Some(b'B') => Some(Key::Down),
                    Some(b'H') => Some(Key::Home),
                    Some(b'F') => Some(Key::End),
                    _ => None,
                };
                // Skip the rest of an unknown sequence (e.g. `5~`, `1;5C`).
                while i < b.len() && !(0x40..=0x7e).contains(&b[i]) {
                    i += 1;
                }
                i += 1;
                if let Some(k) = k {
                    out.push(k);
                }
                continue;
            }
            0x1b => Key::Esc,
            b'\r' | b'\n' => Key::Enter,
            0x7f | 0x08 => Key::Backspace,
            0x03 | 0x04 => Key::CtrlC,
            c if (0x20..0x7f).contains(&c) => Key::Char(c as char),
            _ => {
                i += 1;
                continue;
            }
        };
        out.push(k);
        i += 1;
    }
    out
}

fn draw(st: &State) {
    let (w, h) = term_size();
    let screen = render(st, w, h);
    let mut buf = String::from("\x1b[H");
    for (i, line) in screen.lines.iter().enumerate() {
        if i > 0 {
            buf.push_str("\r\n");
        }
        if Some(i) == screen.selected {
            buf.push_str("\x1b[7m");
            buf.push_str(line);
            buf.push_str("\x1b[0m");
        } else {
            buf.push_str(line);
        }
    }
    let mut out = std::io::stdout();
    let _ = out.write_all(buf.as_bytes());
    let _ = out.flush();
}

fn load() -> Result<Vec<Row>, String> {
    match crate::client::send_request(&Request::List)? {
        Response::ListOk { credentials, .. } => {
            Ok(credentials.iter().map(Row::from_info).collect())
        }
        Response::Err { error } => Err(error),
        _ => Err("unexpected reply".into()),
    }
}

/// `kepr copy NAME` in a child: the value goes from the daemon to the
/// clipboard tool, never through this screen. Its message becomes the
/// status line.
fn copy(name: &str) -> String {
    let Ok(exe) = std::env::current_exe() else {
        return "cannot find the kepr binary".into();
    };
    let out = Command::new(exe)
        .args(["--no-color", "copy", name])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match out {
        Ok(o) => status_line(&o.stdout, &o.stderr, o.status.success()),
        Err(e) => format!("copy failed: {e}"),
    }
}

/// Last non-empty line of a child's output, without the CLI's glyphs.
fn status_line(stdout: &[u8], stderr: &[u8], ok: bool) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    text.lines()
        .map(|l| l.trim_start_matches(['✓', '✗', '⚠', '·', ' ']).trim_end())
        .rfind(|l| !l.is_empty())
        .unwrap_or(if ok { "copied" } else { "copy failed" })
        .to_string()
}

fn delete(name: &str) -> String {
    let req = Request::Delete {
        name: name.to_string(),
    };
    match crate::client::send_request(&req) {
        Ok(Response::DeleteOk { name }) => format!("deleted {name}"),
        Ok(Response::Err { error }) => error,
        Ok(_) => "unexpected reply".into(),
        Err(e) => e,
    }
}

/// Wait up to `ms` for input; true when a key is ready.
fn wait_input(ms: i32) -> bool {
    let mut p = libc::pollfd {
        fd: 0,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd.
    unsafe { libc::poll(&mut p, 1, ms) > 0 }
}

pub fn cmd_ui(args: &[String]) -> Response {
    if crate::cli_mode::json_mode() {
        return Response::fail("kepr ui is interactive; use `kepr --json ls` for scripts");
    }
    if let Some(a) = args.iter().find(|a| !a.starts_with("--")) {
        return Response::fail(format!("kepr ui takes no arguments (got {a})"));
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Response::fail("kepr ui needs a terminal");
    }
    let mut st = match load() {
        Ok(rows) => State::new(rows),
        Err(e) => return Response::fail(e),
    };
    let _raw = match RawTerm::enter() {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    print!("\x1b[2J");
    let mut size = term_size();
    draw(&st);
    let mut buf = [0u8; 64];
    loop {
        if !wait_input(250) {
            if term_size() != size {
                size = term_size();
                print!("\x1b[2J");
                draw(&st);
            }
            continue;
        }
        let n = match std::io::stdin().read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for k in parse_keys(&buf[..n]) {
            let action = st.key(k);
            if action != Action::None {
                // Repaint from scratch: a daemon started by this command
                // may have logged to the same terminal.
                print!("\x1b[2J");
            }
            match action {
                Action::None => {}
                Action::Quit => return Response::Pong,
                Action::Refresh => match load() {
                    Ok(rows) => {
                        st.set_rows(rows);
                        st.status = "reloaded".into();
                    }
                    Err(e) => st.status = e,
                },
                Action::Copy(name) => st.status = copy(&name),
                Action::Delete(name) => {
                    st.status = delete(&name);
                    if let Ok(rows) = load() {
                        st.set_rows(rows);
                    }
                }
            }
        }
        draw(&st);
    }
    Response::Pong
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_arrows_letters_and_controls() {
        assert_eq!(
            parse_keys(b"\x1b[A\x1b[Bjk/\r\x7f\x03"),
            vec![
                Key::Up,
                Key::Down,
                Key::Char('j'),
                Key::Char('k'),
                Key::Char('/'),
                Key::Enter,
                Key::Backspace,
                Key::CtrlC,
            ]
        );
        assert_eq!(parse_keys(b"\x1b"), vec![Key::Esc]);
        assert_eq!(parse_keys(b"\x1bOH\x1b[F"), vec![Key::Home, Key::End]);
        // Unknown sequences (PgUp, Ctrl-Right) are skipped whole.
        assert_eq!(parse_keys(b"\x1b[5~\x1b[1;5Cq"), vec![Key::Char('q')]);
        assert_eq!(parse_keys(b"\x01\xc3"), Vec::<Key>::new());
    }

    #[test]
    fn status_line_is_the_last_message_without_glyphs() {
        assert_eq!(
            status_line(
                b"  \xe2\x9c\x93  K copied; clipboard clears in 20s\n",
                b"",
                true
            ),
            "K copied; clipboard clears in 20s"
        );
        assert_eq!(
            status_line(b"", b"  \xe2\x9c\x97  credential unavailable\n", false),
            "credential unavailable"
        );
        assert_eq!(status_line(b"", b"", false), "copy failed");
    }
}
