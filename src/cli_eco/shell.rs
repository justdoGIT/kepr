// shell.rs — `kepr shell` (T8.01): an interactive prompt that runs kepr
// verbs without retyping `kepr`.
// batch: eco
//
// Each line is split shell-style and run as a child `kepr` process with
// the terminal inherited, so every verb behaves exactly as on the command
// line (exit codes, `--json`, prompts). The daemon answers one request per
// connection, so there is no long-lived connection to keep; the child
// opens its own, as the CLI always does.
//
// Secrets: a line that carries a value inline (`--value`, `--field k=v`)
// is refused before it is run or recorded. `set NAME` with no value runs
// the child's masked entry (cli_input.rs), which reads the terminal with
// echo off: the value never passes through this process, its line buffer
// or its history. History lives in memory only and dies with the shell.

use std::io::{BufRead, IsTerminal, Write};

use kepr_core::protocol::Response;

/// Lines kept for `history` / `!N`; oldest dropped first.
pub const HISTORY_MAX: usize = 1000;

/// POSIX-shell-style word splitting: whitespace separates words, `'…'` is
/// literal, `"…"` honours `\"` `\\` `\$` `` \` `` (other backslashes are
/// kept), a bare `\` escapes the next character, and a word starting with
/// `#` starts a comment.
pub fn split_words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '#' if !in_word => break,
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => return Err("unterminated ' quote".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\' | '$' | '`')) => cur.push(e),
                            Some(e) => {
                                cur.push('\\');
                                cur.push(e);
                            }
                            None => return Err("unterminated \" quote".into()),
                        },
                        Some(ch) => cur.push(ch),
                        None => return Err("unterminated \" quote".into()),
                    }
                }
            }
            '\\' => match chars.next() {
                Some(e) => {
                    in_word = true;
                    cur.push(e);
                }
                None => return Err("trailing backslash".into()),
            },
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

/// Why a line may not run here: an inline value would sit in the shell's
/// history (and in the child's argv).
fn refusal(argv: &[String]) -> Option<&'static str> {
    if argv.first().map(String::as_str) == Some("shell") {
        return Some("already in kepr shell");
    }
    let mut it = argv.iter().peekable();
    while let Some(a) = it.next() {
        if a == "--value" || a.starts_with("--value=") {
            return Some("values are typed at the masked prompt: run `set NAME` without --value");
        }
        if a == "--stdin" {
            return Some("the shell reads its own input; run `set NAME` and use the masked prompt");
        }
        let field = if a == "--field" {
            it.peek().map(|s| s.as_str())
        } else {
            a.strip_prefix("--field=")
        };
        if let Some(kv) = field {
            if kv.split_once('=').is_some_and(|(_, v)| v != "-") {
                return Some(
                    "inline field values would stay in the history; use --field NAME=- (masked prompt)",
                );
            }
        }
    }
    None
}

pub enum Flow {
    Continue,
    Exit,
}

#[derive(Default)]
pub struct Shell {
    history: Vec<String>,
}

impl Shell {
    fn recall(&self, text: &str) -> Option<Result<String, String>> {
        let n = text.strip_prefix('!')?;
        let hit = if n == "!" {
            self.history.last()
        } else {
            n.parse::<usize>()
                .ok()
                .and_then(|i| i.checked_sub(1))
                .and_then(|i| self.history.get(i))
        };
        Some(hit.cloned().ok_or_else(|| format!("no history entry {n}")))
    }

    /// Handle one input line; `run` executes a kepr argv and returns its
    /// exit code.
    pub fn line(
        &mut self,
        raw: &str,
        out: &mut dyn Write,
        run: &mut dyn FnMut(&[String]) -> i32,
    ) -> Flow {
        let mut text = raw.trim().to_string();
        if let Some(r) = self.recall(&text) {
            match r {
                Ok(t) => {
                    let _ = writeln!(out, "{t}");
                    text = t;
                }
                Err(e) => {
                    let _ = writeln!(out, "kepr shell: {e}");
                    return Flow::Continue;
                }
            }
        }
        let mut argv = match split_words(&text) {
            Ok(a) => a,
            Err(e) => {
                let _ = writeln!(out, "kepr shell: {e}");
                return Flow::Continue;
            }
        };
        if argv.first().map(String::as_str) == Some("kepr") {
            argv.remove(0);
        }
        match argv.first().map(String::as_str) {
            None => return Flow::Continue,
            Some("exit" | "quit") => return Flow::Exit,
            Some("help") => {
                let _ = writeln!(
                    out,
                    "Type kepr verbs without `kepr` (ls, get NAME --quiet, set NAME, copy NAME, …).\n\
                     history | !N | !! re-run | exit (or Ctrl-D). `--help` lists every verb."
                );
                return Flow::Continue;
            }
            Some("history") => {
                for (i, h) in self.history.iter().enumerate() {
                    let _ = writeln!(out, "{:>4}  {h}", i + 1);
                }
                return Flow::Continue;
            }
            _ => {}
        }
        if let Some(why) = refusal(&argv) {
            let _ = writeln!(out, "kepr shell: {why}");
            return Flow::Continue;
        }
        if self.history.len() == HISTORY_MAX {
            self.history.remove(0);
        }
        self.history.push(text);
        run(&argv);
        Flow::Continue
    }
}

/// Read lines until `exit` / `quit` / EOF.
pub fn repl(
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    prompt: bool,
    run: &mut dyn FnMut(&[String]) -> i32,
) -> Shell {
    let mut sh = Shell::default();
    let mut buf = String::new();
    loop {
        if prompt {
            eprint!("kepr> ");
            let _ = std::io::stderr().flush();
        }
        buf.clear();
        match input.read_line(&mut buf) {
            Ok(0) | Err(_) => {
                if prompt {
                    eprintln!();
                }
                break;
            }
            Ok(_) => {}
        }
        let flow = sh.line(&buf, out, run);
        let _ = out.flush();
        if let Flow::Exit = flow {
            break;
        }
    }
    sh
}

extern "C" fn on_sigint(_: libc::c_int) {}

/// Ctrl-C interrupts the running child, not the shell. A handler (not
/// SIG_IGN) so children get the default disposition back at exec.
fn catch_sigint() {
    // SAFETY: plain sigaction installing a handler that does nothing.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigint as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

fn run_child(argv: &[String]) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kepr shell: cannot find the kepr binary: {e}");
            return 1;
        }
    };
    match std::process::Command::new(exe).args(argv).status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("kepr shell: {e}");
            1
        }
    }
}

pub fn cmd_shell(args: &[String]) -> Response {
    if let Some(a) = args.iter().find(|a| !a.starts_with("--")) {
        return Response::fail(format!("kepr shell takes no arguments (got {a})"));
    }
    let tty = std::io::stdin().is_terminal();
    if tty {
        catch_sigint();
        eprintln!("kepr shell: type `help`, or `exit` / Ctrl-D to leave. History is not saved.");
    }
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    repl(&mut input, &mut std::io::stdout(), tty, &mut run_child);
    Response::Pong
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn splits_on_whitespace_and_quotes() {
        assert_eq!(split_words("  ls  ").unwrap(), w(&["ls"]));
        assert_eq!(
            split_words("record add K --field 'note=a b'").unwrap(),
            w(&["record", "add", "K", "--field", "note=a b"])
        );
        assert_eq!(
            split_words(r#"exec -- sh -c "echo \"hi\" \$X""#).unwrap(),
            w(&["exec", "--", "sh", "-c", r#"echo "hi" $X"#])
        );
        assert_eq!(split_words(r"a\ b c").unwrap(), w(&["a b", "c"]));
        assert_eq!(split_words("a '' b").unwrap(), w(&["a", "", "b"]));
        assert_eq!(split_words(r#""a\nb""#).unwrap(), w(&[r"a\nb"]));
        assert_eq!(split_words("ls # comment").unwrap(), w(&["ls"]));
        assert_eq!(split_words("a#b").unwrap(), w(&["a#b"]));
        assert_eq!(split_words("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn rejects_unterminated_quotes_and_trailing_backslash() {
        assert!(split_words("get 'X").is_err());
        assert!(split_words("get \"X").is_err());
        assert!(split_words("get X\\").is_err());
    }

    fn drive(input: &str) -> (Vec<Vec<String>>, Shell, String) {
        let mut ran = Vec::new();
        let mut out = Vec::new();
        let sh = repl(
            &mut std::io::Cursor::new(input.as_bytes().to_vec()),
            &mut out,
            false,
            &mut |a: &[String]| {
                ran.push(a.to_vec());
                0
            },
        );
        (ran, sh, String::from_utf8(out).unwrap())
    }

    #[test]
    fn runs_verbs_until_exit() {
        let (ran, sh, _) = drive("ls\nget FOO --quiet\nexit\nls\n");
        assert_eq!(ran, vec![w(&["ls"]), w(&["get", "FOO", "--quiet"])]);
        assert_eq!(sh.history, w(&["ls", "get FOO --quiet"]));
    }

    #[test]
    fn eof_ends_the_shell() {
        let (ran, _, _) = drive("status\n");
        assert_eq!(ran, vec![w(&["status"])]);
        let (ran, _, _) = drive("");
        assert!(ran.is_empty());
        let (ran, _, _) = drive("quit\nls\n");
        assert!(ran.is_empty());
    }

    #[test]
    fn inline_secret_values_never_run_or_reach_history() {
        let (ran, sh, out) = drive(
            "set FOO --value hunter2\nset FOO --value=hunter2\n\
             record add R --type login --field password=hunter2\n\
             set FOO --stdin\nhistory\n",
        );
        assert!(ran.is_empty(), "{ran:?}");
        assert!(sh.history.is_empty());
        assert!(!out.contains("hunter2"));
        assert!(out.contains("masked prompt"));
    }

    #[test]
    fn set_without_value_goes_to_the_masked_prompt() {
        // The child `kepr set FOO` reads the value with cli_input's masked
        // entry straight from the terminal; the shell never sees it.
        let (ran, sh, _) = drive("set foo\nrecord add R --type login --field password=-\n");
        assert_eq!(ran[0], w(&["set", "foo"]));
        assert_eq!(ran[1][6], "password=-");
        assert_eq!(sh.history.len(), 2);
    }

    #[test]
    fn history_builtin_and_rerun() {
        let (ran, sh, out) = drive("ls\nstatus\nhistory\n!1\n!!\n!9\n");
        assert_eq!(
            ran,
            vec![w(&["ls"]), w(&["status"]), w(&["ls"]), w(&["ls"])]
        );
        assert!(out.contains("1  ls") && out.contains("2  status"), "{out}");
        assert!(out.contains("no history entry 9"));
        assert_eq!(sh.history.len(), 4);
    }

    #[test]
    fn kepr_prefix_and_nested_shell() {
        let (ran, _, out) = drive("kepr ls\nshell\nkepr\n");
        assert_eq!(ran, vec![w(&["ls"])]);
        assert!(out.contains("already in kepr shell"));
    }

    #[test]
    fn parse_errors_are_reported_not_run() {
        let (ran, sh, out) = drive("get 'X\n");
        assert!(ran.is_empty());
        assert!(sh.history.is_empty());
        assert!(out.contains("unterminated"));
    }

    #[test]
    fn history_is_bounded() {
        let input: String = (0..HISTORY_MAX + 5)
            .map(|i| format!("get K{i}\n"))
            .collect();
        let (_, sh, _) = drive(&input);
        assert_eq!(sh.history.len(), HISTORY_MAX);
        assert_eq!(sh.history[0], "get K5");
    }
}
