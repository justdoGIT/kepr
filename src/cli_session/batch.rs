// cli_session/batch.rs — `kepr batch FILE [--keep-going]` (T11.18): run
// one kepr command per line, each as a child `kepr` (so every verb
// behaves exactly as on the command line). Lines are split like a shell
// (quotes, `#` comments; `cli_eco::split_words`), a leading `kepr` is
// optional, blank lines are skipped. The first failing line stops the
// batch unless `--keep-going`.
//
// Values never go in a batch file: a line with `--value` / `-v`,
// `--stdin` or an inline `--field NAME=VALUE` is refused, and every line
// is checked before the first one runs, so a refused file changes
// nothing. Use `--generate` or `kepr://` references instead. FILE `-`
// reads the batch from stdin (the children then get no stdin).

use std::io::Read;

use kepr_core::protocol::Response;
use kepr_core::protocol_session::SessionResponse;

use crate::cli_ui::{dim, json_mode, ok};

const USAGE: &str = "usage: kepr batch FILE [--keep-going]   (FILE - = stdin)";
const NO_VALUES: &str = "values never go in a batch file: use --generate or a kepr:// reference";
const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct Line {
    pub no: usize,
    pub argv: Vec<String>,
}

/// Why `argv` may not run in a batch. Words after `--` belong to the
/// command `kepr exec` starts and aren't checked.
fn refusal(argv: &[String]) -> Option<&'static str> {
    let verb = argv.iter().find(|a| !a.starts_with('-'));
    if matches!(verb.map(String::as_str), Some("batch" | "shell")) {
        return Some("batch and shell can't run inside a batch");
    }
    let mut it = argv.iter().peekable();
    while let Some(a) = it.next() {
        if a == "--" {
            break;
        }
        if a == "--value" || a == "-v" || a.starts_with("--value=") {
            return Some(NO_VALUES);
        }
        if a == "--stdin" {
            return Some("--stdin: a batch has no input for values; use --generate");
        }
        let field = if a == "--field" {
            it.peek().map(|s| s.as_str())
        } else {
            a.strip_prefix("--field=")
        };
        if field.is_some_and(|kv| kv.split_once('=').is_some_and(|(_, v)| v != "-")) {
            return Some(NO_VALUES);
        }
    }
    None
}

/// Every command of a batch file, or the first line that can't run.
pub fn parse(text: &str) -> Result<Vec<Line>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let no = i + 1;
        let mut argv = crate::cli_eco::split_words(raw).map_err(|e| format!("line {no}: {e}"))?;
        if argv.first().map(String::as_str) == Some("kepr") {
            argv.remove(0);
        }
        if argv.is_empty() {
            continue;
        }
        if let Some(why) = refusal(&argv) {
            return Err(format!("line {no}: {why}"));
        }
        out.push(Line { no, argv });
    }
    Ok(out)
}

/// Run `lines` through `exec` (argv → exit code). Returns how many ran
/// and the (line, exit code) of each failure.
pub fn run(
    lines: &[Line],
    keep_going: bool,
    exec: &mut dyn FnMut(&Line) -> i32,
) -> (u32, Vec<(usize, i32)>) {
    let (mut ran, mut failed) = (0, Vec::new());
    for l in lines {
        ran += 1;
        let code = exec(l);
        if code != 0 {
            failed.push((l.no, code));
            if !keep_going {
                break;
            }
        }
    }
    (ran, failed)
}

fn read(path: &str) -> Result<String, String> {
    let mut text = String::new();
    let r = if path == "-" {
        std::io::stdin().take(MAX_BYTES).read_to_string(&mut text)
    } else {
        std::fs::File::open(path).and_then(|f| f.take(MAX_BYTES).read_to_string(&mut text))
    };
    r.map_err(|e| format!("{path}: {e}"))?;
    if text.len() as u64 >= MAX_BYTES {
        return Err(format!("{path}: larger than 1 MiB"));
    }
    Ok(text)
}

fn child(l: &Line, from_stdin: bool) -> i32 {
    if !json_mode() {
        dim(&format!("  ▸ line {}: kepr {}", l.no, l.argv.join(" ")));
    }
    let Ok(exe) = std::env::current_exe() else {
        return 127;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(&l.argv);
    if from_stdin {
        cmd.stdin(std::process::Stdio::null());
    }
    cmd.status().map_or(127, |s| s.code().unwrap_or(1))
}

pub fn cmd_batch(args: &[&str]) -> Response {
    let keep_going = args.contains(&"--keep-going");
    let files: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| *a != "--keep-going")
        .collect();
    let [path] = files.as_slice() else {
        return Response::fail(USAGE);
    };
    if path.starts_with("--") {
        return Response::fail(USAGE);
    }
    let lines = match read(path).and_then(|t| parse(&t)) {
        Ok(l) => l,
        Err(e) => return Response::fail(e),
    };
    let from_stdin = *path == "-";
    let (ran, failed) = run(&lines, keep_going, &mut |l| child(l, from_stdin));
    if !failed.is_empty() {
        let which: Vec<String> = failed
            .iter()
            .map(|(n, c)| format!("line {n} (exit {c})"))
            .collect();
        return Response::fail(format!("batch failed: {}", which.join(", ")));
    }
    if !json_mode() {
        ok(&format!("{ran} command(s) ran."));
    }
    Response::Session(SessionResponse::BatchOk { ran })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_comments_quotes_and_the_optional_kepr() {
        let text = "# setup\n\nset DB_PASS --generate   # new one\n\
                    kepr ln 'DB' DB_PASS\n  exec --env \"U=kepr://REC/user\" -- curl -v x\n";
        assert_eq!(
            parse(text).unwrap(),
            [
                Line {
                    no: 3,
                    argv: w(&["set", "DB_PASS", "--generate"])
                },
                Line {
                    no: 4,
                    argv: w(&["ln", "DB", "DB_PASS"])
                },
                Line {
                    no: 5,
                    argv: w(&[
                        "exec",
                        "--env",
                        "U=kepr://REC/user",
                        "--",
                        "curl",
                        "-v",
                        "x"
                    ])
                },
            ]
        );
        assert!(parse("ls 'open").unwrap_err().starts_with("line 1:"));
    }

    #[test]
    fn a_line_with_a_value_is_refused_before_anything_runs() {
        for bad in [
            "set K --value s3cret",
            "set K -v s3cret",
            "set K --value=s3cret",
            "set K --stdin",
            "record add L --field password=hunter2",
            "record add L --field=password=hunter2",
            "batch other.txt",
        ] {
            let text = format!("ls\n{bad}\n");
            let e = parse(&text).unwrap_err();
            assert!(e.starts_with("line 2:"), "{bad}: {e}");
            assert!(!e.contains("s3cret") && !e.contains("hunter2"), "{e}");
        }
        assert!(parse("record add L --field password=-").is_ok());
    }

    #[test]
    fn stops_at_the_first_error_unless_keep_going() {
        let lines = parse("ls\nget A\nget B\nls\n").unwrap();
        let mut seen = Vec::new();
        let mut exec = |l: &Line| {
            seen.push(l.no);
            i32::from(l.argv[0] == "get")
        };
        assert_eq!(run(&lines, false, &mut exec), (2, vec![(2, 1)]));
        assert_eq!(seen, [1, 2]);
        seen.clear();
        let mut exec = |l: &Line| {
            seen.push(l.no);
            i32::from(l.argv[0] == "get")
        };
        assert_eq!(run(&lines, true, &mut exec), (4, vec![(2, 1), (3, 1)]));
    }

    #[test]
    fn usage() {
        assert_eq!(cmd_batch(&[]).err_msg(), Some(USAGE));
        assert_eq!(cmd_batch(&["a", "b"]).err_msg(), Some(USAGE));
        assert!(cmd_batch(&["/nonexistent/batch.txt"]).err_msg().is_some());
    }
}
