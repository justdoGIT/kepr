// cli_agent_adopt_history.rs — keys kept in shell history (T12.19).
//
// bash, zsh and fish history files: each entry's command (zsh's
// `: <time>:<secs>;` and fish's `- cmd: ` prefixes stripped) is read like
// a .env line, plus every leading `NAME=VALUE` word (`A=x B=y cmd`).
// Only values written out in full count (`literal`): `$(pass …)` or
// `$OTHER` are left alone. Line numbers are the file's own, so
// `remove_lines` works unchanged; `entry_lines` adds the rest of a fish or
// multi-line zsh entry, and nothing else changes. A file
// that is not UTF-8 (zsh metafies non-ASCII bytes) is scanned lossily by
// cli_agent_adopt.rs and never rewritten.

use std::path::{Path, PathBuf};

use kepr_core::generate::ZeroString;
use zeroize::Zeroizing;

use crate::cli_agent_adopt::{literal, parse_line, Found};

/// Printed once after `--remove` deleted lines from a history file.
pub const REMOVE_WARNING: &str = "open shells keep these commands in memory and may write them back: run `history -c` in them, or close them";

/// `$HISTFILE` (absolute) in place of `~/.bash_history`, `~/.zsh_history`,
/// `${XDG_DATA_HOME:-~/.local/share}/fish/fish_history`.
pub fn history_files(home: &Path, env: &dyn Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    let abs = |k: &str| {
        env(k)
            .filter(|v| Path::new(v).is_absolute())
            .map(PathBuf::from)
    };
    let bash = abs("HISTFILE").unwrap_or_else(|| home.join(".bash_history"));
    let data = abs("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share"));
    vec![
        bash,
        home.join(".zsh_history"),
        data.join("fish/fish_history"),
    ]
}

/// The default history files that exist, canonical (as `cmd_adopt` holds
/// its paths).
pub fn known_files() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    history_files(&home, &|k| std::env::var(k).ok())
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect()
}

/// A default history file, or a file named like one (`kepr agent adopt
/// ~/old/.zsh_history`).
pub fn is_history_file(p: &Path, known: &[PathBuf]) -> bool {
    let named = p
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with("history") || n == ".histfile");
    named || known.iter().any(|k| k == p)
}

/// The command of a history line: zsh's extended `: 1700000000:0;` prefix
/// and fish's `- cmd: ` stripped; any other line unchanged.
pub fn command_of(line: &str) -> &str {
    if let Some(cmd) = line.strip_prefix("- cmd: ") {
        return cmd;
    }
    let zsh = line.strip_prefix(": ").and_then(|rest| {
        let (stamp, cmd) = rest.split_once(';')?;
        let (start, secs) = stamp.split_once(':')?;
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        (digits(start) && digits(secs)).then_some(cmd)
    });
    zsh.unwrap_or(line)
}

/// The 1-based `lines` with the rest of each one's history entry: fish's
/// indented `when:` / `paths:` lines after `- cmd:`, and the lines of a zsh
/// command continued with a trailing backslash. Any other line is itself.
pub fn entry_lines(text: &str, lines: &[usize]) -> Vec<usize> {
    let all: Vec<&str> = text.lines().collect();
    let mut out: Vec<usize> = Vec::new();
    for &l in lines {
        out.push(l);
        let Some(first) = l.checked_sub(1).and_then(|i| all.get(i)) else {
            continue;
        };
        let fish = first.starts_with("- cmd: ");
        let zsh = !fish && command_of(first).len() != first.len();
        let mut prev = *first;
        for (i, next) in all.iter().enumerate().skip(l) {
            let more = if fish {
                next.starts_with("  ")
            } else {
                zsh && prev.ends_with('\\')
            };
            if !more {
                break;
            }
            out.push(i + 1);
            prev = next;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub fn scan_history(file: &Path, text: &str) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    for (i, l) in text.lines().enumerate() {
        let cmd = command_of(l).trim_start();
        let words = cmd.strip_prefix("export ").unwrap_or(cmd);
        let pairs = parse_line(cmd)
            .into_iter()
            .chain(words.split_whitespace().map_while(parse_line));
        for (name, value) in pairs {
            let mut value = Zeroizing::new(value);
            let seen = out.iter().any(|f| f.line == i + 1 && f.name == name);
            if seen || !literal(&value) {
                continue;
            }
            let Some(p) = kepr_core::providers::detect(Some(&name), &value) else {
                continue;
            };
            out.push(Found {
                file: file.to_path_buf(),
                line: i + 1,
                name,
                provider: p.name,
                value: ZeroString::from_string(std::mem::take(&mut *value)),
                key: None,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_agent_adopt_remove::remove_lines;

    fn got(f: &[Found]) -> Vec<(usize, &str, &str)> {
        f.iter()
            .map(|x| (x.line, x.name.as_str(), x.provider))
            .collect()
    }

    #[test]
    fn command_of_strips_zsh_and_fish_prefixes() {
        assert_eq!(command_of(": 1700000000:0;ls -la"), "ls -la");
        assert_eq!(command_of("- cmd: set -gx A b"), "set -gx A b");
        assert_eq!(command_of("ls"), "ls");
        assert_eq!(command_of(": not-zsh;x"), ": not-zsh;x");
    }

    #[test]
    fn finds_keys_in_bash_zsh_and_fish_history() {
        let bash = "ls\nexport XAI_API_KEY=xai-abcdefghijkl\ncd /tmp\n";
        let f = scan_history(Path::new(".bash_history"), bash);
        assert_eq!(got(&f), vec![(2, "XAI_API_KEY", "xai")]);
        assert_eq!(f[0].value.as_str(), "xai-abcdefghijkl");
        let zsh = ": 1700000000:0;ls\n: 1700000001:0;export ANTHROPIC_API_KEY='sk-ant-api03-abcdefghij'\n";
        let f = scan_history(Path::new(".zsh_history"), zsh);
        assert_eq!(got(&f), vec![(2, "ANTHROPIC_API_KEY", "anthropic")]);
        let fish = "- cmd: ls\n  when: 1700000000\n- cmd: set -gx OPENAI_API_KEY sk-proj-abcdefghij\n  when: 1700000001\n";
        let f = scan_history(Path::new("fish_history"), fish);
        assert_eq!(got(&f), vec![(3, "OPENAI_API_KEY", "openai")]);
    }

    #[test]
    fn finds_every_leading_assignment_of_a_command() {
        let f = scan_history(
            Path::new("h"),
            "OPENAI_API_KEY=sk-proj-abcdefghij python app.py\nA=1 XAI_API_KEY=xai-abcdefghij grok --x=y\n",
        );
        assert_eq!(
            got(&f),
            vec![(1, "OPENAI_API_KEY", "openai"), (2, "XAI_API_KEY", "xai")]
        );
        // Not literal values, and words after the command word.
        let none = "export OPENAI_API_KEY=$(pass show openai)\nOPENAI_API_KEY=$OTHER x\n\
                    echo XAI_API_KEY=xai-abcdefghij\ngrok --key=xai-abcdefghij\n";
        assert!(scan_history(Path::new("h"), none).is_empty());
    }

    #[test]
    fn removing_a_zsh_line_keeps_the_others_byte_identical() {
        let zsh = ": 1700000000:0;ls\n: 1700000001:0;export XAI_API_KEY=xai-abcdefghij\n: 1700000002:0;git status\n";
        let f = scan_history(Path::new(".zsh_history"), zsh);
        let lines: Vec<usize> = f.iter().map(|x| x.line).collect();
        assert_eq!(
            remove_lines(zsh, &lines),
            ": 1700000000:0;ls\n: 1700000002:0;git status\n"
        );
    }

    #[test]
    fn a_whole_fish_or_zsh_entry_is_deleted() {
        let fish = "- cmd: ls\n  when: 1\n- cmd: set -gx XAI_API_KEY xai-abcdefghij\n  when: 2\n  paths:\n    - /x\n- cmd: pwd\n  when: 3\n";
        let f = scan_history(Path::new("fish_history"), fish);
        let lines = entry_lines(fish, &[f[0].line]);
        assert_eq!(lines, vec![3, 4, 5, 6]);
        assert_eq!(
            remove_lines(fish, &lines),
            "- cmd: ls\n  when: 1\n- cmd: pwd\n  when: 3\n"
        );
        let zsh = ": 1:0;ls\n: 2:0;OPENAI_API_KEY=sk-proj-abcdefghij python a.py \\\n--flag \\\n--other\n: 3:0;pwd\n";
        let f = scan_history(Path::new(".zsh_history"), zsh);
        assert_eq!(entry_lines(zsh, &[f[0].line]), vec![2, 3, 4]);
        // A plain line is just itself.
        assert_eq!(entry_lines("A=1\nB=2\n  x\n", &[2]), vec![2]);
    }

    #[test]
    fn histfile_overrides_the_bash_default() {
        let home = Path::new("/h");
        let none = |_: &str| None;
        assert_eq!(
            history_files(home, &none),
            vec![
                PathBuf::from("/h/.bash_history"),
                PathBuf::from("/h/.zsh_history"),
                PathBuf::from("/h/.local/share/fish/fish_history"),
            ]
        );
        let env = |k: &str| match k {
            "HISTFILE" => Some("/elsewhere/hist".to_string()),
            "XDG_DATA_HOME" => Some("/d".to_string()),
            _ => None,
        };
        assert_eq!(
            history_files(home, &env),
            vec![
                PathBuf::from("/elsewhere/hist"),
                PathBuf::from("/h/.zsh_history"),
                PathBuf::from("/d/fish/fish_history"),
            ]
        );
    }
}
