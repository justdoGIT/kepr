// cli_envdump.rs — `kepr env --env VAR1,VAR2[,…]`.
//
// Multi-variable batch sibling of `kepr get --export`. Emits one
// shell-safe `export VAR='value'` line per requested credential to
// stdout, suitable for `eval "$(kepr env --env …)"` or direnv's
// `use kepr` block. Re-uses the same `--env CSV` flag as
// `kepr exec` for parser symmetry — both verbs take "the list of
// cred names this invocation needs."
//
// Shell-escaping: the existing `kepr get --export` path printed
// `export NAME=value` with NO quoting. A value containing spaces,
// shell metachars, or quotes would have broken `eval`. This module
// uses POSIX single-quote escaping (replace `'` with `'\''`, wrap
// in `'…'`) which is portable across bash/zsh/dash and never
// expands further. Apply the same helper to `cmd_get --export` so
// the bug is fixed everywhere, not just in the new path.
//
// Failure semantics: same shape as `kepr exec` — any single fetch
// failure aborts the whole batch BEFORE any line is printed. A
// half-emitted output would have the user `eval`-ing partial state
// and silently missing required vars; clean failure is the safer
// default.

use kepr_core::protocol::Response;

use crate::cli_exec::{CredFetcher, DaemonFetcher};

/// POSIX-safe single-quote escape. The output is the input wrapped
/// in single quotes, with every embedded `'` replaced by `'\''`
/// (close-quote, backslash-escaped quote, re-open-quote).
///
/// Single-quote strings in POSIX shell perform NO expansion at all:
/// no `$`, no backticks, no backslashes, no globs. The only thing
/// they can't contain is another single quote, so the standard
/// trick is to break out of the quotes, emit a backslash-escaped
/// quote, and continue.
pub fn shell_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Resolve every name in `vars` and produce one `export VAR='value'`
/// line per. Returns `Err` on the first failure with a message
/// naming the offending var; the caller MUST NOT print partial
/// output that the user could `eval`.
pub fn build_export_lines<F: CredFetcher>(
    vars: &[String],
    fetcher: &F,
) -> Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(vars.len());
    // T5.06: `VAR=kepr://…` entries too; one fetch per credential.
    for (upper, value) in crate::cli_recordsx::refs::entries(vars, fetcher)? {
        out.push(format!("export {upper}={}", shell_escape(value.as_str())));
    }
    Ok(out)
}

/// Top-level handler. Prints one `export VAR='value'` line per
/// fetched credential to stdout on success; returns `Response::Err`
/// for any pre-print failure. The caller (main.rs) maps the
/// response to an exit code in the usual way.
pub fn cmd_env(env_vars: &[String]) -> Response {
    if env_vars.is_empty() {
        return Response::fail("`kepr env` requires --env VAR[,VAR…]");
    }
    let fetcher = DaemonFetcher;
    let lines = match build_export_lines(env_vars, &fetcher) {
        Ok(l) => l,
        Err(e) => return Response::fail(e),
    };
    for line in &lines {
        println!("{line}");
    }
    Response::Pong
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::generate::ZeroString;
    use std::collections::HashMap;

    /// Re-uses the CredFetcher contract the cli_exec tests rely on,
    /// but reproduced here so each module's tests are self-contained
    /// (no #[cfg(test)] dependency-graph cycle through cli_exec).
    struct MockFetcher {
        map: HashMap<String, Result<String, String>>,
    }
    impl CredFetcher for MockFetcher {
        fn fetch(&self, name: &str) -> Result<ZeroString, String> {
            match self.map.get(name) {
                Some(Ok(v)) => Ok(ZeroString::from_string(v.clone())),
                Some(Err(e)) => Err(e.clone()),
                None => Err(format!("not found: {name}")),
            }
        }
    }

    fn fetcher_with(pairs: &[(&str, Result<&str, &str>)]) -> MockFetcher {
        let mut map = HashMap::new();
        for (k, v) in pairs {
            map.insert(
                k.to_string(),
                v.map(|s| s.to_string()).map_err(|s| s.to_string()),
            );
        }
        MockFetcher { map }
    }

    #[test]
    fn shell_escape_wraps_plain_value_in_single_quotes() {
        assert_eq!(shell_escape("hello"), "'hello'");
    }

    #[test]
    fn shell_escape_handles_value_with_spaces() {
        assert_eq!(shell_escape("hello world"), "'hello world'");
    }

    #[test]
    fn shell_escape_neutralises_dollar_signs() {
        // The whole point of single-quoting: $VAR must NOT be
        // expanded by the consuming shell.
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("$(rm -rf /)"), "'$(rm -rf /)'");
    }

    #[test]
    fn shell_escape_neutralises_backticks() {
        // Backtick command substitution must not fire either.
        assert_eq!(shell_escape("`whoami`"), "'`whoami`'");
    }

    #[test]
    fn shell_escape_neutralises_backslashes() {
        // Inside single quotes, backslash is literal — no escape
        // sequence interpretation.
        assert_eq!(shell_escape("a\\b"), "'a\\b'");
    }

    #[test]
    fn shell_escape_handles_embedded_single_quote() {
        // The crucial case. Input `it's` becomes the 5-segment
        // sequence: open-quote, `it`, close-quote, escaped-quote,
        // open-quote, `s`, close-quote → 'it'\''s'.
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_escape_handles_value_full_of_quotes() {
        assert_eq!(shell_escape("'''"), "''\\'''\\'''\\'''");
    }

    #[test]
    fn shell_escape_handles_empty_value() {
        // An empty value must round-trip as an empty single-quoted
        // string, which `eval` parses as an empty assignment.
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn build_export_lines_emits_one_line_per_var() {
        let f = fetcher_with(&[("FOO", Ok("foo-value")), ("BAR", Ok("bar-value"))]);
        let vars = vec!["FOO".to_string(), "BAR".to_string()];
        let lines = build_export_lines(&vars, &f).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "export FOO='foo-value'");
        assert_eq!(lines[1], "export BAR='bar-value'");
    }

    #[test]
    fn build_export_lines_uppercases_input_names() {
        let f = fetcher_with(&[("FOO", Ok("v"))]);
        let lines = build_export_lines(&["foo".to_string()], &f).unwrap();
        assert_eq!(lines, vec!["export FOO='v'"]);
    }

    #[test]
    fn build_export_lines_aborts_on_first_failure() {
        // Same critical contract as cli_exec::build_env: a missing
        // var must abort BEFORE the caller prints any line. A
        // half-emitted `eval`-able output would have the user's
        // shell silently missing required vars.
        let f = fetcher_with(&[
            ("FOO", Ok("v")),
            ("MISSING", Err("credential unavailable")),
            ("BAR", Ok("v")),
        ]);
        let vars = vec!["FOO".to_string(), "MISSING".to_string(), "BAR".to_string()];
        let err = build_export_lines(&vars, &f).expect_err("missing must abort");
        assert!(err.contains("MISSING"), "names the var: {err}");
        assert!(
            err.contains("credential unavailable"),
            "preserves the daemon's reason: {err}"
        );
    }

    #[test]
    fn build_export_lines_quotes_metachar_values() {
        // End-to-end: a value that would be catastrophic without
        // escaping must come out neutralised. Pin the exact line
        // shape so a future "optimization" that drops the quotes
        // surfaces here.
        let f = fetcher_with(&[("INJECTED", Ok("$(rm -rf /)"))]);
        let lines = build_export_lines(&["INJECTED".to_string()], &f).unwrap();
        assert_eq!(lines, vec!["export INJECTED='$(rm -rf /)'"]);
    }

    #[test]
    fn cmd_env_rejects_empty_var_list() {
        let resp = cmd_env(&[]);
        match resp {
            Response::Err { error } => assert!(error.contains("--env"), "msg: {error}"),
            other => panic!("expected Err, got {other:?}"),
        }
    }
}
