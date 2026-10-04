// cli_exec.rs — `kepr exec --env VAR1,VAR2 -- cmd args...`.
//
// Provisions credentials into a child process's environment without
// the secret ever appearing in the parent shell's history, the
// parent's env, or any shell-level expansion. Fetches each requested
// var via `Request::Get`, then `execvp`s the child with the fetched
// env merged in. The parent is REPLACED by execvp — no fork happens —
// so there is no parent-side environment that could be inspected
// after the fact (e.g. /proc/<pid>/environ on a stray ps).
//
// Failure semantics: if ANY fetch fails (missing cred, daemon
// unreachable, rate-limited), the function returns `Response::Err`
// and the child is NEVER exec'd. A partial-env exec is strictly
// worse than a clean failure — the child would silently see some
// vars unset and fall back to default behaviour.
//
// Testability: the env-build step is split out from the exec step so
// the fetch+merge logic can be unit-tested with a mock fetcher,
// while the exec call itself (which would replace the test process)
// stays at the very edge of the module.

use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::process::Command;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};

use crate::client;

/// Strategy for resolving a credential name → value. Production code
/// dispatches via the daemon socket; tests inject a HashMap-backed
/// fetcher so they don't need a running daemon.
pub trait CredFetcher {
    fn fetch(&self, name: &str) -> Result<ZeroString, String>;
}

/// Production fetcher — talks to the daemon over the standard CLI
/// transport (`client::send_request`). Each fetch is one Unix-socket
/// round-trip.
pub struct DaemonFetcher;

impl CredFetcher for DaemonFetcher {
    fn fetch(&self, name: &str) -> Result<ZeroString, String> {
        match client::send_request(&Request::Get {
            name: name.to_string(),
            fido2_assertion: None,
        }) {
            Ok(Response::GetOk { value, .. }) => Ok(value),
            Ok(Response::Err { error }) => Err(error),
            Ok(other) => Err(format!("unexpected daemon response: {other:?}")),
            Err(e) => Err(format!("daemon unreachable: {e}")),
        }
    }
}

/// Resolve every name in `vars` and return a `(name, value)` map
/// suitable for passing to `Command::envs`. Returns `Err` on the
/// first failure with a message naming the offending var; the
/// caller MUST NOT exec a partial environment.
///
/// Names are uppercased here so callers can pass either case (the
/// CLI parser already uppercases at argv-parse time, but a future
/// caller — e.g. the manifest reader — may not, and the daemon
/// re-uppercases on its side anyway, so doing it here keeps the
/// fetcher honest about what it asked for).
pub fn build_env<F: CredFetcher>(
    vars: &[String],
    fetcher: &F,
) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::with_capacity(vars.len());
    for v in vars {
        let upper = v.to_uppercase();
        let value = fetcher
            .fetch(&upper)
            .map_err(|e| format!("cannot resolve {upper}: {e}"))?;
        // Convert ZeroString → String AT THE LAST POSSIBLE POINT.
        // The String we hand to Command::envs lives until execvp,
        // which clears the parent process image; until then the
        // value is in our own memory only, never on the wire or
        // logged. The daemon's audit log captures the access; the
        // value itself is never written anywhere observable.
        out.insert(upper, value.as_str().to_string());
    }
    Ok(out)
}

/// Resolve every name in `memfd_vars` via `fetcher`, create a sealed memfd
/// for each secret, and return a map of `KEPR_FD_<UPPER_NAME>` -> `fd_string`.
pub fn build_memfd_env<F: CredFetcher>(
    vars: &[String],
    fetcher: &F,
) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::with_capacity(vars.len());
    for v in vars {
        let upper = v.to_uppercase();
        let value = fetcher
            .fetch(&upper)
            .map_err(|e| format!("cannot resolve {upper}: {e}"))?;
        let fd = kepr_core::memfd::create_sealed_memfd(&upper, value.as_str().as_bytes())
            .map_err(|e| format!("cannot create sealed memfd for {upper}: {e}"))?;
        out.insert(format!("KEPR_FD_{upper}"), fd.to_string());
    }
    Ok(out)
}

/// Parse the `--env CSV` argument into a list of variable names.
/// Empty entries (from a trailing comma or `,,`) are rejected so
/// the user gets a clear error rather than a silent no-op fetch
/// for an empty name (which would fail `validate_name` daemon-side
/// anyway, but with a less obvious message).
pub fn parse_env_csv(csv: &str) -> Result<Vec<String>, String> {
    if csv.is_empty() {
        return Err("--env requires at least one variable name".to_string());
    }
    let parts: Vec<String> = csv.split(',').map(|s| s.trim().to_string()).collect();
    if parts.iter().any(|s| s.is_empty()) {
        return Err(format!(
            "--env contains an empty entry (got: {csv:?}); \
             use `VAR1,VAR2` with no leading/trailing/double commas"
        ));
    }
    Ok(parts)
}

/// Replace the current process with `argv[0]` invoked with `argv[1..]`
/// as arguments and `env` merged into the parent's environment.
///
/// This function diverges on success — `execvp` does not return —
/// so the only way control flows back to the caller is on failure
/// (e.g. ENOENT on the binary). On failure it returns `Response::Err`.
pub fn run_exec(env: HashMap<String, String>, argv: &[String]) -> Response {
    if argv.is_empty() {
        return Response::fail("missing command after `--`");
    }
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // `envs` MERGES into the inherited environment rather than
    // replacing it. We deliberately keep PATH, HOME, USER, etc. from
    // the parent — those are not secrets and the user's expectation
    // when running `kepr exec --env API_KEY -- python train.py` is
    // that python finds python the same way it would from the shell.
    cmd.envs(env);
    // exec() replaces the current process image. On success it
    // never returns; on failure it returns std::io::Error.
    let err = cmd.exec();
    Response::fail(format!("exec failed: {err}"))
}

/// Top-level handler. Returns `Response::Err` for any pre-exec
/// failure; on success this function does not return because the
/// process image has been replaced.
pub fn cmd_exec(
    env_vars: &[String],
    memfd_vars: &[String],
    argv: &[String],
    mask: bool,
) -> Response {
    if env_vars.is_empty() && memfd_vars.is_empty() {
        return Response::fail("`kepr exec` requires --env or --memfd VAR[,VAR…]");
    }
    let fetcher = DaemonFetcher;
    let mut env = HashMap::new();
    if !env_vars.is_empty() {
        match build_env(env_vars, &fetcher) {
            Ok(e) => env.extend(e),
            Err(e) => return Response::fail(e),
        }
    }
    if !memfd_vars.is_empty() {
        match build_memfd_env(memfd_vars, &fetcher) {
            Ok(e) => env.extend(e),
            Err(e) => return Response::fail(e),
        }
    }
    if mask {
        return crate::cli_mask::run_masked(env, env_vars, argv);
    }
    run_exec(env, argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only fetcher backed by an in-memory map. Production code
    /// uses `DaemonFetcher`; the unit tests use this so they don't
    /// require a running daemon socket.
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
    fn build_env_collects_all_requested_vars() {
        let f = fetcher_with(&[
            ("FOO", Ok("foo-value")),
            ("BAR", Ok("bar-value")),
            ("BAZ", Ok("baz-value")),
        ]);
        let vars = vec!["FOO".to_string(), "BAR".to_string(), "BAZ".to_string()];
        let env = build_env(&vars, &f).expect("all fetches succeed");
        assert_eq!(env.get("FOO").map(String::as_str), Some("foo-value"));
        assert_eq!(env.get("BAR").map(String::as_str), Some("bar-value"));
        assert_eq!(env.get("BAZ").map(String::as_str), Some("baz-value"));
        assert_eq!(env.len(), 3);
    }

    #[test]
    fn build_env_uppercases_input_names() {
        // The CLI parser already uppercases, but the function should
        // be honest about the contract — a future caller (manifest
        // reader, exec-from-toml) shouldn't have to remember to
        // pre-uppercase.
        let f = fetcher_with(&[("FOO", Ok("v"))]);
        let vars = vec!["foo".to_string()];
        let env = build_env(&vars, &f).unwrap();
        assert_eq!(env.get("FOO").map(String::as_str), Some("v"));
        assert_eq!(env.get("foo"), None, "lowercase form must not appear");
    }

    #[test]
    fn build_env_aborts_on_first_failure() {
        // Critical contract: a single missing cred MUST abort the
        // whole build_env — never return a partial environment that
        // would let the child run with some vars unset.
        let f = fetcher_with(&[
            ("FOO", Ok("foo-value")),
            ("MISSING", Err("credential unavailable")),
            ("BAR", Ok("bar-value")),
        ]);
        let vars = vec!["FOO".to_string(), "MISSING".to_string(), "BAR".to_string()];
        let err = build_env(&vars, &f).expect_err("missing var must fail");
        assert!(
            err.contains("MISSING"),
            "error names the offending var: {err}"
        );
        assert!(
            err.contains("credential unavailable"),
            "error preserves the daemon's reason: {err}"
        );
    }

    #[test]
    fn build_env_zero_vars_yields_empty_map() {
        // Defensive: caller (cmd_exec) rejects this case before
        // build_env is invoked, but the function itself should be
        // total — an empty input is well-defined as an empty output.
        let f = fetcher_with(&[]);
        let env = build_env(&[], &f).unwrap();
        assert!(env.is_empty());
    }

    #[test]
    fn parse_env_csv_splits_on_comma() {
        let v = parse_env_csv("FOO,BAR,BAZ").unwrap();
        assert_eq!(v, vec!["FOO", "BAR", "BAZ"]);
    }

    #[test]
    fn parse_env_csv_trims_surrounding_whitespace() {
        // `--env "FOO, BAR ,BAZ"` is a likely shell-quoting accident,
        // not a malicious input. Trim and accept rather than reject.
        let v = parse_env_csv("FOO, BAR ,BAZ").unwrap();
        assert_eq!(v, vec!["FOO", "BAR", "BAZ"]);
    }

    #[test]
    fn parse_env_csv_single_var_works() {
        let v = parse_env_csv("OPENAI_API_KEY").unwrap();
        assert_eq!(v, vec!["OPENAI_API_KEY"]);
    }

    #[test]
    fn parse_env_csv_rejects_empty_string() {
        assert!(parse_env_csv("").is_err());
    }

    #[test]
    fn parse_env_csv_rejects_empty_entries() {
        // Trailing comma, leading comma, double comma — all
        // user-error patterns that should fail loudly.
        for bad in [",FOO", "FOO,", "FOO,,BAR", ","] {
            let err = parse_env_csv(bad).expect_err("must reject empty entries");
            assert!(
                err.contains("empty entry"),
                "error mentions empty entry: {err}"
            );
        }
    }

    #[test]
    fn cmd_exec_rejects_empty_env_and_memfd_vars() {
        let resp = cmd_exec(&[], &[], &["/bin/echo".to_string()], false);
        match resp {
            Response::Err { error } => {
                assert!(
                    error.contains("--env or --memfd"),
                    "error names --env or --memfd: {error}"
                );
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn build_memfd_env_creates_sealed_fds_and_env_keys() {
        let f = fetcher_with(&[("OPENAI_KEY", Ok("ram_secret_value_99"))]);
        let vars = vec!["OPENAI_KEY".to_string()];
        let env = build_memfd_env(&vars, &f).expect("build_memfd_env succeeded");
        let fd_val = env
            .get("KEPR_FD_OPENAI_KEY")
            .expect("KEPR_FD_OPENAI_KEY present");
        let fd: i32 = fd_val.parse().expect("fd is integer");
        let read_back = std::fs::read_to_string(format!("/proc/self/fd/{fd}")).expect("read fd");
        assert_eq!(read_back, "ram_secret_value_99");
        // SAFETY: `fd` was parsed from the `KEPR_FD_OPENAI_KEY` value this
        // test just created via `build_memfd_env`; it is open, owned solely
        // by this test, and not referenced again after this point.
        unsafe { libc::close(fd) };
    }

    #[test]
    fn run_exec_rejects_empty_argv() {
        // `kepr exec --env FOO --` with nothing after the `--`.
        let resp = run_exec(HashMap::new(), &[]);
        match resp {
            Response::Err { error } => assert!(error.contains("missing command")),
            other => panic!("expected Err, got {other:?}"),
        }
    }
}
