// cli_session/pull.rs — `kepr exec --pull NAME[,NAME…] -- CMD` (T3.06).
// Instead of values (`--env`) or inherited descriptors (`--memfd`), CMD
// gets `KEPR_PULL=NAME,…` and fetches each credential itself when it
// needs it, as a sealed close-on-exec fd (`kepr_core::fdfetch`), so
// nothing it starts inherits a secret. Combines with `--env` / `--memfd`;
// `--mask` covers the `--env` values only (kepr never sees pulled ones).

use std::collections::HashMap;

use kepr_core::protocol::{Request, Response};

use crate::cli_args::Args;
use crate::cli_exec::{build_env, build_memfd_env, run_exec, DaemonFetcher};

/// `--pull` CSV → upper-case credential names.
pub fn parse(csv: &str) -> Result<Vec<String>, String> {
    let names: Vec<String> = csv.split(',').map(|s| s.trim().to_uppercase()).collect();
    for n in &names {
        let ok = (1..=128).contains(&n.len())
            && n.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !ok {
            return Err(format!("--pull: {n:?} is not a credential name"));
        }
    }
    Ok(names)
}

/// The child's environment additions and the names `--mask` hides.
fn child_env(
    vars: &[String],
    memfd_vars: &[String],
    pull: &[String],
) -> Result<(HashMap<String, String>, Vec<String>), String> {
    let f = DaemonFetcher;
    let mut env = if vars.is_empty() {
        HashMap::new()
    } else {
        build_env(vars, &f)?
    };
    let secrets = env.keys().cloned().collect();
    if !memfd_vars.is_empty() {
        env.extend(build_memfd_env(memfd_vars, &f)?);
    }
    env.insert(kepr_core::fdfetch::ENV.to_string(), pull.join(","));
    Ok((env, secrets))
}

pub fn cmd_exec(vars: &[String], args: &Args) -> Response {
    // Start the daemon now if it isn't running: CMD fetches from it.
    if let Err(e) = crate::client::send_request(&Request::Ping) {
        return Response::fail(format!("daemon unreachable: {e}"));
    }
    match child_env(vars, &args.memfd_vars, &args.session.pull) {
        Ok((env, secrets)) if args.mask => {
            crate::cli_mask::run_masked(env, &secrets, &args.exec_argv)
        }
        Ok((env, _)) => run_exec(env, &args.exec_argv),
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_names_are_uppercased_and_checked() {
        assert_eq!(parse("db_pass, Api_Key").unwrap(), ["DB_PASS", "API_KEY"]);
        for bad in ["", "A,,B", "a-b", "../x", "A=kepr://B"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_pull_sets_just_kepr_pull() {
        let raw: Vec<String> = ["exec", "--pull", "a,b", "--"].map(String::from).to_vec();
        let mut f = crate::cli_session::SessionFlags::default();
        assert_eq!(f.take(&raw, 1), Ok(3));
        assert_eq!(f.pull, ["A", "B"]);
        let mut f2 = crate::cli_session::SessionFlags::default();
        assert!(f2.take(&raw[..2], 1).is_err(), "--pull needs a value");
        let (env, secrets) = child_env(&[], &[], &f.pull).unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env["KEPR_PULL"], "A,B");
        assert!(secrets.is_empty());
    }
}
